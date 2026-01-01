/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * gr-linux-crypto is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * gr-linux-crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-linux-crypto; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_OPENSSL

#include <gnuradio/io_signature.h>
#include "brainpool_ecies_multi_encrypt_impl.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <set>
#include <cstdlib>

namespace gr {
namespace linux_crypto {

brainpool_ecies_multi_encrypt::sptr
brainpool_ecies_multi_encrypt::make(const std::string& curve,
                                    const std::vector<std::string>& callsigns,
                                    const std::string& key_store_path,
                                    const std::string& kdf_info,
                                    const std::string& symmetric_cipher)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecies_multi_encrypt_impl(curve, callsigns, key_store_path, kdf_info, symmetric_cipher));
}

brainpool_ecies_multi_encrypt_impl::brainpool_ecies_multi_encrypt_impl(
    const std::string& curve,
    const std::vector<std::string>& callsigns,
    const std::string& key_store_path,
    const std::string& kdf_info,
    const std::string& symmetric_cipher)
    : gr::sync_block("brainpool_ecies_multi_encrypt",
                     gr::io_signature::make(1, 2, sizeof(unsigned char)),  // Data input, optional key input
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_kdf_info(kdf_info),
      d_key_store_path(key_store_path),
      d_symmetric_cipher(symmetric_cipher),
      d_cipher_id(get_cipher_id_from_name(symmetric_cipher)),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve))
{
    if (d_key_store_path.empty()) {
        const char* home = getenv("HOME");
        if (home) {
            d_key_store_path = std::string(home) + "/.gnuradio/callsign_keys.json";
        } else {
            d_key_store_path = ".gnuradio/callsign_keys.json";
        }
    }
    
    load_key_store();
    
    if (!callsigns.empty()) {
        set_callsigns(callsigns);
    }
}

brainpool_ecies_multi_encrypt_impl::~brainpool_ecies_multi_encrypt_impl()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    for (auto& pair : d_recipient_keys) {
        if (pair.second) {
            EVP_PKEY_free(pair.second);
        }
    }
    d_recipient_keys.clear();
}

uint8_t
brainpool_ecies_multi_encrypt_impl::get_curve_id() const
{
    switch (d_curve) {
        case brainpool_ec_impl::Curve::BRAINPOOLP256R1:
            return 0x01;
        case brainpool_ec_impl::Curve::BRAINPOOLP384R1:
            return 0x02;
        case brainpool_ec_impl::Curve::BRAINPOOLP512R1:
            return 0x03;
        default:
            return 0x01;
    }
}

size_t
brainpool_ecies_multi_encrypt_impl::get_public_key_size() const
{
    switch (d_curve) {
        case brainpool_ec_impl::Curve::BRAINPOOLP256R1:
            return 91;
        case brainpool_ec_impl::Curve::BRAINPOOLP384R1:
            return 120;
        case brainpool_ec_impl::Curve::BRAINPOOLP512R1:
            return 158;
        default:
            return 91;
    }
}

static std::string trim_upper(const std::string& str)
{
    std::string result;
    for (char c : str) {
        if (!std::isspace(c)) {
            result += std::toupper(c);
        }
    }
    return result;
}

static std::string extract_json_string_value(const std::string& json, const std::string& key)
{
    std::string search_key = "\"" + key + "\"";
    size_t key_pos = json.find(search_key);
    if (key_pos == std::string::npos) {
        return "";
    }
    
    size_t colon_pos = json.find(':', key_pos);
    if (colon_pos == std::string::npos) {
        return "";
    }
    
    size_t quote_start = json.find('"', colon_pos);
    if (quote_start == std::string::npos) {
        return "";
    }
    
    size_t quote_end = json.find('"', quote_start + 1);
    if (quote_end == std::string::npos) {
        return "";
    }
    
    return json.substr(quote_start + 1, quote_end - quote_start - 1);
}

bool
brainpool_ecies_multi_encrypt_impl::load_key_store()
{
    std::ifstream file(d_key_store_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_content = buffer.str();
    file.close();
    
    size_t pos = 0;
    while ((pos = json_content.find('"', pos)) != std::string::npos) {
        size_t key_start = pos + 1;
        size_t key_end = json_content.find('"', key_start);
        if (key_end == std::string::npos) {
            break;
        }
        
        std::string callsign = json_content.substr(key_start, key_end - key_start);
        callsign = trim_upper(callsign);
        
        if (callsign.length() > MAX_CALLSIGN_LEN) {
            pos = key_end + 1;
            continue;
        }
        
        size_t colon_pos = json_content.find(':', key_end);
        if (colon_pos == std::string::npos) {
            pos = key_end + 1;
            continue;
        }
        
        size_t value_start = json_content.find('"', colon_pos);
        if (value_start == std::string::npos) {
            pos = key_end + 1;
            continue;
        }
        
        size_t value_end = json_content.find('"', value_start + 1);
        if (value_end == std::string::npos) {
            pos = key_end + 1;
            continue;
        }
        
        std::string pem_key = json_content.substr(value_start + 1, value_end - value_start - 1);
        
        BIO* bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
        if (bio) {
            EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (pkey) {
                std::lock_guard<std::mutex> lock(d_mutex);
                if (d_recipient_keys.find(callsign) != d_recipient_keys.end()) {
                    EVP_PKEY_free(d_recipient_keys[callsign]);
                }
                d_recipient_keys[callsign] = pkey;
            }
        }
        
        pos = value_end + 1;
    }
    
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::get_public_key_from_store(const std::string& callsign,
                                                              std::string& public_key_pem)
{
    std::string normalized = trim_upper(callsign);
    
    std::lock_guard<std::mutex> lock(d_mutex);
    auto it = d_recipient_keys.find(normalized);
    if (it != d_recipient_keys.end() && it->second) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            return false;
        }
        
        if (PEM_write_bio_PUBKEY(bio, it->second) != 1) {
            BIO_free(bio);
            return false;
        }
        
        char* pem_ptr = nullptr;
        long pem_len = BIO_get_mem_data(bio, &pem_ptr);
        if (pem_len > 0 && pem_ptr) {
            public_key_pem.assign(pem_ptr, pem_len);
        }
        BIO_free(bio);
        return !public_key_pem.empty();
    }
    
    return false;
}

void
brainpool_ecies_multi_encrypt_impl::set_callsigns(const std::vector<std::string>& callsigns)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (callsigns.size() == 0 || callsigns.size() > MAX_RECIPIENTS) {
        return;
    }
    
    std::vector<std::string> normalized;
    for (const auto& cs : callsigns) {
        std::string norm = trim_upper(cs);
        if (norm.length() > 0 && norm.length() <= MAX_CALLSIGN_LEN) {
            normalized.push_back(norm);
        }
    }
    
    if (normalized.size() != callsigns.size()) {
        return;
    }
    
    std::set<std::string> unique_check(normalized.begin(), normalized.end());
    if (unique_check.size() != normalized.size()) {
        return;
    }
    
    d_callsigns = normalized;
}

std::vector<std::string>
brainpool_ecies_multi_encrypt_impl::get_callsigns() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_callsigns;
}

bool
brainpool_ecies_multi_encrypt_impl::add_callsign(const std::string& callsign)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_callsigns.size() >= MAX_RECIPIENTS) {
        return false;
    }
    
    std::string normalized = trim_upper(callsign);
    if (normalized.length() == 0 || normalized.length() > MAX_CALLSIGN_LEN) {
        return false;
    }
    
    for (const auto& cs : d_callsigns) {
        if (cs == normalized) {
            return false;
        }
    }
    
    d_callsigns.push_back(normalized);
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::remove_callsign(const std::string& callsign)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    std::string normalized = trim_upper(callsign);
    auto it = std::find(d_callsigns.begin(), d_callsigns.end(), normalized);
    if (it != d_callsigns.end()) {
        d_callsigns.erase(it);
        return true;
    }
    
    return false;
}

void
brainpool_ecies_multi_encrypt_impl::set_kdf_info(const std::string& kdf_info)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_kdf_info = kdf_info;
}

std::string
brainpool_ecies_multi_encrypt_impl::get_kdf_info() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_kdf_info;
}

std::string
brainpool_ecies_multi_encrypt_impl::get_curve() const
{
    return d_curve_name;
}

bool
brainpool_ecies_multi_encrypt_impl::derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
                                                    std::vector<uint8_t>& key,
                                                    std::vector<uint8_t>& iv)
{
    key.resize(AES_KEY_SIZE);
    iv.resize(AES_IV_SIZE);
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        return false;
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret.data(), shared_secret.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    if (!d_kdf_info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(d_kdf_info.data()), d_kdf_info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }
    
    size_t derived_len = AES_KEY_SIZE + AES_IV_SIZE;
    std::vector<uint8_t> derived(derived_len);
    
    if (EVP_PKEY_derive(pctx, derived.data(), &derived_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    if (derived_len < AES_KEY_SIZE + AES_IV_SIZE) {
        return false;
    }
    
    std::memcpy(key.data(), derived.data(), AES_KEY_SIZE);
    std::memcpy(iv.data(), derived.data() + AES_IV_SIZE, AES_IV_SIZE);
    
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::encrypt_aes_gcm(const uint8_t* plaintext,
                                                    size_t plaintext_len,
                                                    const std::vector<uint8_t>& key,
                                                    const std::vector<uint8_t>& iv,
                                                    std::vector<uint8_t>& ciphertext,
                                                    std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    ciphertext.resize(plaintext_len);
    int outlen = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    tag.resize(AES_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::encrypt_chacha20_poly1305(const uint8_t* plaintext,
                                                               size_t plaintext_len,
                                                               const std::vector<uint8_t>& key,
                                                               const std::vector<uint8_t>& nonce,
                                                               std::vector<uint8_t>& ciphertext,
                                                               std::vector<uint8_t>& tag)
{
    if (key.size() != AES_KEY_SIZE) {
        return false;
    }
    if (nonce.size() != AES_IV_SIZE) {
        return false;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    ciphertext.resize(plaintext_len);
    int outlen = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    tag.resize(AES_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::encrypt_symmetric_key_ecies(
    const std::vector<uint8_t>& symmetric_key,
    EVP_PKEY* recipient_public_key,
    std::vector<uint8_t>& encrypted_key_block)
{
    auto ephemeral_keypair = d_brainpool_ec->generate_keypair();
    if (!ephemeral_keypair.private_key || !ephemeral_keypair.public_key) {
        return false;
    }
    
    auto shared_secret = d_brainpool_ec->ecdh_exchange(ephemeral_keypair.private_key,
                                                       recipient_public_key);
    if (shared_secret.empty()) {
        EVP_PKEY_free(ephemeral_keypair.private_key);
        EVP_PKEY_free(ephemeral_keypair.public_key);
        return false;
    }
    
    std::vector<uint8_t> key, iv;
    if (!derive_key_hkdf(shared_secret, key, iv)) {
        EVP_PKEY_free(ephemeral_keypair.private_key);
        EVP_PKEY_free(ephemeral_keypair.public_key);
        return false;
    }
    
    std::vector<uint8_t> encrypted_key, tag;
    if (!encrypt_aes_gcm(symmetric_key.data(), symmetric_key.size(), key, iv,
                        encrypted_key, tag)) {
        EVP_PKEY_free(ephemeral_keypair.private_key);
        EVP_PKEY_free(ephemeral_keypair.public_key);
        return false;
    }
    
    std::vector<uint8_t> ephemeral_pubkey_serialized;
    if (!serialize_ephemeral_public_key(ephemeral_keypair.public_key,
                                       ephemeral_pubkey_serialized)) {
        EVP_PKEY_free(ephemeral_keypair.private_key);
        EVP_PKEY_free(ephemeral_keypair.public_key);
        return false;
    }
    
    EVP_PKEY_free(ephemeral_keypair.private_key);
    EVP_PKEY_free(ephemeral_keypair.public_key);
    
    encrypted_key_block.clear();
    uint16_t pubkey_len = static_cast<uint16_t>(ephemeral_pubkey_serialized.size());
    encrypted_key_block.push_back(static_cast<uint8_t>((pubkey_len >> 8) & 0xFF));
    encrypted_key_block.push_back(static_cast<uint8_t>(pubkey_len & 0xFF));
    encrypted_key_block.insert(encrypted_key_block.end(),
                              ephemeral_pubkey_serialized.begin(),
                              ephemeral_pubkey_serialized.end());
    encrypted_key_block.insert(encrypted_key_block.end(), iv.begin(), iv.end());
    uint16_t encrypted_key_len = static_cast<uint16_t>(encrypted_key.size());
    encrypted_key_block.push_back(static_cast<uint8_t>((encrypted_key_len >> 8) & 0xFF));
    encrypted_key_block.push_back(static_cast<uint8_t>(encrypted_key_len & 0xFF));
    encrypted_key_block.insert(encrypted_key_block.end(),
                              encrypted_key.begin(), encrypted_key.end());
    encrypted_key_block.insert(encrypted_key_block.end(), tag.begin(), tag.end());
    
    return true;
}

bool
brainpool_ecies_multi_encrypt_impl::serialize_ephemeral_public_key(EVP_PKEY* public_key,
                                                                    std::vector<uint8_t>& serialized)
{
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return false;
    }
    
    if (PEM_write_bio_PUBKEY(bio, public_key) != 1) {
        BIO_free(bio);
        return false;
    }
    
    char* pem_ptr = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_ptr);
    if (pem_len > 0 && pem_ptr) {
        serialized.assign(reinterpret_cast<const uint8_t*>(pem_ptr),
                         reinterpret_cast<const uint8_t*>(pem_ptr) + pem_len);
    }
    
    BIO_free(bio);
    return !serialized.empty();
}

void
brainpool_ecies_multi_encrypt_impl::build_header(uint8_t recipient_count,
                                                 uint32_t data_length,
                                                 uint8_t cipher_id,
                                                 std::vector<uint8_t>& header)
{
    header.resize(HEADER_SIZE);
    header[0] = FORMAT_VERSION;
    header[1] = get_curve_id();
    header[2] = recipient_count;
    header[3] = cipher_id;
    header[4] = static_cast<uint8_t>((data_length >> 24) & 0xFF);
    header[5] = static_cast<uint8_t>((data_length >> 16) & 0xFF);
    header[6] = static_cast<uint8_t>((data_length >> 8) & 0xFF);
    header[7] = static_cast<uint8_t>(data_length & 0xFF);
}

uint8_t
brainpool_ecies_multi_encrypt_impl::get_cipher_id_from_name(const std::string& cipher_name) const
{
    std::string lower = cipher_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "aes-gcm" || lower == "aes_gcm" || lower == "aesgcm") {
        return CIPHER_ID_AES_GCM;
    } else if (lower == "chacha20-poly1305" || lower == "chacha20_poly1305" || 
               lower == "chacha20poly1305" || lower == "chacha") {
        return CIPHER_ID_CHACHA20_POLY1305;
    } else {
        return CIPHER_ID_AES_GCM;
    }
}

void
brainpool_ecies_multi_encrypt_impl::build_recipient_block(const std::string& callsign,
                                                          const std::vector<uint8_t>& encrypted_key,
                                                          std::vector<uint8_t>& block)
{
    block.clear();
    uint8_t callsign_len = static_cast<uint8_t>(callsign.length());
    block.push_back(callsign_len);
    block.insert(block.end(), callsign.begin(), callsign.end());
    block.push_back(0);
    uint16_t key_len = static_cast<uint16_t>(encrypted_key.size());
    block.push_back(static_cast<uint8_t>((key_len >> 8) & 0xFF));
    block.push_back(static_cast<uint8_t>(key_len & 0xFF));
    block.insert(block.end(), encrypted_key.begin(), encrypted_key.end());
}

int
brainpool_ecies_multi_encrypt_impl::work(int noutput_items,
                                        gr_vector_const_void_star& input_items,
                                        gr_vector_void_star& output_items)
{
    const unsigned char* in = (const unsigned char*)input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];
    
    // Process key input from port 1 if present (from nitrokey_interface or kernel_keyring_source)
    if (input_items.size() > 1 && input_items[1] != nullptr) {
        const unsigned char* key_in = (const unsigned char*)input_items[1];
        process_key_input(key_in, noutput_items);
    }
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_callsigns.empty()) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    if (d_callsigns.size() > MAX_RECIPIENTS) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<EVP_PKEY*> recipient_public_keys;
    for (const auto& callsign : d_callsigns) {
        EVP_PKEY* pkey = nullptr;
        
        // First, check if we have a key from the key input port
        if (d_use_key_input_port && d_recipient_keys.find(callsign) != d_recipient_keys.end()) {
            pkey = d_recipient_keys[callsign];
            // Increment reference count (we'll free it later)
            EVP_PKEY_up_ref(pkey);
        } else {
            // Fall back to key store
            std::string public_key_pem;
            if (!get_public_key_from_store(callsign, public_key_pem)) {
                // Free already loaded keys
                for (auto* key : recipient_public_keys) {
                    EVP_PKEY_free(key);
                }
                memset(out, 0, noutput_items);
                return 0;
            }
            
            BIO* bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size());
            if (!bio) {
                for (auto* key : recipient_public_keys) {
                    EVP_PKEY_free(key);
                }
                memset(out, 0, noutput_items);
                return 0;
            }
            
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (!pkey) {
                for (auto* key : recipient_public_keys) {
                    EVP_PKEY_free(key);
                }
                memset(out, 0, noutput_items);
                return 0;
            }
        }
        
        recipient_public_keys.push_back(pkey);
    }
    
    std::vector<uint8_t> symmetric_key(AES_KEY_SIZE);
    if (RAND_bytes(symmetric_key.data(), AES_KEY_SIZE) != 1) {
        for (auto* pkey : recipient_public_keys) {
            EVP_PKEY_free(pkey);
        }
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> iv(AES_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_IV_SIZE) != 1) {
        for (auto* pkey : recipient_public_keys) {
            EVP_PKEY_free(pkey);
        }
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> plaintext(in, in + noutput_items);
    std::vector<uint8_t> ciphertext, tag;
    bool encrypt_success = false;
    
    if (d_cipher_id == CIPHER_ID_AES_GCM) {
        encrypt_success = encrypt_aes_gcm(plaintext.data(), plaintext.size(), symmetric_key, iv,
                                          ciphertext, tag);
    } else if (d_cipher_id == CIPHER_ID_CHACHA20_POLY1305) {
        encrypt_success = encrypt_chacha20_poly1305(plaintext.data(), plaintext.size(), symmetric_key, iv,
                                                    ciphertext, tag);
    } else {
        encrypt_success = false;
    }
    
    if (!encrypt_success) {
        for (auto* pkey : recipient_public_keys) {
            EVP_PKEY_free(pkey);
        }
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<std::vector<uint8_t>> recipient_blocks;
    for (size_t i = 0; i < d_callsigns.size(); ++i) {
        std::vector<uint8_t> encrypted_key_block;
        if (!encrypt_symmetric_key_ecies(symmetric_key, recipient_public_keys[i],
                                        encrypted_key_block)) {
            for (auto* pkey : recipient_public_keys) {
                EVP_PKEY_free(pkey);
            }
            memset(out, 0, noutput_items);
            return 0;
        }
        
        std::vector<uint8_t> recipient_block;
        build_recipient_block(d_callsigns[i], encrypted_key_block, recipient_block);
        recipient_blocks.push_back(recipient_block);
    }
    
    for (auto* pkey : recipient_public_keys) {
        EVP_PKEY_free(pkey);
    }
    
    uint32_t data_length = AES_IV_SIZE + ciphertext.size() + AES_TAG_SIZE;
    std::vector<uint8_t> header;
    build_header(static_cast<uint8_t>(d_callsigns.size()), data_length, d_cipher_id, header);
    
    size_t total_size = header.size();
    for (const auto& block : recipient_blocks) {
        total_size += block.size();
    }
    total_size += iv.size() + ciphertext.size() + tag.size();
    
    if (total_size > static_cast<size_t>(noutput_items)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t offset = 0;
    std::memcpy(out + offset, header.data(), header.size());
    offset += header.size();
    
    for (const auto& block : recipient_blocks) {
        std::memcpy(out + offset, block.data(), block.size());
        offset += block.size();
    }
    
    std::memcpy(out + offset, iv.data(), iv.size());
    offset += iv.size();
    
    std::memcpy(out + offset, ciphertext.data(), ciphertext.size());
    offset += ciphertext.size();
    
    std::memcpy(out + offset, tag.data(), tag.size());
    offset += tag.size();
    
    return offset;
}

void
brainpool_ecies_multi_encrypt_impl::process_key_input(const unsigned char* key_data, int n_items)
{
    if (n_items <= 0) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_key_input_buffer.size() + static_cast<size_t>(n_items) > MAX_KEY_BUFFER_SIZE) {
        d_key_input_buffer.clear();
    }
    
    d_key_input_buffer.insert(d_key_input_buffer.end(), key_data, key_data + n_items);
    
    // Check if we have a complete PEM key (look for BEGIN/END markers)
    std::string key_string(reinterpret_cast<const char*>(d_key_input_buffer.data()),
                          d_key_input_buffer.size());
    
    if (key_string.find("-----BEGIN") != std::string::npos &&
        key_string.find("-----END") != std::string::npos) {
        // We have a complete PEM key
        // For multi-recipient, we need to know which callsign this key is for
        // For now, if we have only one callsign, use it; otherwise, try to parse callsign from key
        // or use the first callsign as default
        
        std::string callsign_to_use;
        if (d_callsigns.size() == 1) {
            callsign_to_use = d_callsigns[0];
        } else if (!d_callsigns.empty()) {
            // Use first callsign as default - user should set callsigns before connecting key input
            callsign_to_use = d_callsigns[0];
        }
        
        if (!callsign_to_use.empty()) {
            parse_and_store_key(key_string, callsign_to_use);
            d_use_key_input_port = true;
        }
        
        d_key_input_buffer.clear();
    }
}

bool
brainpool_ecies_multi_encrypt_impl::parse_and_store_key(const std::string& key_data_str, const std::string& callsign)
{
    if (key_data_str.empty() || callsign.empty()) {
        return false;
    }
    
    // Parse PEM key
    BIO* bio = BIO_new_mem_buf(key_data_str.data(), key_data_str.size());
    if (!bio) {
        return false;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) {
        return false;
    }
    
    // Store the key in the recipient keys map
    // Free existing key if present
    if (d_recipient_keys.find(callsign) != d_recipient_keys.end()) {
        EVP_PKEY_free(d_recipient_keys[callsign]);
    }
    
    d_recipient_keys[callsign] = pkey;
    
    return true;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

