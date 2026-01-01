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
#include "brainpool_ecies_multi_decrypt_impl.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cctype>

namespace gr {
namespace linux_crypto {

brainpool_ecies_multi_decrypt::sptr
brainpool_ecies_multi_decrypt::make(const std::string& curve,
                                    const std::string& recipient_callsign,
                                    const std::string& key_source,
                                    const std::string& recipient_key_identifier,
                                    const std::string& kdf_info)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecies_multi_decrypt_impl(curve, recipient_callsign,
                                               key_source, recipient_key_identifier, kdf_info));
}

std::string
brainpool_ecies_multi_decrypt_impl::trim_upper(const std::string& str)
{
    std::string result;
    for (char c : str) {
        if (!std::isspace(c)) {
            result += std::toupper(c);
        }
    }
    return result;
}

brainpool_ecies_multi_decrypt_impl::brainpool_ecies_multi_decrypt_impl(
    const std::string& curve,
    const std::string& recipient_callsign,
    const std::string& key_source,
    const std::string& recipient_key_identifier,
    const std::string& kdf_info)
    : gr::sync_block("brainpool_ecies_multi_decrypt",
                     gr::io_signature::make(1, 2, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_kdf_info(kdf_info),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve)),
      d_recipient_callsign(trim_upper(recipient_callsign)),
      d_key_source(key_source),
      d_recipient_key_identifier(recipient_key_identifier),
      d_use_key_input_port(false)
{
    // Key will be loaded on-demand during decryption
}

brainpool_ecies_multi_decrypt_impl::~brainpool_ecies_multi_decrypt_impl()
{
    // No keys to free - keys are managed by secure sources
}

size_t
brainpool_ecies_multi_decrypt_impl::get_public_key_size() const
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

void
brainpool_ecies_multi_decrypt_impl::set_recipient_callsign(const std::string& callsign)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_recipient_callsign = trim_upper(callsign);
}

std::string
brainpool_ecies_multi_decrypt_impl::get_recipient_callsign() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_recipient_callsign;
}

void
brainpool_ecies_multi_decrypt_impl::set_recipient_key(const std::string& key_source, const std::string& key_identifier)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    d_key_source = key_source;
    d_recipient_key_identifier = key_identifier;
}

std::string
brainpool_ecies_multi_decrypt_impl::get_key_source() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_source;
}

std::string
brainpool_ecies_multi_decrypt_impl::get_recipient_key_identifier() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_recipient_key_identifier;
}

bool
brainpool_ecies_multi_decrypt_impl::is_key_loaded() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_recipient_key_identifier.empty()) {
        return false;
    }
    
    // If key is from input port, check if we have valid PEM data
    if (d_key_source == "key_input" && d_use_key_input_port) {
        // Check if we have a valid PEM key in the identifier
        return (d_recipient_key_identifier.find("-----BEGIN") != std::string::npos &&
                d_recipient_key_identifier.find("-----END") != std::string::npos);
    }
    
    // Check if key source is available
    return openpgp_card_helper::is_key_source_available(d_key_source, d_recipient_key_identifier);
}

void
brainpool_ecies_multi_decrypt_impl::set_kdf_info(const std::string& kdf_info)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_kdf_info = kdf_info;
}

std::string
brainpool_ecies_multi_decrypt_impl::get_kdf_info() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_kdf_info;
}

std::string
brainpool_ecies_multi_decrypt_impl::get_curve() const
{
    return d_curve_name;
}

bool
brainpool_ecies_multi_decrypt_impl::derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
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
brainpool_ecies_multi_decrypt_impl::decrypt_aes_gcm(const uint8_t* ciphertext,
                                                    size_t ciphertext_len,
                                                    const std::vector<uint8_t>& key,
                                                    const std::vector<uint8_t>& iv,
                                                    const std::vector<uint8_t>& tag,
                                                    std::vector<uint8_t>& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    plaintext.resize(ciphertext_len);
    int outlen = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                           const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len = 0;
    int result = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        return false;
    }
    
    plaintext.resize(outlen + final_len);
    return true;
}

bool
brainpool_ecies_multi_decrypt_impl::decrypt_chacha20_poly1305(const uint8_t* ciphertext,
                                                               size_t ciphertext_len,
                                                               const std::vector<uint8_t>& key,
                                                               const std::vector<uint8_t>& nonce,
                                                               const std::vector<uint8_t>& tag,
                                                               std::vector<uint8_t>& plaintext)
{
    if (key.size() != AES_KEY_SIZE) {
        return false;
    }
    if (nonce.size() != AES_IV_SIZE) {
        return false;
    }
    if (tag.size() != AES_TAG_SIZE) {
        return false;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    plaintext.resize(ciphertext_len);
    int outlen = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AES_TAG_SIZE,
                           const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len = 0;
    int result = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        return false;
    }
    
    plaintext.resize(outlen + final_len);
    return true;
}

EVP_PKEY*
brainpool_ecies_multi_decrypt_impl::deserialize_ephemeral_public_key(const uint8_t* data, size_t data_len)
{
    BIO* bio = BIO_new_mem_buf(data, data_len);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    return pkey;
}

bool
brainpool_ecies_multi_decrypt_impl::decrypt_symmetric_key_ecies(
    const std::vector<uint8_t>& encrypted_key_block,
    std::vector<uint8_t>& symmetric_key)
{
    if (encrypted_key_block.size() < 2) {
        return false;
    }
    
    size_t offset = 0;
    uint16_t pubkey_len = (static_cast<uint16_t>(encrypted_key_block[offset]) << 8) |
                          encrypted_key_block[offset + 1];
    offset += 2;
    
    if (offset + pubkey_len > encrypted_key_block.size()) {
        return false;
    }
    
    EVP_PKEY* ephemeral_pubkey = deserialize_ephemeral_public_key(
        encrypted_key_block.data() + offset, pubkey_len);
    if (!ephemeral_pubkey) {
        return false;
    }
    
    offset += pubkey_len;
    
    if (offset + AES_IV_SIZE > encrypted_key_block.size()) {
        EVP_PKEY_free(ephemeral_pubkey);
        return false;
    }
    
    std::vector<uint8_t> iv(encrypted_key_block.begin() + offset,
                           encrypted_key_block.begin() + offset + AES_IV_SIZE);
    offset += AES_IV_SIZE;
    
    if (offset + 2 > encrypted_key_block.size()) {
        EVP_PKEY_free(ephemeral_pubkey);
        return false;
    }
    
    uint16_t ciphertext_len = (static_cast<uint16_t>(encrypted_key_block[offset]) << 8) |
                             encrypted_key_block[offset + 1];
    offset += 2;
    
    if (offset + ciphertext_len + AES_TAG_SIZE > encrypted_key_block.size()) {
        EVP_PKEY_free(ephemeral_pubkey);
        return false;
    }
    
    std::vector<uint8_t> ciphertext(encrypted_key_block.begin() + offset,
                                    encrypted_key_block.begin() + offset + ciphertext_len);
    offset += ciphertext_len;
    
    std::vector<uint8_t> tag(encrypted_key_block.begin() + offset,
                             encrypted_key_block.begin() + offset + AES_TAG_SIZE);
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_recipient_key_identifier.empty() || !is_key_loaded()) {
        EVP_PKEY_free(ephemeral_pubkey);
        return false;
    }
    
    // Perform ECDH based on key source
    std::vector<uint8_t> shared_secret;
    
    if (d_key_source == "key_input" && d_use_key_input_port) {
        // Key from input port - parse PEM and use OpenSSL ECDH
        BIO* bio = BIO_new_mem_buf(d_recipient_key_identifier.data(), d_recipient_key_identifier.size());
        if (bio) {
            EVP_PKEY* private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            
            if (private_key) {
                // Perform ECDH using OpenSSL
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
                if (ctx) {
                    if (EVP_PKEY_derive_init(ctx) > 0 &&
                        EVP_PKEY_derive_set_peer(ctx, ephemeral_pubkey) > 0) {
                        size_t secret_len = 0;
                        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) > 0) {
                            shared_secret.resize(secret_len);
                            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
                                shared_secret.clear();
                            }
                        }
                    }
                    EVP_PKEY_CTX_free(ctx);
                }
                EVP_PKEY_free(private_key);
            }
        }
    } else {
        // Use helper class to perform ECDH with secure key source
        shared_secret = openpgp_card_helper::ecdh_exchange(
            d_key_source,
            d_recipient_key_identifier,
            ephemeral_pubkey
        );
    }
    
    EVP_PKEY_free(ephemeral_pubkey);
    
    if (shared_secret.empty()) {
        return false;
    }
    
    std::vector<uint8_t> key, derived_iv;
    if (!derive_key_hkdf(shared_secret, key, derived_iv)) {
        return false;
    }
    
    if (derived_iv != iv) {
        return false;
    }
    
    if (!decrypt_aes_gcm(ciphertext.data(), ciphertext.size(), key, iv, tag, symmetric_key)) {
        return false;
    }
    
    return true;
}

int
brainpool_ecies_multi_decrypt_impl::work(int noutput_items,
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
    
    if (d_recipient_key_identifier.empty() || !is_key_loaded() || d_recipient_callsign.empty()) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    if (static_cast<size_t>(noutput_items) < HEADER_SIZE) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    uint8_t version = in[0];
    uint8_t curve_id = in[1];
    uint8_t recipient_count = in[2];
    uint8_t cipher_id = in[3];
    uint32_t data_length = (static_cast<uint32_t>(in[4]) << 24) |
                          (static_cast<uint32_t>(in[5]) << 16) |
                          (static_cast<uint32_t>(in[6]) << 8) |
                          in[7];
    
    if (version != FORMAT_VERSION) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    if (recipient_count == 0 || recipient_count > MAX_RECIPIENTS) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t offset = HEADER_SIZE;
    std::vector<uint8_t> encrypted_key_block;
    bool found = false;
    
    for (uint8_t i = 0; i < recipient_count; ++i) {
        if (offset >= static_cast<size_t>(noutput_items)) {
            memset(out, 0, noutput_items);
            return 0;
        }
        
        uint8_t callsign_len = in[offset];
        offset += 1;
        
        if (callsign_len == 0 || callsign_len > MAX_CALLSIGN_LEN ||
            offset + callsign_len + 1 > static_cast<size_t>(noutput_items)) {
            memset(out, 0, noutput_items);
            return 0;
        }
        
        if (in[offset + callsign_len] != 0) {
            memset(out, 0, noutput_items);
            return 0;
        }
        
        std::string callsign(reinterpret_cast<const char*>(in + offset), callsign_len);
        callsign = trim_upper(callsign);
        offset += callsign_len + 1;
        
        if (offset + 2 > static_cast<size_t>(noutput_items)) {
            memset(out, 0, noutput_items);
            return 0;
        }
        
        uint16_t key_len = (static_cast<uint16_t>(in[offset]) << 8) | in[offset + 1];
        offset += 2;
        
        if (offset + key_len > static_cast<size_t>(noutput_items)) {
            memset(out, 0, noutput_items);
            return 0;
        }
        
        if (callsign == d_recipient_callsign) {
            encrypted_key_block.assign(in + offset, in + offset + key_len);
            found = true;
        }
        
        offset += key_len;
    }
    
    if (!found || encrypted_key_block.empty()) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    if (offset + AES_IV_SIZE > static_cast<size_t>(noutput_items)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> iv(in + offset, in + offset + AES_IV_SIZE);
    offset += AES_IV_SIZE;
    
    size_t ciphertext_length = data_length - AES_IV_SIZE;
    if (ciphertext_length == 0 || offset + ciphertext_length + AES_TAG_SIZE > static_cast<size_t>(noutput_items)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> ciphertext(in + offset, in + offset + ciphertext_length);
    offset += ciphertext_length;
    
    if (offset + AES_TAG_SIZE > static_cast<size_t>(noutput_items)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> tag(in + offset, in + offset + AES_TAG_SIZE);
    
    std::vector<uint8_t> symmetric_key;
    if (!decrypt_symmetric_key_ecies(encrypted_key_block, symmetric_key)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::vector<uint8_t> plaintext;
    bool decrypt_success = false;
    if (cipher_id == CIPHER_ID_AES_GCM) {
        decrypt_success = decrypt_aes_gcm(ciphertext.data(), ciphertext.size(), symmetric_key, iv, tag, plaintext);
    } else if (cipher_id == CIPHER_ID_CHACHA20_POLY1305) {
        decrypt_success = decrypt_chacha20_poly1305(ciphertext.data(), ciphertext.size(), symmetric_key, iv, tag, plaintext);
    } else {
        decrypt_success = false;
    }
    
    if (!decrypt_success) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    if (plaintext.size() > static_cast<size_t>(noutput_items)) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    std::memcpy(out, plaintext.data(), plaintext.size());
    return plaintext.size();
}

void
brainpool_ecies_multi_decrypt_impl::process_key_input(const unsigned char* key_data, int n_items)
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
        // For decrypt, we can use this key if key_source is set to use key input
        if (parse_and_store_key(key_string)) {
            d_use_key_input_port = true;
            // Update key_source to indicate we're using key input
            d_key_source = "key_input";
        }
        
        d_key_input_buffer.clear();
    }
}

bool
brainpool_ecies_multi_decrypt_impl::parse_and_store_key(const std::string& key_data_str)
{
    if (key_data_str.empty()) {
        return false;
    }
    
    // For decrypt, we need to check if this is a private key
    // The key could be from nitrokey_interface or kernel_keyring_source
    // Both can output PEM format keys
    
    // Try parsing as private key first (most common for decrypt)
    BIO* bio = BIO_new_mem_buf(key_data_str.data(), key_data_str.size());
    if (!bio) {
        return false;
    }
    
    // Try private key first
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        // Try public key (some sources might output public keys)
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        return false;
    }
    
    // Store the key identifier as the PEM data itself
    // This allows the decrypt logic to use it
    // Note: For secure sources, we should use the key_source/key_identifier
    // But for key input port, we store the PEM data
    d_recipient_key_identifier = key_data_str;
    
    EVP_PKEY_free(pkey);  // We'll re-parse when needed
    
    return true;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

