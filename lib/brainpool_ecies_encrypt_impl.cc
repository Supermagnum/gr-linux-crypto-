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
#include "brainpool_ecies_encrypt_impl.h"
#include "openpgp_card_helper.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>

namespace gr {
namespace linux_crypto {

brainpool_ecies_encrypt::sptr
brainpool_ecies_encrypt::make(const std::string& curve,
                               const std::string& key_source,
                               const std::string& recipient_key_identifier,
                               const std::string& kdf_info)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecies_encrypt_impl(curve, key_source, recipient_key_identifier, kdf_info));
}

brainpool_ecies_encrypt_impl::brainpool_ecies_encrypt_impl(
    const std::string& curve,
    const std::string& key_source,
    const std::string& recipient_key_identifier,
    const std::string& kdf_info)
    : gr::sync_block("brainpool_ecies_encrypt",
                     gr::io_signature::make(1, 2, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_kdf_info(kdf_info),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve)),
      d_key_source(key_source),
      d_recipient_key_identifier(recipient_key_identifier),
      d_recipient_public_key(nullptr),
      d_use_key_input_port(false)
{
    if (!recipient_key_identifier.empty()) {
        load_recipient_public_key();
    }
    
    set_output_multiple(2 + get_public_key_size() + AES_IV_SIZE + 2 + AES_TAG_SIZE + 1);
}

brainpool_ecies_encrypt_impl::~brainpool_ecies_encrypt_impl()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_recipient_public_key) {
        EVP_PKEY_free(d_recipient_public_key);
        d_recipient_public_key = nullptr;
    }
}

size_t
brainpool_ecies_encrypt_impl::get_public_key_size() const
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
brainpool_ecies_encrypt_impl::set_recipient_key(const std::string& key_source, const std::string& key_identifier)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    d_key_source = key_source;
    d_recipient_key_identifier = key_identifier;
    
    load_recipient_public_key();
}

void
brainpool_ecies_encrypt_impl::load_recipient_public_key()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_recipient_public_key) {
        EVP_PKEY_free(d_recipient_public_key);
        d_recipient_public_key = nullptr;
    }
    
    if (d_recipient_key_identifier.empty()) {
        return;
    }
    
    // Use helper class to get public key from secure source
    d_recipient_public_key = openpgp_card_helper::get_public_key(d_key_source, d_recipient_key_identifier);
}

std::string
brainpool_ecies_encrypt_impl::get_key_source() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_source;
}

std::string
brainpool_ecies_encrypt_impl::get_recipient_key_identifier() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_recipient_key_identifier;
}

void
brainpool_ecies_encrypt_impl::set_kdf_info(const std::string& kdf_info)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_kdf_info = kdf_info;
}

std::string
brainpool_ecies_encrypt_impl::get_kdf_info() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_kdf_info;
}

std::string
brainpool_ecies_encrypt_impl::get_curve() const
{
    return d_curve_name;
}

bool
brainpool_ecies_encrypt_impl::derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
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
    std::memcpy(iv.data(), derived.data() + AES_KEY_SIZE, AES_IV_SIZE);
    
    return true;
}

bool
brainpool_ecies_encrypt_impl::encrypt_aes_gcm(const uint8_t* plaintext,
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
brainpool_ecies_encrypt_impl::serialize_ephemeral_public_key(EVP_PKEY* public_key,
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
brainpool_ecies_encrypt_impl::process_key_input(const unsigned char* key_data, int n_items)
{
    // Key input port is deprecated - keys should come from secure sources (OpenPGP Card or kernel keyring)
    // This function is kept for backward compatibility but does nothing
    (void)key_data;
    (void)n_items;
}

int
brainpool_ecies_encrypt_impl::work(int noutput_items,
                                   gr_vector_const_void_star& input_items,
                                   gr_vector_void_star& output_items)
{
    const unsigned char* in = (const unsigned char*)input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];
    
    if (input_items.size() > 1 && input_items[1] != nullptr) {
        const unsigned char* key_in = (const unsigned char*)input_items[1];
        int key_n_items = noutput_items;
        process_key_input(key_in, key_n_items);
    }
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (!d_recipient_public_key) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t processed = 0;
    size_t output_pos = 0;
    
    constexpr size_t MAX_CHUNK_SIZE = 1024;
    size_t MIN_OUTPUT_OVERHEAD = 2 + get_public_key_size() + AES_IV_SIZE + 2 + AES_TAG_SIZE;
    
    while (processed < static_cast<size_t>(noutput_items) && 
           output_pos + MIN_OUTPUT_OVERHEAD < static_cast<size_t>(noutput_items)) {
        
        size_t available_input = static_cast<size_t>(noutput_items) - processed;
        size_t available_output = static_cast<size_t>(noutput_items) - output_pos;
        
        if (available_output < MIN_OUTPUT_OVERHEAD) {
            break;
        }
        
        size_t chunk_size = std::min(available_input, MAX_CHUNK_SIZE);
        if (chunk_size == 0) {
            break;
        }
        
        std::vector<uint8_t> plaintext(in + processed, in + processed + chunk_size);
        
        auto ephemeral_keypair = d_brainpool_ec->generate_keypair();
        if (!ephemeral_keypair.private_key || !ephemeral_keypair.public_key) {
            memset(out + output_pos, 0, noutput_items - output_pos);
            break;
        }
        
        auto shared_secret = d_brainpool_ec->ecdh_exchange(ephemeral_keypair.private_key,
                                                          d_recipient_public_key);
        if (shared_secret.empty()) {
            EVP_PKEY_free(ephemeral_keypair.private_key);
            EVP_PKEY_free(ephemeral_keypair.public_key);
            memset(out + output_pos, 0, noutput_items - output_pos);
            break;
        }
        
        std::vector<uint8_t> key, iv;
        if (!derive_key_hkdf(shared_secret, key, iv)) {
            EVP_PKEY_free(ephemeral_keypair.private_key);
            EVP_PKEY_free(ephemeral_keypair.public_key);
            memset(out + output_pos, 0, noutput_items - output_pos);
            break;
        }
        
        std::vector<uint8_t> ciphertext, tag;
        if (!encrypt_aes_gcm(plaintext.data(), plaintext.size(), key, iv, ciphertext, tag)) {
            EVP_PKEY_free(ephemeral_keypair.private_key);
            EVP_PKEY_free(ephemeral_keypair.public_key);
            memset(out + output_pos, 0, noutput_items - output_pos);
            break;
        }
        
        std::vector<uint8_t> ephemeral_pubkey_serialized;
        if (!serialize_ephemeral_public_key(ephemeral_keypair.public_key,
                                           ephemeral_pubkey_serialized)) {
            EVP_PKEY_free(ephemeral_keypair.private_key);
            EVP_PKEY_free(ephemeral_keypair.public_key);
            memset(out + output_pos, 0, noutput_items - output_pos);
            break;
        }
        
        EVP_PKEY_free(ephemeral_keypair.private_key);
        EVP_PKEY_free(ephemeral_keypair.public_key);
        
        size_t total_output_size = 2 + ephemeral_pubkey_serialized.size() + AES_IV_SIZE + 
                                   2 + ciphertext.size() + AES_TAG_SIZE;
        
        if (output_pos + total_output_size > static_cast<size_t>(noutput_items)) {
            break;
        }
        
        uint16_t pubkey_len = static_cast<uint16_t>(ephemeral_pubkey_serialized.size());
        out[output_pos++] = static_cast<uint8_t>((pubkey_len >> 8) & 0xFF);
        out[output_pos++] = static_cast<uint8_t>(pubkey_len & 0xFF);
        
        std::memcpy(out + output_pos, ephemeral_pubkey_serialized.data(),
                   ephemeral_pubkey_serialized.size());
        output_pos += ephemeral_pubkey_serialized.size();
        
        std::memcpy(out + output_pos, iv.data(), AES_IV_SIZE);
        output_pos += AES_IV_SIZE;
        
        uint16_t ciphertext_len = static_cast<uint16_t>(ciphertext.size());
        out[output_pos++] = static_cast<uint8_t>((ciphertext_len >> 8) & 0xFF);
        out[output_pos++] = static_cast<uint8_t>(ciphertext_len & 0xFF);
        
        std::memcpy(out + output_pos, ciphertext.data(), ciphertext.size());
        output_pos += ciphertext.size();
        
        std::memcpy(out + output_pos, tag.data(), AES_TAG_SIZE);
        output_pos += AES_TAG_SIZE;
        
        processed += chunk_size;
    }
    
    if (processed == 0) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    return output_pos;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

