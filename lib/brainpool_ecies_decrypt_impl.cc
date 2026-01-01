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
#include "brainpool_ecies_decrypt_impl.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace gr {
namespace linux_crypto {

brainpool_ecies_decrypt::sptr
brainpool_ecies_decrypt::make(const std::string& curve,
                               const std::string& key_source,
                               const std::string& recipient_key_identifier,
                               const std::string& kdf_info)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecies_decrypt_impl(curve, key_source, recipient_key_identifier, kdf_info));
}

brainpool_ecies_decrypt_impl::brainpool_ecies_decrypt_impl(
    const std::string& curve,
    const std::string& key_source,
    const std::string& recipient_key_identifier,
    const std::string& kdf_info)
    : gr::sync_block("brainpool_ecies_decrypt",
                     gr::io_signature::make(1, 2, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_kdf_info(kdf_info),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve)),
      d_key_source(key_source),
      d_recipient_key_identifier(recipient_key_identifier),
      d_ephemeral_public_key_size(0),
      d_use_key_input_port(false)
{
    // Key will be loaded on-demand during decryption
}

brainpool_ecies_decrypt_impl::~brainpool_ecies_decrypt_impl()
{
    // No keys to free - keys are managed by secure sources
}

size_t
brainpool_ecies_decrypt_impl::get_public_key_size() const
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
brainpool_ecies_decrypt_impl::set_kdf_info(const std::string& kdf_info)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_kdf_info = kdf_info;
}

std::string
brainpool_ecies_decrypt_impl::get_kdf_info() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_kdf_info;
}

std::string
brainpool_ecies_decrypt_impl::get_curve() const
{
    return d_curve_name;
}

void
brainpool_ecies_decrypt_impl::set_recipient_key(const std::string& key_source, const std::string& key_identifier)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    d_key_source = key_source;
    d_recipient_key_identifier = key_identifier;
}

std::string
brainpool_ecies_decrypt_impl::get_key_source() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_source;
}

std::string
brainpool_ecies_decrypt_impl::get_recipient_key_identifier() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_recipient_key_identifier;
}

bool
brainpool_ecies_decrypt_impl::is_key_loaded() const
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

bool
brainpool_ecies_decrypt_impl::derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
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
brainpool_ecies_decrypt_impl::decrypt_aes_gcm(const uint8_t* ciphertext,
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

EVP_PKEY*
brainpool_ecies_decrypt_impl::deserialize_ephemeral_public_key(const uint8_t* data, size_t data_len)
{
    BIO* bio = BIO_new_mem_buf(data, data_len);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    return pkey;
}

int
brainpool_ecies_decrypt_impl::work(int noutput_items,
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
    
    if (d_recipient_key_identifier.empty() || !is_key_loaded()) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t processed = 0;
    size_t output_pos = 0;
    
    constexpr size_t MIN_INPUT_SIZE = 2 + 1 + AES_IV_SIZE + 2 + 1 + AES_TAG_SIZE;
    
    while (processed + MIN_INPUT_SIZE <= static_cast<size_t>(noutput_items)) {
        size_t remaining = static_cast<size_t>(noutput_items) - processed;
        
        if (remaining < MIN_INPUT_SIZE) {
            break;
        }
        
        const uint8_t* current = in + processed;
        
        if (remaining < 2) {
            break;
        }
        
        uint16_t pubkey_len = (static_cast<uint16_t>(current[0]) << 8) | current[1];
        processed += 2;
        remaining -= 2;
        
        if (pubkey_len == 0 || pubkey_len > 1024 || pubkey_len > remaining) {
            break;
        }
        
        EVP_PKEY* ephemeral_pubkey = deserialize_ephemeral_public_key(
            current + 2, pubkey_len);
        if (!ephemeral_pubkey) {
            break;
        }
        
        processed += pubkey_len;
        remaining -= pubkey_len;
        
        if (remaining < AES_IV_SIZE + 2 + AES_TAG_SIZE) {
            EVP_PKEY_free(ephemeral_pubkey);
            break;
        }
        
        std::vector<uint8_t> iv(current + 2 + pubkey_len, 
                                current + 2 + pubkey_len + AES_IV_SIZE);
        processed += AES_IV_SIZE;
        remaining -= AES_IV_SIZE;
        
        uint16_t ciphertext_len = (static_cast<uint16_t>(current[2 + pubkey_len + AES_IV_SIZE]) << 8) | 
                                  current[2 + pubkey_len + AES_IV_SIZE + 1];
        processed += 2;
        remaining -= 2;
        
        if (ciphertext_len == 0 || ciphertext_len > 65535 ||
            remaining < ciphertext_len + AES_TAG_SIZE) {
            EVP_PKEY_free(ephemeral_pubkey);
            break;
        }
        
        std::vector<uint8_t> ciphertext(current + 2 + pubkey_len + AES_IV_SIZE + 2,
                                       current + 2 + pubkey_len + AES_IV_SIZE + 2 + ciphertext_len);
        processed += ciphertext_len;
        remaining -= ciphertext_len;
        
        std::vector<uint8_t> tag(current + 2 + pubkey_len + AES_IV_SIZE + 2 + ciphertext_len,
                                current + 2 + pubkey_len + AES_IV_SIZE + 2 + ciphertext_len + AES_TAG_SIZE);
        processed += AES_TAG_SIZE;
        
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
            memset(out + output_pos, 0, noutput_items - output_pos);
            continue;
        }
        
        std::vector<uint8_t> key, derived_iv;
        if (!derive_key_hkdf(shared_secret, key, derived_iv)) {
            memset(out + output_pos, 0, noutput_items - output_pos);
            continue;
        }
        
        if (derived_iv != iv) {
            memset(out + output_pos, 0, noutput_items - output_pos);
            continue;
        }
        
        std::vector<uint8_t> plaintext;
        if (!decrypt_aes_gcm(ciphertext.data(), ciphertext.size(), key, iv, tag, plaintext)) {
            memset(out + output_pos, 0, noutput_items - output_pos);
            continue;
        }
        
        if (output_pos + plaintext.size() > static_cast<size_t>(noutput_items)) {
            break;
        }
        
        std::memcpy(out + output_pos, plaintext.data(), plaintext.size());
        output_pos += plaintext.size();
    }
    
    if (output_pos == 0) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    return output_pos;
}

void
brainpool_ecies_decrypt_impl::process_key_input(const unsigned char* key_data, int n_items)
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
brainpool_ecies_decrypt_impl::parse_and_store_key(const std::string& key_data_str)
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

