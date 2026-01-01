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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_IMPL_H

#ifdef HAVE_OPENSSL

#include <gnuradio/linux_crypto/brainpool_ecies_multi_encrypt.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <vector>
#include <mutex>
#include <string>
#include <memory>
#include <map>
#include <fstream>
#include <sstream>

namespace gr {
namespace linux_crypto {

class brainpool_ecies_multi_encrypt_impl : public brainpool_ecies_multi_encrypt
{
private:
    brainpool_ec_impl::Curve d_curve;
    std::string d_curve_name;
    std::string d_kdf_info;
    std::string d_key_store_path;
    std::string d_symmetric_cipher;
    uint8_t d_cipher_id;
    std::shared_ptr<brainpool_ec_impl> d_brainpool_ec;
    
    std::vector<std::string> d_callsigns;
    std::map<std::string, EVP_PKEY*> d_recipient_keys;
    mutable std::mutex d_mutex;
    
    std::vector<uint8_t> d_input_buffer;
    std::vector<uint8_t> d_output_buffer;
    
    std::vector<uint8_t> d_key_input_buffer;
    bool d_use_key_input_port;
    static constexpr size_t MAX_KEY_BUFFER_SIZE = 4096;
    
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_IV_SIZE = 12;
    static constexpr size_t AES_TAG_SIZE = 16;
    static constexpr size_t HEADER_SIZE = 8;
    static constexpr size_t MAX_CALLSIGN_LEN = 14;
    static constexpr uint8_t FORMAT_VERSION = 0x01;
    
    static constexpr uint8_t CIPHER_ID_AES_GCM = 0x01;
    static constexpr uint8_t CIPHER_ID_CHACHA20_POLY1305 = 0x02;
    
    bool load_key_store();
    bool get_public_key_from_store(const std::string& callsign, std::string& public_key_pem);
    uint8_t get_curve_id() const;
    
    bool derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
                        std::vector<uint8_t>& key,
                        std::vector<uint8_t>& iv);
    
    bool encrypt_aes_gcm(const uint8_t* plaintext,
                        size_t plaintext_len,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag);
    
    bool encrypt_chacha20_poly1305(const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& nonce,
                                  std::vector<uint8_t>& ciphertext,
                                  std::vector<uint8_t>& tag);
    
    uint8_t get_cipher_id_from_name(const std::string& cipher_name) const;
    
    bool encrypt_symmetric_key_ecies(const std::vector<uint8_t>& symmetric_key,
                                    EVP_PKEY* recipient_public_key,
                                    std::vector<uint8_t>& encrypted_key_block);
    
    bool serialize_ephemeral_public_key(EVP_PKEY* public_key,
                                       std::vector<uint8_t>& serialized);
    
    size_t get_public_key_size() const;
    
    void build_header(uint8_t recipient_count, uint32_t data_length, uint8_t cipher_id, std::vector<uint8_t>& header);
    void build_recipient_block(const std::string& callsign,
                              const std::vector<uint8_t>& encrypted_key,
                              std::vector<uint8_t>& block);
    
    void process_key_input(const unsigned char* key_data, int n_items);
    bool parse_and_store_key(const std::string& key_data_str, const std::string& callsign = "");

public:
    brainpool_ecies_multi_encrypt_impl(const std::string& curve,
                                      const std::vector<std::string>& callsigns,
                                      const std::string& key_store_path,
                                      const std::string& kdf_info,
                                      const std::string& symmetric_cipher);
    ~brainpool_ecies_multi_encrypt_impl();

    void set_callsigns(const std::vector<std::string>& callsigns) override;
    std::vector<std::string> get_callsigns() const override;
    bool add_callsign(const std::string& callsign) override;
    bool remove_callsign(const std::string& callsign) override;
    void set_kdf_info(const std::string& kdf_info) override;
    std::string get_kdf_info() const override;
    std::string get_curve() const override;

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items) override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_IMPL_H */

