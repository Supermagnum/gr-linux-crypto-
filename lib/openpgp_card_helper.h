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

#ifndef INCLUDED_GR_LINUX_CRYPTO_OPENPGP_CARD_HELPER_H
#define INCLUDED_GR_LINUX_CRYPTO_OPENPGP_CARD_HELPER_H

#ifdef HAVE_OPENSSL

#include <openssl/evp.h>
#include <string>
#include <vector>
#include <memory>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Helper class for secure key source operations
 * \ingroup linux_crypto
 *
 * This class provides functionality to work with keys from secure sources:
 * - OpenPGP Card keys (hardware-protected, non-extractable)
 * - Kernel keyring keys (kernel-protected, extractable)
 *
 * Private keys from OpenPGP Card never leave the Secure Element.
 */
class openpgp_card_helper
{
public:
    /*!
     * \brief Extract public key from secure key source
     * \param key_source Key source type: "opgp_card" or "kernel_keyring"
     * \param key_identifier Key identifier (keygrip for OpenPGP Card, key_id for kernel keyring)
     * \return OpenSSL EVP_PKEY pointer (caller must free with EVP_PKEY_free)
     *         Returns nullptr on failure
     */
    static EVP_PKEY* get_public_key(const std::string& key_source, const std::string& key_identifier);

    /*!
     * \brief Extract public key from OpenPGP Card (legacy method)
     * \param keygrip Keygrip identifier for the OpenPGP Card key
     * \return OpenSSL EVP_PKEY pointer (caller must free with EVP_PKEY_free)
     *         Returns nullptr on failure
     */
    static EVP_PKEY* get_public_key_from_card(const std::string& keygrip);

    /*!
     * \brief Extract public key from kernel keyring
     * \param key_id Kernel keyring key ID
     * \return OpenSSL EVP_PKEY pointer (caller must free with EVP_PKEY_free)
     *         Returns nullptr on failure
     */
    static EVP_PKEY* get_public_key_from_kernel(int key_id);

    /*!
     * \brief Perform ECDH key exchange using secure key source
     * \param key_source Key source type: "opgp_card" or "kernel_keyring"
     * \param key_identifier Key identifier (keygrip for OpenPGP Card, key_id for kernel keyring)
     * \param other_public_key The other party's public key (ephemeral key in ECIES)
     * \return Shared secret from ECDH exchange, empty vector on failure
     */
    static std::vector<uint8_t> ecdh_exchange(
        const std::string& key_source,
        const std::string& key_identifier,
        EVP_PKEY* other_public_key
    );

    /*!
     * \brief Perform ECDH key exchange using OpenPGP Card private key (legacy method)
     * \param keygrip Keygrip identifier for the OpenPGP Card key
     * \param other_public_key The other party's public key (ephemeral key in ECIES)
     * \return Shared secret from ECDH exchange, empty vector on failure
     */
    static std::vector<uint8_t> ecdh_exchange_with_card(
        const std::string& keygrip,
        EVP_PKEY* other_public_key
    );

    /*!
     * \brief Perform ECDH key exchange using kernel keyring private key
     * \param key_id Kernel keyring key ID
     * \param other_public_key The other party's public key (ephemeral key in ECIES)
     * \return Shared secret from ECDH exchange, empty vector on failure
     */
    static std::vector<uint8_t> ecdh_exchange_with_kernel(
        int key_id,
        EVP_PKEY* other_public_key
    );

    /*!
     * \brief Check if secure key source is available and key exists
     * \param key_source Key source type: "opgp_card" or "kernel_keyring"
     * \param key_identifier Key identifier (keygrip for OpenPGP Card, key_id for kernel keyring)
     * \return true if source is available and key exists, false otherwise
     */
    static bool is_key_source_available(const std::string& key_source, const std::string& key_identifier);

    /*!
     * \brief Check if OpenPGP Card is available and key exists (legacy method)
     * \param keygrip Keygrip identifier for the OpenPGP Card key
     * \return true if card is available and key exists, false otherwise
     */
    static bool is_card_available(const std::string& keygrip);

    /*!
     * \brief Get keygrip from GnuPG key ID or fingerprint
     * \param key_identifier GnuPG key ID, fingerprint, or email
     * \return Keygrip string, empty if not found
     */
    static std::string get_keygrip_from_key_id(const std::string& key_identifier);

private:
    /*!
     * \brief Export public key from GnuPG in binary format
     * \param keygrip Keygrip identifier
     * \return Public key data in binary format, empty on failure
     */
    static std::vector<uint8_t> export_public_key_binary(const std::string& keygrip);

    /*!
     * \brief Convert GnuPG public key to OpenSSL EVP_PKEY
     * \param key_data Public key data from GnuPG
     * \return OpenSSL EVP_PKEY pointer, nullptr on failure
     */
    static EVP_PKEY* convert_gnupg_to_openssl(const std::vector<uint8_t>& key_data);

    /*!
     * \brief Read key from kernel keyring and parse as PEM
     * \param key_id Kernel keyring key ID
     * \return Key data as string (PEM format), empty on failure
     */
    static std::string read_key_from_kernel(int key_id);

    /*!
     * \brief Parse PEM key data to OpenSSL EVP_PKEY
     * \param pem_data Key data in PEM format
     * \param is_private true for private key, false for public key
     * \param password Password for encrypted private keys (empty if unencrypted)
     * \return OpenSSL EVP_PKEY pointer, nullptr on failure
     */
    static EVP_PKEY* parse_pem_key(const std::string& pem_data, bool is_private, const std::string& password = "");

    /*!
     * \brief Perform ECDH via GnuPG subprocess
     * \param keygrip Keygrip identifier
     * \param ephemeral_pubkey_pem Ephemeral public key in PEM format
     * \return Shared secret, empty on failure
     */
    static std::vector<uint8_t> gpg_ecdh_exchange(
        const std::string& keygrip,
        const std::string& ephemeral_pubkey_pem
    );
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

#endif /* INCLUDED_GR_LINUX_CRYPTO_OPENPGP_CARD_HELPER_H */

