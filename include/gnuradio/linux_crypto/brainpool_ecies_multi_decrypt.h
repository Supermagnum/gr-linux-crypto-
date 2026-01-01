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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_DECRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_DECRYPT_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECIES multi-recipient decryption block
 * \ingroup linux_crypto
 *
 * This block implements multi-recipient ECIES decryption using Brainpool
 * elliptic curves. The block:
 * 1. Parses the encrypted block header
 * 2. Searches for the recipient's callsign in recipient blocks
 * 3. Decrypts the symmetric key using recipient's private key (ECIES)
 * 4. Decrypts the payload using AES-GCM with the symmetric key
 * 5. Outputs decrypted plaintext
 */
class LINUX_CRYPTO_API brainpool_ecies_multi_decrypt : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecies_multi_decrypt> sptr;

    /*!
     * \brief Make a Brainpool ECIES multi-recipient decryption block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param recipient_callsign Callsign of this recipient
     * \param key_source Key source type: "opgp_card" or "kernel_keyring"
     * \param recipient_key_identifier Key identifier (keygrip for OpenPGP Card, key_id for kernel keyring)
     * \param kdf_info Optional context information for HKDF key derivation (must match encryption)
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::string& recipient_callsign = "",
                    const std::string& key_source = "kernel_keyring",
                    const std::string& recipient_key_identifier = "",
                    const std::string& kdf_info = "gr-linux-crypto-ecies-v1");

    /*!
     * \brief Set recipient callsign
     * \param callsign Callsign of this recipient
     */
    virtual void set_recipient_callsign(const std::string& callsign) = 0;

    /*!
     * \brief Get current recipient callsign
     * \return Current callsign
     */
    virtual std::string get_recipient_callsign() const = 0;

    /*!
     * \brief Set recipient's key source and identifier
     * \param key_source Key source type: "opgp_card" or "kernel_keyring"
     * \param key_identifier Key identifier (keygrip for OpenPGP Card, key_id for kernel keyring)
     */
    virtual void set_recipient_key(const std::string& key_source, const std::string& key_identifier) = 0;

    /*!
     * \brief Get current key source
     * \return Key source type ("opgp_card" or "kernel_keyring")
     */
    virtual std::string get_key_source() const = 0;

    /*!
     * \brief Get current recipient's key identifier
     * \return Key identifier (keygrip or key_id)
     */
    virtual std::string get_recipient_key_identifier() const = 0;

    /*!
     * \brief Check if key is loaded and available
     * \return true if key is loaded and available
     */
    virtual bool is_key_loaded() const = 0;

    /*!
     * \brief Set KDF info parameter
     * \param kdf_info Context information for HKDF (must match encryption)
     */
    virtual void set_kdf_info(const std::string& kdf_info) = 0;

    /*!
     * \brief Get current KDF info parameter
     * \return Current KDF info string
     */
    virtual std::string get_kdf_info() const = 0;

    /*!
     * \brief Get current curve
     * \return Curve name
     */
    virtual std::string get_curve() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_DECRYPT_H */
