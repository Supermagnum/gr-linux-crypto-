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

#include "openpgp_card_helper.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <keyutils.h>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

#ifdef HAVE_GPGME
#include <gpgme.h>
#include <gpg-error.h>
#endif

namespace gr {
namespace linux_crypto {

EVP_PKEY*
openpgp_card_helper::get_public_key(const std::string& key_source, const std::string& key_identifier)
{
    if (key_source == "opgp_card") {
        return get_public_key_from_card(key_identifier);
    } else if (key_source == "kernel_keyring") {
        try {
            int key_id = std::stoi(key_identifier);
            return get_public_key_from_kernel(key_id);
        } catch (...) {
            return nullptr;
        }
    }
    return nullptr;
}

EVP_PKEY*
openpgp_card_helper::get_public_key_from_card(const std::string& keygrip)
{
    if (keygrip.empty()) {
        return nullptr;
    }

    // Find key ID from keygrip
    std::string command = "gpg --list-secret-keys --keyid-format=long --with-keygrip 2>/dev/null | grep -B5 '" + keygrip + "' | grep '^sec' | head -1 | awk '{print $2}' | cut -d'/' -f2";
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return nullptr;
    }

    char buffer[128];
    std::string key_id;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        key_id = buffer;
        // Remove trailing newline
        if (!key_id.empty() && key_id.back() == '\n') {
            key_id.pop_back();
        }
    }
    pclose(pipe);

    if (key_id.empty()) {
        return nullptr;
    }

    // Export public key in OpenPGP format and convert to PEM
    // GnuPG exports in OpenPGP format, so we need to parse it
    // For now, use a workaround: try to get the key in a parseable format
    // 
    // Actually, we can use GnuPG's --export with --export-options to get
    // the key, but it's still OpenPGP format. We need to parse it.
    //
    // Simplified approach: Use the fact that OpenPGP public keys contain
    // the same cryptographic material as OpenSSL keys, just in a different format.
    // We'll parse the minimal necessary parts.
    
    command = "gpg --export --export-options export-minimal " + key_id + " 2>/dev/null";
    pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return nullptr;
    }

    std::vector<uint8_t> key_data;
    char read_buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(read_buffer, 1, sizeof(read_buffer), pipe)) > 0) {
        key_data.insert(key_data.end(), read_buffer, read_buffer + bytes_read);
    }
    pclose(pipe);

    if (key_data.empty()) {
        return nullptr;
    }

    // Convert OpenPGP format to OpenSSL EVP_PKEY
    // This requires parsing OpenPGP packets (RFC 4880)
    // For now, return nullptr and document that GPGME or OpenPGP parser is needed
    // TODO: Implement OpenPGP packet parsing or integrate GPGME library
    
    return convert_gnupg_to_openssl(key_data);
}

EVP_PKEY*
openpgp_card_helper::get_public_key_from_kernel(int key_id)
{
    // Read key from kernel keyring
    std::string pem_data = read_key_from_kernel(key_id);
    if (pem_data.empty()) {
        return nullptr;
    }

    // Parse as public key (try public key first, then private key)
    EVP_PKEY* pkey = parse_pem_key(pem_data, false, "");
    if (pkey) {
        return pkey;
    }

    // If public key parsing failed, try as private key and extract public key
    pkey = parse_pem_key(pem_data, true, "");
    if (pkey) {
        // Extract public key from private key
        EVP_PKEY* pubkey = nullptr;
        EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key) {
            EC_KEY* pub_ec_key = EC_KEY_new();
            if (pub_ec_key) {
                const EC_GROUP* group = EC_KEY_get0_group(ec_key);
                const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key);
                
                EC_KEY_set_group(pub_ec_key, group);
                EC_KEY_set_public_key(pub_ec_key, pub_point);
                
                pubkey = EVP_PKEY_new();
                if (pubkey) {
                    EVP_PKEY_set1_EC_KEY(pubkey, pub_ec_key);
                }
                EC_KEY_free(pub_ec_key);
            }
            EC_KEY_free(ec_key);
        }
        EVP_PKEY_free(pkey);
        return pubkey;
    }

    return nullptr;
}

std::vector<uint8_t>
openpgp_card_helper::ecdh_exchange(
    const std::string& key_source,
    const std::string& key_identifier,
    EVP_PKEY* other_public_key)
{
    if (key_source == "opgp_card") {
        return ecdh_exchange_with_card(key_identifier, other_public_key);
    } else if (key_source == "kernel_keyring") {
        try {
            int key_id = std::stoi(key_identifier);
            return ecdh_exchange_with_kernel(key_id, other_public_key);
        } catch (...) {
            return std::vector<uint8_t>();
        }
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t>
openpgp_card_helper::ecdh_exchange_with_card(
    const std::string& keygrip,
    EVP_PKEY* other_public_key)
{
    if (keygrip.empty() || !other_public_key) {
        return std::vector<uint8_t>();
    }

    // Serialize ephemeral public key to PEM format
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return std::vector<uint8_t>();
    }

    if (PEM_write_bio_PUBKEY(bio, other_public_key) != 1) {
        BIO_free(bio);
        return std::vector<uint8_t>();
    }

    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::string ephemeral_pubkey_pem(pem_data, pem_len);
    BIO_free(bio);

    // Use GnuPG to perform ECDH
    return gpg_ecdh_exchange(keygrip, ephemeral_pubkey_pem);
}

std::vector<uint8_t>
openpgp_card_helper::ecdh_exchange_with_kernel(
    int key_id,
    EVP_PKEY* other_public_key)
{
    if (!other_public_key) {
        return std::vector<uint8_t>();
    }

    // Read private key from kernel keyring
    std::string pem_data = read_key_from_kernel(key_id);
    if (pem_data.empty()) {
        return std::vector<uint8_t>();
    }

    // Parse private key
    EVP_PKEY* private_key = parse_pem_key(pem_data, true, "");
    if (!private_key) {
        return std::vector<uint8_t>();
    }

    // Perform ECDH using OpenSSL
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(private_key);
        return std::vector<uint8_t>();
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return std::vector<uint8_t>();
    }

    if (EVP_PKEY_derive_set_peer(ctx, other_public_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return std::vector<uint8_t>();
    }

    // Determine shared secret size
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return std::vector<uint8_t>();
    }

    // Derive shared secret
    std::vector<uint8_t> shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return std::vector<uint8_t>();
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    return shared_secret;
}

bool
openpgp_card_helper::is_key_source_available(
    const std::string& key_source,
    const std::string& key_identifier)
{
    if (key_source == "opgp_card") {
        return is_card_available(key_identifier);
    } else if (key_source == "kernel_keyring") {
        try {
            int key_id = std::stoi(key_identifier);
            long key_size = keyctl(KEYCTL_READ, key_id, nullptr, 0);
            return key_size >= 0;
        } catch (...) {
            return false;
        }
    }
    return false;
}

bool
openpgp_card_helper::is_card_available(const std::string& keygrip)
{
    if (keygrip.empty()) {
        return false;
    }

    // Check if GnuPG can access the key
    FILE* pipe = popen(("gpg --list-secret-keys --keyid-format=long --with-keygrip 2>/dev/null | grep -q \"" + keygrip + "\"").c_str(), "r");
    if (!pipe) {
        return false;
    }

    int status = pclose(pipe);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

std::string
openpgp_card_helper::get_keygrip_from_key_id(const std::string& key_identifier)
{
    if (key_identifier.empty()) {
        return "";
    }

    // Use GnuPG to get keygrip from key ID
    std::string command = "gpg --list-secret-keys --keyid-format=long --with-keygrip " + key_identifier + " 2>/dev/null | grep -A1 '^sec' | grep 'Keygrip' | awk '{print $3}'";
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "";
    }

    char buffer[128];
    std::string keygrip;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        keygrip = buffer;
        // Remove trailing newline
        if (!keygrip.empty() && keygrip.back() == '\n') {
            keygrip.pop_back();
        }
    }

    pclose(pipe);
    return keygrip;
}

std::vector<uint8_t>
openpgp_card_helper::export_public_key_binary(const std::string& keygrip)
{
    if (keygrip.empty()) {
        return std::vector<uint8_t>();
    }

    // Find key ID from keygrip by searching GnuPG keyring
    // The keygrip is a unique identifier, so we search for it in the keyring
    std::string command = "gpg --list-secret-keys --keyid-format=long --with-keygrip 2>/dev/null | grep -B5 '" + keygrip + "' | grep '^sec' | head -1 | awk '{print $2}' | cut -d'/' -f2";
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return std::vector<uint8_t>();
    }

    char buffer[128];
    std::string key_id;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        key_id = buffer;
        // Remove trailing newline
        if (!key_id.empty() && key_id.back() == '\n') {
            key_id.pop_back();
        }
    }
    pclose(pipe);

    if (key_id.empty()) {
        // If we couldn't find key ID, try using keygrip directly (might work for some GnuPG versions)
        key_id = keygrip;
    }

    // Export public key in binary format
    command = "gpg --export --export-options export-minimal " + key_id + " 2>/dev/null";
    
    pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> key_data;
    char read_buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(read_buffer, 1, sizeof(read_buffer), pipe)) > 0) {
        key_data.insert(key_data.end(), read_buffer, read_buffer + bytes_read);
    }

    pclose(pipe);
    return key_data;
}

EVP_PKEY*
openpgp_card_helper::convert_gnupg_to_openssl(const std::vector<uint8_t>& key_data)
{
    if (key_data.empty()) {
        return nullptr;
    }

#ifdef HAVE_GPGME
    // Use GPGME to parse OpenPGP format and convert to OpenSSL format
    gpgme_error_t err;
    gpgme_ctx_t ctx = nullptr;
    gpgme_data_t key_data_gpgme = nullptr;
    gpgme_data_t pem_data = nullptr;
    EVP_PKEY* pkey = nullptr;

    // Initialize GPGME
    err = gpgme_new(&ctx);
    if (err != GPG_ERR_NO_ERROR) {
        return nullptr;
    }

    // Set protocol to OpenPGP
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_release(ctx);
        return nullptr;
    }

    // Create data object from key data
    err = gpgme_data_new_from_mem(&key_data_gpgme,
                                   reinterpret_cast<const char*>(key_data.data()),
                                   key_data.size(),
                                   0);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_release(ctx);
        return nullptr;
    }

    // Import the key
    err = gpgme_op_import(ctx, key_data_gpgme);
    gpgme_import_result_t import_result = gpgme_op_import_result(ctx);
    if (err != GPG_ERR_NO_ERROR || !import_result || import_result->imported == 0) {
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    // Get the imported key fingerprint
    gpgme_key_t key = nullptr;
    if (import_result->imports && import_result->imports->fpr) {
        err = gpgme_get_key(ctx, import_result->imports->fpr, &key, 0);
        if (err != GPG_ERR_NO_ERROR) {
            gpgme_data_release(key_data_gpgme);
            gpgme_release(ctx);
            return nullptr;
        }
    } else {
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    // Export key in PEM format using GPGME
    err = gpgme_data_new(&pem_data);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_key_release(key);
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    // Export public key
    err = gpgme_op_export(ctx, key->subkeys->keyid, GPGME_EXPORT_MODE_MINIMAL, pem_data);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_data_release(pem_data);
        gpgme_key_release(key);
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    // Read PEM data
    off_t pem_len = gpgme_data_seek(pem_data, 0, SEEK_END);
    gpgme_data_seek(pem_data, 0, SEEK_SET);
    
    if (pem_len <= 0) {
        gpgme_data_release(pem_data);
        gpgme_key_release(key);
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    std::vector<char> pem_buffer(pem_len);
    ssize_t read_len = gpgme_data_read(pem_data, pem_buffer.data(), pem_len);
    
    if (read_len <= 0) {
        gpgme_data_release(pem_data);
        gpgme_key_release(key);
        gpgme_data_release(key_data_gpgme);
        gpgme_release(ctx);
        return nullptr;
    }

    // Parse PEM data with OpenSSL
    std::string pem_string(pem_buffer.data(), read_len);
    pkey = parse_pem_key(pem_string, false, "");

    // Cleanup
    gpgme_data_release(pem_data);
    gpgme_key_release(key);
    gpgme_data_release(key_data_gpgme);
    gpgme_release(ctx);

    return pkey;
#else
    // Fallback: Basic OpenPGP format parser (RFC 4880)
    // This is a simplified parser that extracts EC public keys from OpenPGP packets
    // For full support, GPGME is recommended
    
    if (key_data.size() < 3) {
        return nullptr;
    }

    // OpenPGP packets start with a tag byte
    // Public Key Packet (tag 6) or Public Subkey Packet (tag 14)
    size_t pos = 0;
    while (pos < key_data.size()) {
        if (pos + 1 >= key_data.size()) {
            break;
        }

        uint8_t tag_byte = key_data[pos];
        uint8_t packet_tag = (tag_byte >> 2) & 0x3F;
        bool new_format = (tag_byte & 0x40) != 0;

        pos++;

        // Read packet length
        size_t packet_len = 0;
        if (new_format) {
            if (pos >= key_data.size()) {
                break;
            }
            uint8_t len_byte = key_data[pos++];
            if (len_byte < 192) {
                packet_len = len_byte;
            } else if (len_byte < 224) {
                if (pos + 1 >= key_data.size()) {
                    break;
                }
                packet_len = ((len_byte - 192) << 8) + key_data[pos++] + 192;
            } else if (len_byte == 255) {
                if (pos + 4 >= key_data.size()) {
                    break;
                }
                packet_len = (static_cast<size_t>(key_data[pos]) << 24) |
                             (static_cast<size_t>(key_data[pos + 1]) << 16) |
                             (static_cast<size_t>(key_data[pos + 2]) << 8) |
                             static_cast<size_t>(key_data[pos + 3]);
                pos += 4;
            } else {
                // Partial body length (not supported in this simple parser)
                break;
            }
        } else {
            // Old format (not commonly used)
            break;
        }

        // Check if this is a public key packet (tag 6) or public subkey packet (tag 14)
        if (packet_tag == 6 || packet_tag == 14) {
            if (pos + packet_len > key_data.size()) {
                break;
            }

            // Parse public key packet
            // Format: version(1) | timestamp(4) | algorithm(1) | key material
            if (pos + 6 >= key_data.size()) {
                break;
            }

            uint8_t version = key_data[pos];
            if (version != 4) {
                // Only support version 4 packets
                pos += packet_len;
                continue;
            }

            pos += 5; // Skip version and timestamp
            uint8_t algorithm = key_data[pos++];

            // Check if this is an EC key (algorithm 18 = ECDSA, 19 = ECDH)
            if (algorithm == 18 || algorithm == 19) {
                // EC key format: OID length(1) | OID | curve point
                if (pos >= key_data.size()) {
                    break;
                }

                uint8_t oid_len = key_data[pos++];
                if (pos + oid_len >= key_data.size()) {
                    break;
                }

                // Skip OID (we assume Brainpool curves)
                pos += oid_len;

                // Read curve point (uncompressed format: 0x04 | x | y)
                if (pos >= key_data.size()) {
                    break;
                }

                uint8_t point_format = key_data[pos++];
                if (point_format != 0x04) {
                    // Only support uncompressed points
                    pos += packet_len - (pos - (packet_len > 0 ? pos : 0));
                    continue;
                }

                // For Brainpool P256r1, each coordinate is 32 bytes
                // For Brainpool P384r1, each coordinate is 48 bytes
                // For Brainpool P512r1, each coordinate is 64 bytes
                // We'll try to determine from remaining data
                size_t remaining = packet_len - (pos - (packet_len > 0 ? (pos - packet_len + 6) : 0));
                if (remaining < 64 || remaining % 2 != 0) {
                    pos += packet_len - (pos - (packet_len > 0 ? (pos - packet_len + 6) : 0));
                    continue;
                }

                size_t coord_len = remaining / 2;
                if (pos + remaining > key_data.size()) {
                    break;
                }

                // Extract x and y coordinates
                std::vector<uint8_t> x_coord(key_data.begin() + pos, key_data.begin() + pos + coord_len);
                std::vector<uint8_t> y_coord(key_data.begin() + pos + coord_len, key_data.begin() + pos + 2 * coord_len);

                // Create OpenSSL EC key from coordinates
                // This is a simplified approach - in practice, we'd need to
                // determine the curve from the OID and create the appropriate EC_GROUP
                // For now, try common Brainpool curves
                EC_KEY* ec_key = nullptr;
                const EC_GROUP* group = nullptr;

                // Try Brainpool P256r1 first
                group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
                if (group) {
                    ec_key = EC_KEY_new();
                    if (ec_key) {
                        EC_KEY_set_group(ec_key, group);
                        BIGNUM* x = BN_bin2bn(x_coord.data(), x_coord.size(), nullptr);
                        BIGNUM* y = BN_bin2bn(y_coord.data(), y_coord.size(), nullptr);
                        EC_POINT* point = EC_POINT_new(group);
                        if (point && x && y) {
                            if (EC_POINT_set_affine_coordinates(group, point, x, y, nullptr)) {
                                EC_KEY_set_public_key(ec_key, point);
                                EVP_PKEY* pkey = EVP_PKEY_new();
                                if (pkey) {
                                    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
                                    EC_POINT_free(point);
                                    BN_free(x);
                                    BN_free(y);
                                    EC_KEY_free(ec_key);
                                    EC_GROUP_free(const_cast<EC_GROUP*>(group));
                                    return pkey;
                                }
                            }
                            EC_POINT_free(point);
                        }
                        if (x) BN_free(x);
                        if (y) BN_free(y);
                        EC_KEY_free(ec_key);
                    }
                    EC_GROUP_free(const_cast<EC_GROUP*>(group));
                }

                // If P256r1 failed, try other curves (P384r1, P512r1)
                // For brevity, we'll just return nullptr here
                // A full implementation would try all Brainpool curves
            }
        }

        pos += packet_len;
    }

    // If we couldn't parse it, return nullptr
    return nullptr;
#endif
}

std::vector<uint8_t>
openpgp_card_helper::gpg_ecdh_exchange(
    const std::string& keygrip,
    const std::string& ephemeral_pubkey_pem)
{
    if (keygrip.empty() || ephemeral_pubkey_pem.empty()) {
        return std::vector<uint8_t>();
    }

#ifdef HAVE_GPGME
    // Use GPGME to perform ECDH with OpenPGP Card key
    gpgme_error_t err;
    gpgme_ctx_t ctx = nullptr;
    gpgme_key_t card_key = nullptr;
    gpgme_data_t ephemeral_key_data = nullptr;
    std::vector<uint8_t> shared_secret;

    // Initialize GPGME
    err = gpgme_new(&ctx);
    if (err != GPG_ERR_NO_ERROR) {
        return std::vector<uint8_t>();
    }

    // Set protocol to OpenPGP
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_release(ctx);
        return std::vector<uint8_t>();
    }

    // Find key by keygrip - first get key ID from keygrip
    std::string key_id = get_keygrip_from_key_id(keygrip);
    if (key_id.empty()) {
        // Try using keygrip directly as key ID
        key_id = keygrip;
    }

    // Get the key by ID
    err = gpgme_get_key(ctx, key_id.c_str(), &card_key, 0);
    if (err != GPG_ERR_NO_ERROR || !card_key) {
        gpgme_release(ctx);
        return std::vector<uint8_t>();
    }

    // Import ephemeral public key
    err = gpgme_data_new_from_mem(&ephemeral_key_data,
                                   ephemeral_pubkey_pem.c_str(),
                                   ephemeral_pubkey_pem.size(),
                                   0);
    if (err != GPG_ERR_NO_ERROR) {
        gpgme_key_release(card_key);
        gpgme_release(ctx);
        return std::vector<uint8_t>();
    }

    // Import the ephemeral key
    err = gpgme_op_import(ctx, ephemeral_key_data);
    gpgme_import_result_t import_result = gpgme_op_import_result(ctx);
    if (err != GPG_ERR_NO_ERROR || !import_result || import_result->imported == 0) {
        gpgme_data_release(ephemeral_key_data);
        gpgme_key_release(card_key);
        gpgme_release(ctx);
        return std::vector<uint8_t>();
    }

    // Get the ephemeral key
    gpgme_key_t ephemeral_key = nullptr;
    if (import_result->imports && import_result->imports->fpr) {
        err = gpgme_get_key(ctx, import_result->imports->fpr, &ephemeral_key, 0);
        if (err != GPG_ERR_NO_ERROR) {
            gpgme_data_release(ephemeral_key_data);
            gpgme_key_release(card_key);
            gpgme_release(ctx);
            return std::vector<uint8_t>();
        }
    } else {
        gpgme_data_release(ephemeral_key_data);
        gpgme_key_release(card_key);
        gpgme_release(ctx);
        return std::vector<uint8_t>();
    }

    // Note: GPGME doesn't expose ECDH directly. The encryption operation
    // uses ECDH internally, but doesn't return the shared secret.
    // For ECIES, we need the raw shared secret to derive the symmetric key.
    //
    // Workaround options:
    // 1. Use GPGME's Assuan interface to access lower-level card operations
    // 2. Extract public keys and perform ECDH in software (defeats hardware protection)
    // 3. Use a hybrid approach with GPGME for key management and OpenSSL for ECDH
    //
    // For now, we'll return empty vector. Full ECDH support requires either:
    // - GPGME Assuan interface integration
    // - Or accepting that we need to extract the public key and do ECDH in software
    //   (which defeats the purpose of hardware protection for the private key)

    // Cleanup
    gpgme_key_release(ephemeral_key);
    gpgme_data_release(ephemeral_key_data);
    gpgme_key_release(card_key);
    gpgme_release(ctx);

    // TODO: Implement proper ECDH using GPGME Assuan interface
    // This requires using gpgme_op_assuan_transact to send commands
    // directly to the card, which is complex and card-specific
    
    return std::vector<uint8_t>();
#else
    // Without GPGME, we cannot perform ECDH with hardware-protected keys
    // Return empty vector
    return std::vector<uint8_t>();
#endif
}

std::string
openpgp_card_helper::read_key_from_kernel(int key_id)
{
    // Get key size first
    long key_size = keyctl(KEYCTL_READ, key_id, nullptr, 0);
    if (key_size < 0) {
        return "";
    }

    // Read key data
    std::vector<char> key_data(key_size);
    long bytes_read = keyctl(KEYCTL_READ, key_id, key_data.data(), key_size);
    if (bytes_read < 0 || static_cast<size_t>(bytes_read) != static_cast<size_t>(key_size)) {
        return "";
    }

    return std::string(key_data.data(), key_size);
}

EVP_PKEY*
openpgp_card_helper::parse_pem_key(
    const std::string& pem_data,
    bool is_private,
    const std::string& password)
{
    if (pem_data.empty()) {
        return nullptr;
    }

    BIO* bio = BIO_new_mem_buf(pem_data.data(), pem_data.size());
    if (!bio) {
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    const char* passwd = password.empty() ? nullptr : password.c_str();

    if (is_private) {
        pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, const_cast<char*>(passwd));
    } else {
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    }

    BIO_free(bio);
    return pkey;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

