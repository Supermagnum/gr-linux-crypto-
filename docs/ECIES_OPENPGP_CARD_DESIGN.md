# ECIES Blocks - Secure Key Source Integration Design

## Overview

Refactor ECIES blocks to use **secure key sources** instead of PEM keys. Supported sources:
1. **OpenPGP Card keys** (hardware-protected, non-extractable) - Maximum security
2. **Kernel keyring keys** (Linux kernel-protected, extractable) - High security, flexible

This ensures keys are stored securely and never in plain PEM format in user space.

## Security Requirements

- **OpenPGP Card private keys MUST NEVER leave the Secure Element**
- **Kernel keyring keys are kernel-protected** (extractable but secure)
- **Only public keys can be extracted from OpenPGP Card** (for encryption)
- **Decryption operations use GnuPG/OpenPGP Card interfaces OR kernel keyring**
- **No PEM key support** (removed for security - keys must come from secure sources)

## Architecture Changes

### Key Input Ports (Added 2025-12-XX)

All ECIES blocks now support **optional key input ports** that allow dynamic key input from hardware sources:

- **Port 1 (optional)**: Accepts key data from `nitrokey_interface` or `kernel_keyring_source` blocks
- Keys are buffered until a complete PEM key is detected (BEGIN/END markers)
- Keys from input ports take precedence over secure key sources
- For encrypt blocks: Key is associated with the first callsign in recipient list
- For decrypt blocks: Key is used directly for ECDH operations

This provides flexibility for flowgraph-based key management while maintaining security through hardware sources.

### Current Architecture (PEM-based)
```
ECIES Encrypt:
  - Input: PEM public key
  - Process: OpenSSL EVP_PKEY → ECDH → HKDF → AES-GCM
  - Output: ECIES encrypted data

ECIES Decrypt:
  - Input: PEM private key
  - Process: OpenSSL EVP_PKEY → ECDH → HKDF → AES-GCM
  - Output: Decrypted plaintext
```

### New Architecture (Secure Key Source-based)
```
ECIES Encrypt:
  - Input: Key source type + identifier
    * OpenPGP Card: keygrip/key ID
    * Kernel keyring: key_id
  - Process: 
    1. Extract public key from source:
       - OpenPGP Card: Extract via GnuPG
       - Kernel keyring: Read from kernel, parse PEM
    2. Convert to OpenSSL EVP_PKEY
    3. Perform ECIES encryption (ECDH → HKDF → AES-GCM)
  - Output: ECIES encrypted data

ECIES Decrypt:
  - Input: Key source type + identifier
    * OpenPGP Card: keygrip/key ID
    * Kernel keyring: key_id
  - Process:
    1. Extract ephemeral public key from encrypted data
    2. Get private key from source:
       - OpenPGP Card: Use GnuPG to perform ECDH (key never extracted)
       - Kernel keyring: Read from kernel, parse PEM, use OpenSSL ECDH
    3. Derive symmetric key (HKDF)
    4. Decrypt with AES-GCM
  - Output: Decrypted plaintext
```

## Implementation Strategy

### Hybrid Approach (Recommended)
- **Encryption:** Extract public key from source (OpenPGP Card or kernel keyring), use OpenSSL for ECIES
- **Decryption:** 
  - **OpenPGP Card:** Use GnuPG subprocess for ECDH (key never extracted)
  - **Kernel keyring:** Extract key from kernel, use OpenSSL ECDH
- Then use OpenSSL for HKDF/AES-GCM (common path)

**Pros:**
- Maintains ECIES format compatibility
- Supports multiple secure key sources
- Hardware-protected keys (OpenPGP Card)
- Kernel-protected keys (kernel keyring)
- Leverages existing OpenSSL code

**Cons:**
- Requires GnuPG subprocess calls for OpenPGP Card decryption
- More complex implementation

## Implementation Details

### Key Identification

Instead of PEM keys, use key source type + identifier:

**OpenPGP Card:**
- **Keygrip:** Unique identifier for OpenPGP Card keys (recommended)
- **Key ID:** GnuPG key ID (shorter, less unique)
- **Fingerprint:** Full key fingerprint

**Kernel Keyring:**
- **Key ID:** Linux kernel keyring key ID (integer)

**Example:**
```cpp
// Old API (REMOVED)
brainpool_ecies_decrypt::make(
    curve="brainpoolP256r1",
    recipient_private_key_pem="-----BEGIN PRIVATE KEY-----...",
    private_key_password="",
    kdf_info="gr-linux-crypto-ecies-v1"
);

// New API - OpenPGP Card
brainpool_ecies_decrypt::make(
    curve="brainpoolP256r1",
    key_source="opgp_card",  // or "kernel_keyring"
    recipient_key_identifier="ABC123DEF456...",  // keygrip for OpenPGP Card
    kdf_info="gr-linux-crypto-ecies-v1"
);

// New API - Kernel Keyring
brainpool_ecies_decrypt::make(
    curve="brainpoolP256r1",
    key_source="kernel_keyring",
    recipient_key_identifier="12345",  // key_id for kernel keyring
    kdf_info="gr-linux-crypto-ecies-v1"
);
```

### Public Key Extraction

For encryption, extract public key from OpenPGP Card:

```cpp
// Use GnuPG to export public key
std::string extract_public_key_from_card(const std::string& keygrip) {
    // gpg --export --export-options export-minimal KEYGRIP
    // Convert exported key to OpenSSL EVP_PKEY
}
```

### Decryption with Hardware Keys

For decryption, use GnuPG to perform ECDH:

```cpp
// 1. Extract ephemeral public key from encrypted data
EVP_PKEY* ephemeral_pubkey = deserialize_ephemeral_public_key(...);

// 2. Use GnuPG to compute ECDH with card's private key
std::vector<uint8_t> shared_secret = gpg_ecdh_exchange(
    keygrip,           // Card key identifier
    ephemeral_pubkey   // Ephemeral public key
);

// 3. Continue with HKDF and AES-GCM (existing code)
```

### GnuPG Integration

The implementation uses a hybrid approach:

**With GPGME (Recommended):**
- Uses GPGME library for proper OpenPGP format parsing
- Converts OpenPGP keys to OpenSSL EVP_PKEY format
- Provides better error handling and key management
- Supports full OpenPGP Card operations

**Without GPGME (Fallback):**
- Uses GnuPG subprocess calls (similar to `M17SessionKeyExchange`)
- Basic OpenPGP format parser for key extraction
- Limited functionality but still functional

```cpp
class OpenPGPCardHelper {
    // Extract public key from card
    // Uses GPGME if available, otherwise GnuPG subprocess + basic parser
    static EVP_PKEY* get_public_key(const std::string& keygrip);
    
    // Perform ECDH with card's private key
    // Uses GPGME if available, otherwise returns empty (requires GPGME)
    static std::vector<uint8_t> ecdh_exchange(
        const std::string& keygrip,
        EVP_PKEY* other_public_key
    );
    
    // Check if card is available
    static bool is_card_available(const std::string& keygrip);
};
```

## API Changes

### Removed Parameters
- `recipient_public_key_pem` (encrypt)
- `recipient_private_key_pem` (decrypt)
- `private_key_password` (decrypt)
- `set_recipient_public_key()` (encrypt)
- `set_recipient_private_key()` (decrypt)

### New Parameters
- `recipient_keygrip` (encrypt/decrypt)
- `set_recipient_keygrip()` (encrypt/decrypt)
- `get_recipient_keygrip()` (encrypt/decrypt)
- `is_card_available()` (check card status)

## Migration Path

1. **Phase 1:** Add OpenPGP Card support alongside PEM (deprecated)
2. **Phase 2:** Remove PEM support, require OpenPGP Card
3. **Phase 3:** Update all examples and documentation

## Dependencies

### Required
- **GnuPG:** Required for OpenPGP Card access
- **GnuPG Agent:** Required for PIN handling
- **scdaemon:** Required for smart card communication
- **pcscd:** Required for PC/SC smart card interface

### Optional (Recommended)
- **GPGME (libgpgme-dev):** Recommended for full OpenPGP Card support
  - Provides proper OpenPGP format parsing and key conversion
  - Enables better integration with GnuPG and smart cards
  - Without GPGME, a basic OpenPGP format parser is used as fallback
  - Install: `sudo apt-get install libgpgme-dev`

## Testing

1. Generate keys on Nitrokey 3 OpenPGP Card
2. Extract keygrip: `gpg --list-secret-keys --keyid-format=long --with-keygrip`
3. Test encryption with extracted public key
4. Test decryption with card's private key
5. Verify keys never leave Secure Element

## Security Benefits

1. **Hardware Protection:** Keys stored in tamper-resistant Secure Element
2. **No Key Extraction:** Private keys cannot be extracted
3. **PIN Protection:** Operations require PIN authentication
4. **Physical Security:** Device removal clears operations

## Limitations

1. **Requires GnuPG:** Must have GnuPG installed and configured
2. **PIN Entry:** Requires pinentry program for PIN input
3. **Performance:** Subprocess calls add latency (GPGME reduces this)
4. **Card Presence:** Card must be physically present
5. **GPGME for ECDH:** Full ECDH support with hardware-protected keys requires GPGME
   - Without GPGME, ECDH operations may not work with OpenPGP Card keys
   - GPGME provides proper access to card's private key for ECDH
6. **OpenPGP Format Parsing:** Without GPGME, basic parser supports limited key types
   - Full support requires GPGME for proper RFC 4880 compliance

