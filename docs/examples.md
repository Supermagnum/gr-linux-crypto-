# GNU Radio Linux Crypto Examples

This document provides comprehensive examples for using the GNU Radio Linux Crypto module.

## Table of Contents

1. [Basic AES Encryption](#basic-aes-encryption)
2. [Kernel Keyring Integration](#kernel-keyring-integration)
3. [Hardware Security Module Usage](#hardware-security-module-usage)
4. [Complete Crypto Flow](#complete-crypto-flow)
5. [Advanced Usage Patterns](#advanced-usage-patterns)
6. [Brainpool ECIES Encryption](#brainpool-ecies-encryption)
7. [Multi-Recipient ECIES](#multi-recipient-ecies)

## Basic AES Encryption

### Simple Encryption/Decryption

```python
#!/usr/bin/env python3
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def basic_aes_example():
    """Basic AES encryption example."""
    crypto = CryptoHelpers()
    
    # Generate random key and IV
    key = crypto.generate_random_key(32)  # 256-bit key
    iv = crypto.generate_random_iv(16)    # 128-bit IV
    
    # Encrypt data
    data = b"Hello, GNU Radio Crypto!"
    encrypted = crypto.aes_encrypt(data, key, iv, 'cbc')
    
    # Decrypt data
    decrypted = crypto.aes_decrypt(encrypted, key, iv, 'cbc')
    
    print(f"Original: {data}")
    print(f"Decrypted: {decrypted}")
    print(f"Success: {data == decrypted}")

if __name__ == "__main__":
    basic_aes_example()
```

### GNU Radio Flowgraph Example

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks
from gnuradio import linux_crypto

def gr_aes_flowgraph():
    """GNU Radio AES encryption flowgraph using kernel crypto API."""
    tb = gr.top_block()
    
    # Create signal source
    src_data = [1, 2, 3, 4, 5] * 1000
    src = blocks.vector_source_b(src_data)
    
    # Use kernel_crypto_aes block instead (which is built and available)
    key = [0x01] * 32  # 256-bit key
    iv = [0x02] * 16   # 128-bit IV
    aes_encrypt = linux_crypto.kernel_crypto_aes(key, iv, "cbc", True)
    
    # Create sink
    sink = blocks.vector_sink_b()
    
    # Connect blocks
    tb.connect(src, aes_encrypt, sink)
    
    # Run flowgraph
    tb.run()
    
    print(f"Processed {len(sink.data())} samples")

if __name__ == "__main__":
    gr_aes_flowgraph()
```

## Kernel Keyring Integration

### Adding and Reading Keys

```python
#!/usr/bin/env python3
from gr_linux_crypto.keyring_helper import KeyringHelper

def keyring_example():
    """Kernel keyring integration example."""
    helper = KeyringHelper()
    
    # Add a key to the keyring
    key_data = b"secret_key_data"
    key_id = helper.add_key('user', 'gr_crypto_key', key_data)
    print(f"Added key with ID: {key_id}")
    
    # Read the key back
    retrieved_data = helper.read_key(key_id)
    print(f"Retrieved data: {retrieved_data}")
    
    # List all keys
    keys = helper.list_keys()
    for key in keys:
        print(f"Key: {key['id']} - {key['description']}")
    
    # Clean up
    helper.revoke_key(key_id)

if __name__ == "__main__":
    keyring_example()
```

### GNU Radio Keyring Source

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks
from gnuradio import linux_crypto

def gr_keyring_flowgraph():
    """GNU Radio keyring source flowgraph."""
    tb = gr.top_block()
    
    # Create keyring source
    keyring_src = linux_crypto.kernel_keyring_source(key_id=12345, auto_repeat=True)
    
    # Create sink
    sink = blocks.vector_sink_b()
    
    # Connect blocks
    tb.connect(keyring_src, sink)
    
    # Run flowgraph
    tb.run()
    
    print(f"Key data: {sink.data()}")

if __name__ == "__main__":
    gr_keyring_flowgraph()
```

## Hardware Security Module Usage

### Nitrokey Integration

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks
from gnuradio import linux_crypto

def nitrokey_example():
    """Nitrokey hardware security module example."""
    # Create Nitrokey interface
    nitrokey = linux_crypto.nitrokey_interface(auto_repeat=False)
    
    # Check if device is connected
    if nitrokey.is_device_connected():
        print("Nitrokey device connected")
        
        # Load key from slot
        if nitrokey.load_key_from_slot(1):
            print("Key loaded from Nitrokey slot 1")
        
        # Create GNU Radio flowgraph
        tb = gr.top_block()
        sink = blocks.vector_sink_b()
        tb.connect(nitrokey, sink)
        tb.run()
        
        print(f"Hardware key data: {sink.data()}")
    else:
        print("No Nitrokey device found")

if __name__ == "__main__":
    nitrokey_example()
```

## Complete Crypto Flow

### End-to-End Encryption Pipeline

```python
#!/usr/bin/env python3
import numpy as np
from gnuradio import gr, blocks
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def complete_crypto_pipeline():
    """Complete cryptographic pipeline example."""
    crypto = CryptoHelpers()
    
    # Generate materials
    key = crypto.generate_random_key(32)
    iv = crypto.generate_random_iv(16)
    
    # Create test message
    message = "GNU Radio Linux Crypto - Secure Communication"
    message_bytes = message.encode('utf-8')
    
    # Pad message
    padded_message = crypto.pad_pkcs7(message_bytes, 16)
    message_array = np.frombuffer(padded_message, dtype=np.uint8)
    
    # Create GNU Radio flowgraph
    tb = gr.top_block()
    
    # Source
    src = blocks.vector_source_b(message_array.tolist())
    
    # Encryption sink
    encrypt_sink = blocks.vector_sink_b()
    
    # Connect and run encryption
    tb.connect(src, encrypt_sink)
    tb.run()
    
    # Get encrypted data
    encrypted_data = np.array(encrypt_sink.data(), dtype=np.uint8)
    
    # Decrypt using crypto helpers
    decrypted_data = crypto.aes_decrypt(encrypted_data.tobytes(), key, iv, 'cbc')
    unpadded_data = crypto.unpad_pkcs7(decrypted_data)
    
    print(f"Original: {message}")
    print(f"Decrypted: {unpadded_data.decode('utf-8')}")
    print(f"Success: {message == unpadded_data.decode('utf-8')}")

if __name__ == "__main__":
    complete_crypto_pipeline()
```

## Advanced Usage Patterns

### Key Derivation and Management

#### Password-Based Key Derivation (PBKDF2)

```python
#!/usr/bin/env python3
from gr_linux_crypto.crypto_helpers import CryptoHelpers
from gr_linux_crypto.keyring_helper import KeyringHelper

def advanced_key_management():
    """Advanced key management example with PBKDF2."""
    crypto = CryptoHelpers()
    helper = KeyringHelper()
    
    # Derive key from password using PBKDF2
    password = b"my_secret_password"
    salt = crypto.generate_random_iv(16)
    derived_key = crypto.derive_key_from_password(password, salt, length=32, iterations=100000)
    
    # Store derived key in keyring
    key_id = helper.add_key('user', 'derived_key', derived_key)
    
    # Create HMAC
    data = b"Important message"
    hmac_sig = crypto.hmac_sign(data, derived_key)
    
    print(f"Derived key: {crypto.bytes_to_hex(derived_key)}")
    print(f"HMAC: {crypto.bytes_to_hex(hmac_sig)}")
    print(f"Key stored with ID: {key_id}")

if __name__ == "__main__":
    advanced_key_management()
```

#### HKDF Key Derivation (for Shared Secrets)

```python
#!/usr/bin/env python3
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def hkdf_ecdh_example():
    """HKDF key derivation from ECDH shared secret."""
    crypto = CryptoHelpers()
    
    # Generate key pairs for Alice and Bob
    alice_private, alice_public = crypto.generate_brainpool_keypair('brainpoolP256r1')
    bob_private, bob_public = crypto.generate_brainpool_keypair('brainpoolP256r1')
    
    # Both parties compute shared secret via ECDH
    alice_shared_secret = crypto.brainpool_ecdh(alice_private, bob_public)
    bob_shared_secret = crypto.brainpool_ecdh(bob_private, alice_public)
    
    # Shared secrets are identical
    assert alice_shared_secret == bob_shared_secret
    
    # Derive encryption keys using HKDF (RFC 5869)
    # HKDF is designed for key derivation from shared secrets
    salt = crypto.generate_random_key(16)  # Can be random or application-specific
    info = b'gnuradio-encryption-v1'  # Context/application-specific information
    
    # Alice derives encryption key
    alice_encryption_key = crypto.derive_key_hkdf(
        alice_shared_secret,
        salt=salt,
        info=info,
        length=32,  # 256-bit key for AES-256
        algorithm='sha256'
    )
    
    # Bob derives the same encryption key (must use same salt and info)
    bob_encryption_key = crypto.derive_key_hkdf(
        bob_shared_secret,
        salt=salt,
        info=info,
        length=32,
        algorithm='sha256'
    )
    
    # Keys are identical
    assert alice_encryption_key == bob_encryption_key
    
    print(f"Shared secret: {crypto.bytes_to_hex(alice_shared_secret)}")
    print(f"Derived encryption key: {crypto.bytes_to_hex(alice_encryption_key)}")
    
    # Now both parties can use the encryption key for AES encryption
    iv = crypto.generate_random_iv(16)
    message = b"Secret message encrypted with ECDH+HKDF derived key"
    encrypted = crypto.aes_encrypt(message, alice_encryption_key, iv, 'cbc')
    decrypted = crypto.aes_decrypt(encrypted, bob_encryption_key, iv, 'cbc')
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Encryption successful: {message == decrypted}")

def hkdf_advanced_example():
    """Advanced HKDF usage with multiple algorithms."""
    crypto = CryptoHelpers()
    
    # Input key material (IKM) - typically from ECDH or other key exchange
    ikm = crypto.generate_random_key(32)
    
    # HKDF with SHA256
    key_sha256 = crypto.derive_key_hkdf(ikm, length=32, algorithm='sha256')
    
    # HKDF with SHA384
    key_sha384 = crypto.derive_key_hkdf(ikm, length=48, algorithm='sha384')
    
    # HKDF with SHA512
    key_sha512 = crypto.derive_key_hkdf(ikm, length=64, algorithm='sha512')
    
    # HKDF with context information (info parameter)
    salt = b'application_salt'
    info_auth = b'encryption-key'
    info_signing = b'signing-key'
    
    encryption_key = crypto.derive_key_hkdf(ikm, salt=salt, info=info_auth, length=32)
    signing_key = crypto.derive_key_hkdf(ikm, salt=salt, info=info_signing, length=32)
    
    # Different info values produce different keys
    assert encryption_key != signing_key
    
    print(f"SHA256 key: {crypto.bytes_to_hex(key_sha256)}")
    print(f"SHA384 key: {crypto.bytes_to_hex(key_sha384)}")
    print(f"SHA512 key: {crypto.bytes_to_hex(key_sha512)}")
    print(f"Encryption key: {crypto.bytes_to_hex(encryption_key)}")
    print(f"Signing key: {crypto.bytes_to_hex(signing_key)}")

if __name__ == "__main__":
    print("=== HKDF with ECDH ===")
    hkdf_ecdh_example()
    print("\n=== Advanced HKDF ===")
    hkdf_advanced_example()
```

### Authenticated Encryption with Additional Data (AAD)

```python
#!/usr/bin/env python3
"""AES-GCM and ChaCha20-Poly1305 with AAD (Additional Authenticated Data) support."""

from gr_linux_crypto.linux_crypto import encrypt, decrypt

def aes_gcm_with_aad_example():
    """AES-GCM encryption with AAD support."""
    key = b'0' * 32  # 256-bit key for AES-256
    iv = b'0' * 12   # 96-bit IV for GCM
    plaintext = b"Secret message content"
    aad = b"Message metadata that should be authenticated but not encrypted"
    
    # Encrypt with AAD
    ciphertext, iv_out, auth_tag = encrypt(
        'aes-256',
        key,
        plaintext,
        iv_mode=iv,
        auth='gcm',
        aad=aad  # Additional Authenticated Data
    )
    
    print(f"Plaintext: {plaintext}")
    print(f"AAD: {aad}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Auth Tag: {auth_tag.hex()}")
    
    # Decrypt with same AAD
    decrypted = decrypt(
        'aes-256',
        key,
        ciphertext,
        iv_out,
        auth='gcm',
        auth_tag=auth_tag,
        aad=aad  # Must match encryption AAD
    )
    
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == plaintext}")
    
    # Attempting to decrypt with wrong AAD will fail
    wrong_aad = b"Different metadata"
    try:
        decrypt(
            'aes-256',
            key,
            ciphertext,
            iv_out,
            auth='gcm',
            auth_tag=auth_tag,
            aad=wrong_aad  # Wrong AAD - will raise ValueError
        )
        print("ERROR: Decryption should have failed with wrong AAD!")
    except ValueError as e:
        print(f"Correctly rejected wrong AAD: {e}")

def chacha20_poly1305_with_aad_example():
    """ChaCha20-Poly1305 encryption with AAD support."""
    key = b'0' * 32  # 256-bit key for ChaCha20
    nonce = b'0' * 12  # 96-bit nonce
    plaintext = b"Message to encrypt"
    aad = b"Header information (authenticated but not encrypted)"
    
    # Encrypt with AAD
    ciphertext, nonce_out, auth_tag = encrypt(
        'chacha20',
        key,
        plaintext,
        iv_mode=nonce,
        auth='poly1305',
        aad=aad
    )
    
    # Decrypt with same AAD
    decrypted = decrypt(
        'chacha20',
        key,
        ciphertext,
        nonce_out,
        auth='poly1305',
        auth_tag=auth_tag,
        aad=aad
    )
    
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")

def aad_use_cases():
    """Common use cases for AAD in AEAD encryption."""
    
    # Use case 1: Encrypting message with metadata
    message = b"Sensitive payload data"
    metadata = b"From: alice@example.com\nTo: bob@example.com\nSubject: Encrypted"
    
    key = b'0' * 32
    iv = b'0' * 12
    
    # Encrypt payload, authenticate metadata
    ciphertext, iv_out, tag = encrypt(
        'aes-256',
        key,
        message,
        iv_mode=iv,
        auth='gcm',
        aad=metadata
    )
    
    # Metadata is authenticated but not encrypted (more efficient)
    # Changing metadata will be detected during decryption
    
    # Use case 2: Encrypting with protocol headers
    protocol_header = b"M17_PROTOCOL_V1\nCALLSIGN: KA1ABC\nTIMESTAMP: 2025-11-02"
    payload = b"Actual radio transmission data"
    
    ciphertext2, iv2, tag2 = encrypt(
        'aes-256',
        key,
        payload,
        iv_mode=iv,
        auth='gcm',
        aad=protocol_header
    )
    
    print("Use cases demonstrated:")
    print("1. Message encryption with authenticated metadata")
    print("2. Protocol header authentication")

if __name__ == "__main__":
    print("=== AES-GCM with AAD ===")
    aes_gcm_with_aad_example()
    print("\n=== ChaCha20-Poly1305 with AAD ===")
    chacha20_poly1305_with_aad_example()
    print("\n=== AAD Use Cases ===")
    aad_use_cases()
```

### Multi-Algorithm Support

```python
#!/usr/bin/env python3
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def multi_algorithm_example():
    """Multi-algorithm cryptographic operations."""
    crypto = CryptoHelpers()
    
    data = b"Test data for multiple algorithms"
    
    # Hash with different algorithms
    sha1_hash = crypto.hash_data(data, 'sha1')
    sha256_hash = crypto.hash_data(data, 'sha256')
    sha512_hash = crypto.hash_data(data, 'sha512')
    
    print(f"SHA1: {crypto.bytes_to_hex(sha1_hash)}")
    print(f"SHA256: {crypto.bytes_to_hex(sha256_hash)}")
    print(f"SHA512: {crypto.bytes_to_hex(sha512_hash)}")
    
    # AES with different modes
    key = crypto.generate_random_key(32)
    iv = crypto.generate_random_iv(16)
    
    cbc_encrypted = crypto.aes_encrypt(data, key, iv, 'cbc')
    ecb_encrypted = crypto.aes_encrypt(data, key, b'', 'ecb')
    
    print(f"CBC encrypted: {crypto.bytes_to_hex(cbc_encrypted)}")
    print(f"ECB encrypted: {crypto.bytes_to_hex(ecb_encrypted)}")

if __name__ == "__main__":
    multi_algorithm_example()
```

## Performance Considerations

### Benchmarking Crypto Operations

```python
#!/usr/bin/env python3
import time
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def benchmark_crypto():
    """Benchmark cryptographic operations."""
    crypto = CryptoHelpers()
    
    # Test data
    data = b"X" * 1024 * 1024  # 1MB of data
    key = crypto.generate_random_key(32)
    iv = crypto.generate_random_iv(16)
    
    # Benchmark AES encryption
    start_time = time.time()
    encrypted = crypto.aes_encrypt(data, key, iv, 'cbc')
    encryption_time = time.time() - start_time
    
    # Benchmark AES decryption
    start_time = time.time()
    decrypted = crypto.aes_decrypt(encrypted, key, iv, 'cbc')
    decryption_time = time.time() - start_time
    
    print(f"Encryption time: {encryption_time:.3f} seconds")
    print(f"Decryption time: {decryption_time:.3f} seconds")
    print(f"Throughput: {len(data) / encryption_time / 1024 / 1024:.2f} MB/s")

if __name__ == "__main__":
    benchmark_crypto()
```

## Error Handling

### Robust Error Handling

```python
#!/usr/bin/env python3
from gr_linux_crypto.keyring_helper import KeyringHelper
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def error_handling_example():
    """Error handling example."""
    try:
        # Initialize helpers
        helper = KeyringHelper()
        crypto = CryptoHelpers()
        
        # Try to read non-existent key
        try:
            key_data = helper.read_key("999999")
            print(f"Key data: {key_data}")
        except RuntimeError as e:
            print(f"Key not found: {e}")
        
        # Try invalid crypto operation
        try:
            invalid_key = b"short"  # Too short for AES
            crypto.aes_encrypt(b"test", invalid_key, b"iv", 'cbc')
        except Exception as e:
            print(f"Crypto error: {e}")
            
    except Exception as e:
        print(f"Initialization error: {e}")

if __name__ == "__main__":
    error_handling_example()
```

## Brainpool ECIES Encryption

ECIES (Elliptic Curve Integrated Encryption Scheme) provides authenticated encryption using Brainpool elliptic curves. This section demonstrates both single-recipient and multi-recipient encryption.

ECIES supports two symmetric ciphers for bulk payload encryption:
- **AES-256-GCM**: Recommended when hardware acceleration (AES-NI) is available
- **ChaCha20-Poly1305**: Recommended for battery-powered devices and software-only implementations

### Single-Recipient ECIES

```python
#!/usr/bin/env python3
from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
from gr_linux_crypto.callsign_key_store import CallsignKeyStore
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def single_recipient_ecies_example():
    """Single-recipient ECIES encryption example."""
    crypto = CryptoHelpers()
    key_store = CallsignKeyStore()
    
    # Generate key pair for recipient
    recipient_callsign = "W1ABC"
    recipient_private, recipient_public = crypto.generate_brainpool_keypair('brainpoolP256r1')
    public_key_pem = crypto.serialize_brainpool_public_key(recipient_public)
    private_key_pem = crypto.serialize_brainpool_private_key(recipient_private)
    
    # Add recipient's public key to store
    key_store.add_public_key(recipient_callsign, public_key_pem.decode('ascii'))
    
    # Create ECIES instance (defaults to AES-GCM)
    ecies = MultiRecipientECIES(curve='brainpoolP256r1', symmetric_cipher='aes-gcm')
    
    # Encrypt message
    plaintext = b"Secret message for single recipient"
    encrypted = ecies.encrypt(plaintext, [recipient_callsign])
    
    print(f"Plaintext: {plaintext}")
    print(f"Encrypted length: {len(encrypted)} bytes")
    
    # Decrypt message
    decrypted = ecies.decrypt(encrypted, recipient_callsign, private_key_pem.decode('ascii'))
    
    print(f"Decrypted: {decrypted}")
    print(f"Success: {plaintext == decrypted}")

if __name__ == "__main__":
    single_recipient_ecies_example()
```

### ECIES Blocks with Secure Key Sources

The C++ ECIES blocks (`brainpool_ecies_encrypt`, `brainpool_ecies_decrypt`, `brainpool_ecies_multi_encrypt`, `brainpool_ecies_multi_decrypt`) now support secure key sources instead of PEM keys. This ensures keys are stored securely and never in plain PEM format in user space.

### Supported Key Sources

1. **OpenPGP Card** (`key_source='opgp_card'`):
   - Hardware-protected, non-extractable keys
   - Maximum security - private keys never leave the Secure Element
   - Requires GnuPG and optionally GPGME for full support
   - Key identifier: keygrip (recommended) or key ID

2. **Kernel Keyring** (`key_source='kernel_keyring'`):
   - Linux kernel-protected keys
   - High security, extractable but secure
   - Key identifier: kernel keyring key ID (integer)

### OpenPGP Card Example

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks, linux_crypto

def opgp_card_ecies_example():
    """ECIES encryption using OpenPGP Card."""
    tb = gr.top_block()
    
    # Get keygrip from GnuPG
    # Run: gpg --list-secret-keys --keyid-format=long --with-keygrip
    keygrip = "ABC123DEF4567890ABCDEF1234567890ABCDEF12"
    
    # Create encrypt block with OpenPGP Card key
    encrypt_block = linux_crypto.brainpool_ecies_encrypt(
        curve='brainpoolP256r1',
        key_source='opgp_card',
        recipient_key_identifier=keygrip,
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create decrypt block with OpenPGP Card key
    decrypt_block = linux_crypto.brainpool_ecies_decrypt(
        curve='brainpoolP256r1',
        key_source='opgp_card',
        recipient_key_identifier=keygrip,
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create source and sink
    src = blocks.vector_source_b(b"Secret message")
    sink = blocks.vector_sink_b()
    
    # Connect: source -> encrypt -> decrypt -> sink
    tb.connect(src, encrypt_block, decrypt_block, sink)
    tb.run()
    
    print(f"Decrypted: {bytes(sink.data())}")

if __name__ == "__main__":
    opgp_card_ecies_example()
```

### Kernel Keyring Example

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks, linux_crypto
from gr_linux_crypto.keyring_helper import KeyringHelper

def kernel_keyring_ecies_example():
    """ECIES encryption using kernel keyring."""
    tb = gr.top_block()
    
    # Store private key in kernel keyring
    helper = KeyringHelper()
    private_key_pem = b"-----BEGIN PRIVATE KEY-----\n..."
    key_id = helper.add_key('user', 'ecies_private_key', private_key_pem)
    
    # Create encrypt block with kernel keyring key
    encrypt_block = linux_crypto.brainpool_ecies_encrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',
        recipient_key_identifier=str(key_id),
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create decrypt block with kernel keyring key
    decrypt_block = linux_crypto.brainpool_ecies_decrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',
        recipient_key_identifier=str(key_id),
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create source and sink
    src = blocks.vector_source_b(b"Secret message")
    sink = blocks.vector_sink_b()
    
    # Connect: source -> encrypt -> decrypt -> sink
    tb.connect(src, encrypt_block, decrypt_block, sink)
    tb.run()
    
    print(f"Decrypted: {bytes(sink.data())}")

if __name__ == "__main__":
    kernel_keyring_ecies_example()
```

### Getting OpenPGP Card Keygrip

To use OpenPGP Card keys, you need to get the keygrip:

```bash
# List keys with keygrips
gpg --list-secret-keys --keyid-format=long --with-keygrip

# Example output:
# sec   brainpoolP256r1/ABC123DEF4567890 2024-01-15 [SC]
#       Keygrip = ABC123DEF4567890ABCDEF1234567890ABCDEF12
# uid           [ultimate] Your Name <your@email.com>
```

The keygrip is the unique identifier for the key on the OpenPGP Card.

### ECIES Blocks with Key Input Ports

All ECIES blocks support **optional key input ports** that allow dynamic key input from hardware sources like `nitrokey_interface` or `kernel_keyring_source` blocks. This enables flexible key management in GNU Radio flowgraphs.

#### Using Nitrokey Interface with ECIES

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks, linux_crypto

def nitrokey_ecies_example():
    """ECIES encryption using Nitrokey interface block."""
    tb = gr.top_block()
    
    # Create Nitrokey interface block (reads key from slot 0)
    nitrokey = linux_crypto.nitrokey_interface(slot=0, auto_repeat=False)
    
    # Create encrypt block with key input port
    encrypt_block = linux_crypto.brainpool_ecies_encrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',  # Fallback if key input not available
        recipient_key_identifier='',
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create decrypt block with key input port
    decrypt_block = linux_crypto.brainpool_ecies_decrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',  # Fallback if key input not available
        recipient_key_identifier='',
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create source and sink
    src = blocks.vector_source_b(b"Secret message")
    sink = blocks.vector_sink_b()
    
    # Connect: source -> encrypt
    # Connect: nitrokey -> encrypt (key input port 1)
    tb.connect(src, (encrypt_block, 0))
    tb.connect(nitrokey, (encrypt_block, 1))  # Key input port
    
    # Connect: encrypt -> decrypt
    # Connect: nitrokey -> decrypt (key input port 1)
    tb.connect(encrypt_block, (decrypt_block, 0))
    tb.connect(nitrokey, (decrypt_block, 1))  # Key input port
    
    # Connect: decrypt -> sink
    tb.connect(decrypt_block, sink)
    
    tb.run()
    
    print(f"Decrypted: {bytes(sink.data())}")

if __name__ == "__main__":
    nitrokey_ecies_example()
```

#### Using Kernel Keyring Source with ECIES

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks, linux_crypto
from gr_linux_crypto.keyring_helper import KeyringHelper

def kernel_keyring_source_ecies_example():
    """ECIES encryption using kernel keyring source block."""
    tb = gr.top_block()
    
    # Store key in kernel keyring
    helper = KeyringHelper()
    private_key_pem = b"-----BEGIN PRIVATE KEY-----\n..."
    key_id = helper.add_key('user', 'ecies_key', private_key_pem)
    
    # Create kernel keyring source block
    keyring_src = linux_crypto.kernel_keyring_source(key_id=key_id, auto_repeat=False)
    
    # Create encrypt block with key input port
    encrypt_block = linux_crypto.brainpool_ecies_encrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',
        recipient_key_identifier=str(key_id),
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create decrypt block with key input port
    decrypt_block = linux_crypto.brainpool_ecies_decrypt(
        curve='brainpoolP256r1',
        key_source='kernel_keyring',
        recipient_key_identifier=str(key_id),
        kdf_info='gr-linux-crypto-ecies-v1'
    )
    
    # Create source and sink
    src = blocks.vector_source_b(b"Secret message")
    sink = blocks.vector_sink_b()
    
    # Connect: source -> encrypt
    # Connect: keyring_src -> encrypt (key input port 1)
    tb.connect(src, (encrypt_block, 0))
    tb.connect(keyring_src, (encrypt_block, 1))  # Key input port
    
    # Connect: encrypt -> decrypt
    # Connect: keyring_src -> decrypt (key input port 1)
    tb.connect(encrypt_block, (decrypt_block, 0))
    tb.connect(keyring_src, (decrypt_block, 1))  # Key input port
    
    # Connect: decrypt -> sink
    tb.connect(decrypt_block, sink)
    
    tb.run()
    
    print(f"Decrypted: {bytes(sink.data())}")

if __name__ == "__main__":
    kernel_keyring_source_ecies_example()
```

#### Multi-Recipient ECIES with Key Input

```python
#!/usr/bin/env python3
from gnuradio import gr, blocks, linux_crypto

def multi_recipient_key_input_example():
    """Multi-recipient ECIES with key input from Nitrokey."""
    tb = gr.top_block()
    
    # Create Nitrokey interface block
    nitrokey = linux_crypto.nitrokey_interface(slot=0, auto_repeat=False)
    
    # Create multi-encrypt block with key input port
    encrypt_block = linux_crypto.brainpool_ecies_multi_encrypt(
        curve='brainpoolP256r1',
        callsigns=['W1ABC', 'K2XYZ'],
        key_store_path='',
        kdf_info='gr-linux-crypto-ecies-v1',
        symmetric_cipher='aes-gcm'
    )
    
    # Create source and sink
    src = blocks.vector_source_b(b"Message for multiple recipients")
    sink = blocks.vector_sink_b()
    
    # Connect: source -> encrypt
    # Connect: nitrokey -> encrypt (key input port 1)
    tb.connect(src, (encrypt_block, 0))
    tb.connect(nitrokey, (encrypt_block, 1))  # Key input port
    
    # Connect: encrypt -> sink
    tb.connect(encrypt_block, sink)
    
    tb.run()
    
    print(f"Encrypted length: {len(sink.data())} bytes")

if __name__ == "__main__":
    multi_recipient_key_input_example()
```

**Notes:**
- Key input ports are **optional** - blocks work without them using secure key sources
- Keys from input ports take precedence over secure key sources
- PEM keys are automatically detected by looking for `-----BEGIN` and `-----END` markers
- For multi-recipient encrypt, the key from input port is associated with the first callsign in the recipient list
- Maximum key buffer size is 4096 bytes

### Dependencies

**Required:**
- GnuPG (for OpenPGP Card access)
- GnuPG Agent (for PIN handling)
- scdaemon (for smart card communication)
- pcscd (for PC/SC smart card interface)

**Optional (Recommended):**
- GPGME (libgpgme-dev) - Recommended for full OpenPGP Card support
  - Provides proper OpenPGP format parsing and key conversion
  - Enables better integration with GnuPG and smart cards
  - Without GPGME, a basic OpenPGP format parser is used as fallback
  - Install: `sudo apt-get install libgpgme-dev`

### Security Benefits

1. **Hardware Protection**: OpenPGP Card keys stored in tamper-resistant Secure Element
2. **No Key Extraction**: Private keys cannot be extracted from OpenPGP Card
3. **PIN Protection**: Operations require PIN authentication
4. **Physical Security**: Device removal clears operations
5. **Kernel Protection**: Kernel keyring keys are kernel-protected

## Multi-Recipient ECIES

Multi-recipient ECIES allows encrypting a message for up to 25 recipients. Each recipient receives an encrypted copy of the symmetric key, while the payload is encrypted once.

```python
#!/usr/bin/env python3
from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
from gr_linux_crypto.callsign_key_store import CallsignKeyStore
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def multi_recipient_ecies_example():
    """Multi-recipient ECIES encryption example."""
    crypto = CryptoHelpers()
    key_store = CallsignKeyStore()
    
    # Generate key pairs for multiple recipients
    recipients = ['W1ABC', 'K2XYZ', 'N3DEF', 'W4GHI']
    recipient_keypairs = {}
    
    for callsign in recipients:
        private_key, public_key = crypto.generate_brainpool_keypair('brainpoolP256r1')
        public_key_pem = crypto.serialize_brainpool_public_key(public_key)
        private_key_pem = crypto.serialize_brainpool_private_key(private_key)
        
        key_store.add_public_key(callsign, public_key_pem.decode('ascii'))
        recipient_keypairs[callsign] = private_key_pem.decode('ascii')
    
    # Create ECIES instance (defaults to AES-GCM)
    ecies = MultiRecipientECIES(curve='brainpoolP256r1', symmetric_cipher='aes-gcm')
    
    # Encrypt message for all recipients
    plaintext = b"Message for multiple recipients"
    encrypted = ecies.encrypt(plaintext, recipients)
    
    print(f"Plaintext: {plaintext}")
    print(f"Recipients: {recipients}")
    print(f"Encrypted length: {len(encrypted)} bytes")
    
    # Each recipient can decrypt using their private key
    for callsign in recipients:
        decrypted = ecies.decrypt(encrypted, callsign, recipient_keypairs[callsign])
        print(f"{callsign} decrypted: {decrypted}")
        assert plaintext == decrypted, f"Decryption failed for {callsign}"
    
    print("All recipients successfully decrypted the message!")

if __name__ == "__main__":
    multi_recipient_ecies_example()
```

### Callsign Key Store Management

```python
#!/usr/bin/env python3
from gr_linux_crypto.callsign_key_store import CallsignKeyStore
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def callsign_key_store_example():
    """Example of managing callsign-based key store."""
    crypto = CryptoHelpers()
    key_store = CallsignKeyStore()
    
    # Add public keys for multiple callsigns
    callsigns = ['W1ABC', 'K2XYZ', 'N3DEF']
    
    for callsign in callsigns:
        _, public_key = crypto.generate_brainpool_keypair('brainpoolP256r1')
        public_key_pem = crypto.serialize_brainpool_public_key(public_key)
        key_store.add_public_key(callsign, public_key_pem.decode('ascii'))
    
    # List all callsigns in store
    stored_callsigns = key_store.list_callsigns()
    print(f"Stored callsigns: {stored_callsigns}")
    
    # Retrieve a public key
    public_key_pem = key_store.get_public_key('W1ABC')
    if public_key_pem:
        print(f"Found public key for W1ABC")
    
    # Check if callsign exists
    if key_store.has_callsign('K2XYZ'):
        print("K2XYZ is in the key store")
    
    # Remove a callsign
    key_store.remove_public_key('N3DEF')
    print("Removed N3DEF from key store")

if __name__ == "__main__":
    callsign_key_store_example()
```

### ChaCha20-Poly1305 Cipher Support

For battery-powered devices or software-only implementations, ChaCha20-Poly1305 provides excellent performance without requiring hardware acceleration:

```python
#!/usr/bin/env python3
from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
from gr_linux_crypto.callsign_key_store import CallsignKeyStore
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def chacha20_poly1305_ecies_example():
    """ECIES encryption using ChaCha20-Poly1305 cipher."""
    crypto = CryptoHelpers()
    key_store = CallsignKeyStore()
    
    # Generate key pair for recipient
    recipient_callsign = "W1ABC"
    recipient_private, recipient_public = crypto.generate_brainpool_keypair('brainpoolP256r1')
    public_key_pem = crypto.serialize_brainpool_public_key(recipient_public)
    private_key_pem = crypto.serialize_brainpool_private_key(recipient_private)
    
    # Add recipient's public key to store
    key_store.add_public_key(recipient_callsign, public_key_pem.decode('ascii'))
    
    # Create ECIES instance with ChaCha20-Poly1305
    ecies = MultiRecipientECIES(
        curve='brainpoolP256r1',
        symmetric_cipher='chacha20-poly1305'
    )
    
    # Encrypt message
    plaintext = b"Message encrypted with ChaCha20-Poly1305"
    encrypted = ecies.encrypt(plaintext, [recipient_callsign])
    
    print(f"Plaintext: {plaintext}")
    print(f"Encrypted length: {len(encrypted)} bytes")
    print(f"Cipher: ChaCha20-Poly1305")
    
    # Decrypt message (automatically detects cipher from header)
    decrypted = ecies.decrypt(encrypted, recipient_callsign, private_key_pem.decode('ascii'))
    
    print(f"Decrypted: {decrypted}")
    print(f"Success: {plaintext == decrypted}")

if __name__ == "__main__":
    chacha20_poly1305_ecies_example()
```

**Format Documentation:** The complete multi-recipient ECIES format specification is available in `docs/multi_recipient_ecies_format.md`.

## Best Practices

1. **Key Management**: Always use secure random number generation for keys
2. **Error Handling**: Implement proper exception handling for crypto operations
3. **Memory Management**: Clear sensitive data from memory when done
4. **Performance**: Use appropriate algorithms for your use case
5. **Security**: Follow cryptographic best practices and standards
