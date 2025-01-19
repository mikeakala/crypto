# crypto

## Overview

This is a lightweight C library that provides a secure wrapper around cryptographic operations, focusing on key exchange, hashing, and password hashing. It leverages the power of libsodium[https://doc.libsodium.org/] to offer a simple, yet robust API for common cryptographic tasks.

## Features

- Asymmetric key pair generation
- Client session key derivation
- SHA-256 and SHA-512 hashing
- Secure password hashing

## Prerequisites
- Install libsodium (e.g., via Homebrew on macOS: `brew install libsodium`).


## API Reference

### Key Exchange

- `int create_asymmetric_keypair(unsigned char *public_key, unsigned char *secret_key)`
- `int derive_client_session_keys(unsigned char *receive_key, unsigned char *transmit_key, const unsigned char *client_public_key, const unsigned char *client_secret_key, const unsigned char *server_public_key)`

### Hashing

- `int compute_sha256_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length)`
- `int compute_sha512_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length)`

### Password Hashing

- `int secure_password_hash(char *hashed_password, unsigned long hashed_password_length, const char *password, unsigned long password_length)`

For detailed function descriptions, please refer to the comments in the `secure_kx_hash_lib.h` header file.


## Security Considerations

This library uses well-established cryptographic primitives from libsodium. However, proper use of cryptographic functions requires careful consideration of your specific security requirements. Always ensure you're using the latest versions of libsodium, and consider consulting with a security expert for critical applications.

## 📝 License

This project is licensed under the MIT License.

