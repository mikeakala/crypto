// secure_kx_hash_lib.h
#ifndef SECURE_KX_HASH_LIB_H
#define SECURE_KX_HASH_LIB_H

#include <sodium.h>

// Error codes
#define SKHLIB_SUCCESS 0
#define SKHLIB_ERROR -1

// Key exchange API
/**
 * @brief Generate an asymmetric key pair for key exchange.
 * 
 * @param[out] public_key Buffer to store the generated public key.
 * @param[out] secret_key Buffer to store the generated secret key.
 * @return int SKHLIB_SUCCESS on success, SKHLIB_ERROR on failure.
 */
int create_asymmetric_keypair(unsigned char *public_key, unsigned char *secret_key);

/**
 * @brief Create client session keys for secure communication.
 * 
 * @param[out] receive_key Buffer to store the generated receive key.
 * @param[out] transmit_key Buffer to store the generated transmit key.
 * @param[in] client_public_key Client's public key.
 * @param[in] client_secret_key Client's secret key.
 * @param[in] server_public_key Server's public key.
 * @return int SKHLIB_SUCCESS on success, SKHLIB_ERROR on failure.
 */
int derive_client_session_keys(unsigned char *receive_key, unsigned char *transmit_key,
                               const unsigned char *client_public_key, const unsigned char *client_secret_key,
                               const unsigned char *server_public_key);

// Hashing API
/**
 * @brief Compute SHA-256 hash of a message.
 * 
 * @param[out] hash_output Buffer to store the computed hash.
 * @param[in] message Input message to be hashed.
 * @param[in] message_length Length of the input message.
 * @return int SKHLIB_SUCCESS on success, SKHLIB_ERROR on failure.
 */
int compute_sha256_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length);

/**
 * @brief Compute SHA-512 hash of a message.
 * 
 * @param[out] hash_output Buffer to store the computed hash.
 * @param[in] message Input message to be hashed.
 * @param[in] message_length Length of the input message.
 * @return int SKHLIB_SUCCESS on success, SKHLIB_ERROR on failure.
 */
int compute_sha512_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length);

// Password hashing API
/**
 * @brief Hash a password using a secure algorithm.
 * 
 * @param[out] hashed_password Buffer to store the hashed password.
 * @param[in] hashed_password_length Length of the hashed password buffer.
 * @param[in] password Input password to be hashed.
 * @param[in] password_length Length of the input password.
 * @return int SKHLIB_SUCCESS on success, SKHLIB_ERROR on failure.
 */
int secure_password_hash(char *hashed_password, unsigned long hashed_password_length,
                         const char *password, unsigned long password_length);

#endif // SECURE_KX_HASH_LIB_H

