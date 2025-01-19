// secure_kx_hash_lib.c
#include "secure_kx_hash_lib.h"
#include <string.h>

int create_asymmetric_keypair(unsigned char *public_key, unsigned char *secret_key) {
    if (public_key == NULL || secret_key == NULL) {
        return SKHLIB_ERROR;
    }
    
    if (crypto_kx_keypair(public_key, secret_key) != 0) {
        return SKHLIB_ERROR;
    }
    
    return SKHLIB_SUCCESS;
}

int derive_client_session_keys(unsigned char *receive_key, unsigned char *transmit_key,
                               const unsigned char *client_public_key, const unsigned char *client_secret_key,
                               const unsigned char *server_public_key) {
    if (receive_key == NULL || transmit_key == NULL || 
        client_public_key == NULL || client_secret_key == NULL || server_public_key == NULL) {
        return SKHLIB_ERROR;
    }
    
    if (crypto_kx_client_session_keys(receive_key, transmit_key, client_public_key, client_secret_key, server_public_key) != 0) {
        return SKHLIB_ERROR;
    }
    
    return SKHLIB_SUCCESS;
}

int compute_sha256_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length) {
    if (hash_output == NULL || message == NULL) {
        return SKHLIB_ERROR;
    }
    
    crypto_hash_sha256(hash_output, message, message_length);
    return SKHLIB_SUCCESS;
}

int compute_sha512_hash(unsigned char *hash_output, const unsigned char *message, unsigned long long message_length) {
    if (hash_output == NULL || message == NULL) {
        return SKHLIB_ERROR;
    }
    
    crypto_hash_sha512(hash_output, message, message_length);
    return SKHLIB_SUCCESS;
}

int secure_password_hash(char *hashed_password, unsigned long hashed_password_length,
                         const char *password, unsigned long password_length) {

    unsigned char salt[crypto_pwhash_SALTBYTES];

    randombytes_buf(salt, sizeof salt);

    if (hashed_password == NULL || password == NULL) {
        return SKHLIB_ERROR;
    }
    
    if (crypto_pwhash((unsigned char *)hashed_password, hashed_password_length,
                      password, password_length,
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        // Securely clear any partial results
        memset(hashed_password, 0, hashed_password_length);
        return SKHLIB_ERROR;
    }
    
    return SKHLIB_SUCCESS;
}
