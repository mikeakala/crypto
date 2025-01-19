// tests/test_secure_kx_hash_lib.c

#include <stdio.h>
#include <sodium.h>
#include "secure_kx_hash_lib.h"

// Utility function for printing hex values
static void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test function for asymmetric key pair generation
static void test_asymmetric_keypair_generation() {
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
    
    int result = create_asymmetric_keypair(client_pk, client_sk);
    
    printf("Asymmetric Key Pair Generation Test:\n");
    printf("Result: %s\n", result == SKHLIB_SUCCESS ? "Success" : "Failure");
    printf("Public Key: ");
    print_hex(client_pk, crypto_kx_PUBLICKEYBYTES);
    printf("Secret Key: ");
    print_hex(client_sk, crypto_kx_SECRETKEYBYTES);
    printf("\n");
}

// Add more test functions for other library features...

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    test_asymmetric_keypair_generation();
    

    return 0;
}
