#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int crypto_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext,
                   size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        fprintf(stderr, "Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int total_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Failed to encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    *ciphertext_len = total_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int crypto_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext,
                   size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        fprintf(stderr, "Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int total_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Failed to decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Failed to finalize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    *plaintext_len = total_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
