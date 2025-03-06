#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stddef.h>

#define AES_128_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

int crypto_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext,
                   size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len);
int crypto_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext,
                   size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len);

#endif  // CRYPTO_H
