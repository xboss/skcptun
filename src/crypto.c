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

// #include "skt.h"

// int main(int argc, char const* argv[]) {
//     char key[] = "yourpassword1234";
// //     unsigned char key[16];
// // RAND_bytes(key, sizeof(key));
//     char iv[] = "bewatermyfriend.";
// //     unsigned char iv[16];
// // RAND_bytes(iv, sizeof(iv));
//     // char plaintext[] = "Hello, world!Hello, world!Hello, world!12345";
//     char plaintext[] = {0x02, 0x79, 0x6f, 0x75, 0x72, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x79, 0x6f, 0x75, 0x72, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x79, 0x6f, 0x75, 0x72, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x31, 0x32, 0x01, 0x01, 0x01, 0xc0, 0x00, 0x00, 0x01, 0x95, 0x85, 0xf6, 0x4a, 0xdf};
//     char ciphertext[sizeof plaintext] = {0};
//     // printf("plaintext: %s\n", plaintext);
//     skt_print_hex("plaintext", plaintext, sizeof(plaintext));
//     size_t ciphertext_len = 0;

//     char plaintext2[sizeof plaintext] = {0};
//     size_t plaintext2_len = 0;

//     crypto_encrypt(key, iv, plaintext, sizeof(plaintext), ciphertext, &ciphertext_len);
//     assert(ciphertext_len == sizeof(plaintext));
//     skt_print_hex("ciphertext", ciphertext, ciphertext_len);
//     crypto_decrypt(key, iv, ciphertext, ciphertext_len, plaintext2, &plaintext2_len);
//     skt_print_hex("plaintext2", plaintext2, plaintext2_len);
//     assert(sizeof(plaintext) == plaintext2_len);
//     assert(0 == memcmp(plaintext, plaintext2, plaintext2_len));
//     // printf("plaintext2: %s\n", plaintext2);

//     // crypto_encrypt(key, iv, plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
//     // assert(ciphertext_len == strlen(plaintext));
//     // skt_print_hex("ciphertext", ciphertext, ciphertext_len);
//     // crypto_decrypt(key, iv, ciphertext, ciphertext_len, plaintext2, &plaintext2_len);
//     // // skt_print_hex("plaintext2", plaintext2, plaintext2_len);
//     // assert(strlen(plaintext) == plaintext2_len);
//     // assert(0 == strncmp(plaintext, plaintext2, plaintext2_len));

//     return 0;
// }
