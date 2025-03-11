#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int crypto_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext, size_t* ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // 明确设置 IV 长度（示例）
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    *ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len = len;

    // Final 应该不输出任何数据
    if (EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (len != 0) {  // 关键检查
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int crypto_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext, size_t* plaintext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // 明确设置 IV 长度
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    *plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len = len;

    // Final 应该不输出任何数据
    if (EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (len != 0) {  // 关键检查
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

#include "skt.h"
int main(int argc, char const* argv[]) {
    char key[] = "yourpassword1234555";
//     unsigned char key[16];
// RAND_bytes(key, sizeof(key));
    char iv[] = "bewatermyfriend.";
//     unsigned char iv[16];
// RAND_bytes(iv, sizeof(iv));
    char plaintext[] = "Hello, world!";
    char ciphertext[AES_BLOCK_SIZE * 10] = {0};
    // printf("plaintext: %s\n", plaintext);
    // skt_print_hex("plaintext", plaintext, strlen(plaintext));
    size_t ciphertext_len = 0;

    char plaintext2[AES_BLOCK_SIZE * 10] = {0};
    size_t plaintext2_len = 0;

    crypto_encrypt(key, iv, plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
    assert(ciphertext_len == strlen(plaintext));
    skt_print_hex("ciphertext", ciphertext, ciphertext_len);
    crypto_decrypt(key, iv, ciphertext, ciphertext_len, plaintext2, &plaintext2_len);
    // skt_print_hex("plaintext2", plaintext2, plaintext2_len);
    assert(strlen(plaintext) == plaintext2_len);
    assert(0 == strncmp(plaintext, plaintext2, plaintext2_len));
    // printf("plaintext2: %s\n", plaintext2);

    crypto_encrypt(key, iv, plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
    assert(ciphertext_len == strlen(plaintext));
    skt_print_hex("ciphertext", ciphertext, ciphertext_len);
    crypto_decrypt(key, iv, ciphertext, ciphertext_len, plaintext2, &plaintext2_len);
    // skt_print_hex("plaintext2", plaintext2, plaintext2_len);
    assert(strlen(plaintext) == plaintext2_len);
    assert(0 == strncmp(plaintext, plaintext2, plaintext2_len));

    return 0;
}

// gcc src/crypto.c -I. -o test -lcrypto -lssl -g && ./test