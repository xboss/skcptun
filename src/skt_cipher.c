
#include "skt_cipher.h"

#include <assert.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *str2hex(const char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len % 2) == 0);
    ret = malloc(str_len / 2);
    for (i = 0; i < str_len; i = i + 2) {
        sscanf(str + i, "%2hhx", &ret[i / 2]);
    }
    return ret;
}

char *skt_cipher_padding(const char *buf, int size, int *final_size) {
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + pidding_size;
    ret = (char *)malloc(size + pidding_size);
    memcpy(ret, buf, size);
    if (pidding_size != 0) {
        for (i = size; i < (size + pidding_size); i++) {
            ret[i] = 0;
        }
    }
    return ret;
}

void skt_aes_cbc_encrpyt(const char *raw_buf, char **encrpy_buf, int len, char *key, char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_encrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_ENCRYPT);
    free(skey);
    free(siv);
}
void skt_aes_cbc_decrpyt(const char *raw_buf, char **encrpy_buf, int len, char *key, char *iv) {
    AES_KEY aes_key;
    unsigned char *skey = str2hex(key);
    unsigned char *siv = str2hex(iv);
    AES_set_decrypt_key(skey, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *)raw_buf, (unsigned char *)*encrpy_buf, len, &aes_key, siv, AES_DECRYPT);
    free(skey);
    free(siv);
}
