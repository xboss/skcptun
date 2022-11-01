#ifndef _SKT_CIPHER_H
#define _SKT_CIPHER_H

char *skt_cipher_padding(const char *buf, int size, int *final_size);
void skt_aes_cbc_encrpyt(const char *raw_buf, char **encrpy_buf, int len, char *key, char *iv);
void skt_aes_cbc_decrpyt(const char *raw_buf, char **encrpy_buf, int len, char *key, char *iv);

#endif