#ifndef _MYTLS_H_
#define _MYTLS_H_

#include "aes.h"

#define BASE64_ENCODED_SIZE_BYTES 24

int testAES256ECB(void);
int testBASE64(void);
void pkcs7_padding(char *dst, const char *src, int inputLen);
void pkcs7_unpadding(char *data);
int my_aes_encrypt(const char *input, char *output, int inputLen);
int my_aes_decrypt(const char* input, char* output);

#endif