#include "mytls.h"

uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

#define BLOCKSIZE 16
//pkcs7_padding 填充
void pkcs7_padding(char* dst, const char* src, int inputLen)
{
    memset(dst, 0, BLOCKSIZE);
    memcpy(dst, src, inputLen);
    // 判断缺少几位长度
    int padding = BLOCKSIZE - inputLen;
    int i = 0;
    // 补足位数,把padding复制padding个
    // 如果padding为0,会直接跳过
    while(i < padding)
    {
        memset(dst + inputLen + i, padding, 1);
        ++i;
    }
}


//pkcs7_unpadding 填充的反向操作
void pkcs7_unpadding(char* data)
{
    //获取填充的个数,即最后一位的数字
    int unPadding = data[BLOCKSIZE - 1];
    if(unPadding >= BLOCKSIZE) 
    {
        // 说明没有填充
        return;
    }
    data[BLOCKSIZE - unPadding] = '\0';
}

int my_aes_encrypt(const char* input, char* output, int inputLen)
{
    struct AES_ctx ctx;
    char msg[BLOCKSIZE];
    // 超过16字节,不予处理
    if (inputLen > BLOCKSIZE) {
        return -1;
    }
    
    /**************************Step 1 AES256 Encryption***************************/
    // 填充
    pkcs7_padding(msg, input, inputLen);
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, (uint8_t*)msg);

    /**************************Step 2 Base64 Encoding***************************/    
    int encodedLen = base64_enc_len(BLOCKSIZE);
    char encoded_text[encodedLen];

    // note input is consumed in this step: it will be empty afterwards
    base64_encode(encoded_text, msg, BLOCKSIZE); 
    
    /**************************Step 3 Copy result***************************/
    memset(output, 0, encodedLen + 1);
    memcpy(output, encoded_text, encodedLen);
    output[encodedLen] = '\0';
    return 0;
}

int my_aes_decrypt(const char* input, char* output)
{
    struct AES_ctx ctx;

    /**************************Step 1 Copy input***************************/
    char encoded_text[BASE64_ENCODED_SIZE_BYTES];
    memcpy(encoded_text, input, BASE64_ENCODED_SIZE_BYTES);

    /**************************Step 2 Base64 Decoding***************************/
    base64_decode(output, encoded_text, BASE64_ENCODED_SIZE_BYTES);
    
    /**************************Step 3 AES256 Decryption***************************/

    AES_init_ctx(&ctx, key);

    AES_ECB_decrypt(&ctx, (uint8_t*)output);

    // 去除填充字段
    pkcs7_unpadding(output);
}
