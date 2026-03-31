#include "encryption.h"
#include <string.h>
#include <openssl/aes.h>

#define KEY_SIZE 16  // 128-bit key for AES-128
#define BLOCK_SIZE 16  // AES block size is always 16 bytes

// make a key from the password
// just repeat it until we have 16 bytes 
static void make_key(const char *psk, unsigned char *key)
{
    memset(key, 0, KEY_SIZE);
    size_t psk_len = strlen(psk);
    
    for (int i = 0; i < KEY_SIZE; i++) {
        key[i] = (unsigned char)psk[i % psk_len];
    }
}

// pad the message so its a multiple of 16
// we just add spaces at the end to make it work
static int pad_message(const char *plaintext, unsigned char *padded)
{
    int len = strlen(plaintext);
    int padded_len = ((len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE; // round up to 16
    
    memset(padded, 0, padded_len);
    memcpy(padded, plaintext, len);
    
    // fill rest with spaces
    for (int i = len; i < padded_len; i++) {
        padded[i] = ' ';
    }
    
    return padded_len;
}

// encrypt stuff
// just loop through the message in 16 byte chunks and encrypt each one
void encrypt_message(const char *plaintext, const char *key, 
                     unsigned char *ciphertext, size_t len)
{
    if (plaintext == NULL || key == NULL || ciphertext == NULL) {
        return;
    }

    unsigned char aes_key[KEY_SIZE];
    unsigned char padded[4096]; // big enough for messages
    
    // make the key smaller/bigger so its 16 bytes
    make_key(key, aes_key);
    
    // make message fit in blocks
    int padded_len = pad_message(plaintext, padded);
    
    // encrypt each 16 byte block
    AES_KEY aes_expand;
    AES_set_encrypt_key(aes_key, 128, &aes_expand);
    
    for (int i = 0; i < padded_len; i += BLOCK_SIZE) {
        AES_ecb_encrypt(padded + i, ciphertext + i, &aes_expand, AES_ENCRYPT);
    }
}

// decrypt part
// reverse of encrypt, loop through and decrypt each block
void decrypt_message(const unsigned char *ciphertext, const char *key, 
                     char *plaintext, size_t len)
{
    if (ciphertext == NULL || key == NULL || plaintext == NULL) {
        return;
    }

    unsigned char aes_key[KEY_SIZE];
    unsigned char decrypted[4096];
    
    // make the key
    make_key(key, aes_key);
    
    // decrypt each block
    AES_KEY aes_expand;
    AES_set_decrypt_key(aes_key, 128, &aes_expand);
    
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        AES_ecb_encrypt(ciphertext + i, decrypted + i, &aes_expand, AES_DECRYPT);
    }
    
    // copy to plaintext and null terminate
    memcpy(plaintext, decrypted, len);
    plaintext[len] = '\0';
}
