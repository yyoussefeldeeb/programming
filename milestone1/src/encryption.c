#include "encryption.h"
#include <string.h>

void encrypt_message(const char *plaintext, const char *key, 
                     unsigned char *ciphertext, size_t len)
{
    if (plaintext == NULL || key == NULL || ciphertext == NULL) {
        return;
    }
    
    size_t key_len = strlen(key);
    
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = (unsigned char)plaintext[i] ^ (unsigned char)key[i % key_len];
    }
}

void decrypt_message(const unsigned char *ciphertext, const char *key, 
                     char *plaintext, size_t len)
{
    if (ciphertext == NULL || key == NULL || plaintext == NULL) {
        return;
    }
    
    size_t key_len = strlen(key);
    
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = (char)(ciphertext[i] ^ (unsigned char)key[i % key_len]);
    }
}
