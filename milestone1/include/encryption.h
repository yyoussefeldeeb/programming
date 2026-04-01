#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>

void encrypt_message(const char *plaintext, const char *key, 
                     unsigned char *ciphertext);

void decrypt_message(const unsigned char *ciphertext, const char *key, 
                     char *plaintext, size_t len);

#endif // ENCRYPTION_H
