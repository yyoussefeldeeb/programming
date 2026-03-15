#include "auth.h"
#include <string.h>

#define DEFAULT_PSK "SecureKey123"

int authenticate_psk(const char *received_psk, const char *expected_psk)
{
    if (received_psk == NULL || expected_psk == NULL) {
        return 0;
    }
    
    return (strcmp(received_psk, expected_psk) == 0) ? 1 : 0;
}

const char* get_default_psk(void)
{
    return DEFAULT_PSK;
}
