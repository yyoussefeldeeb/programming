#include "auth.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_PSK "SecureKey123"
#define USERS_FILE "users.txt"

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

// read users.txt and check if username:password exists
// if found, put the role in the role buffer
int authenticate_user(const char *username, const char *password, char *role)
{
    if (username == NULL || password == NULL || role == NULL) {
        return 0;
    }

    FILE *file = fopen(USERS_FILE, "r");
    if (file == NULL) {
        printf("Error: Could not open %s\n", USERS_FILE);
        return 0;
    }

    char line[256];
    char file_user[64], file_pass[64], file_role[64];
    int found = 0;

    // read each line from users.txt
    while (fgets(line, sizeof(line), file)) {
        // parse line: username:password:role
        if (sscanf(line, "%63[^:]:%63[^:]:%63[^\n]", file_user, file_pass, file_role) == 3) {
            // check if username and password match
            if (strcmp(file_user, username) == 0 && strcmp(file_pass, password) == 0) {
                strcpy(role, file_role);
                found = 1;
                break;
            }
        }
    }

    fclose(file);
    return found;
}
