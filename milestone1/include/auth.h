#ifndef AUTH_H
#define AUTH_H

int authenticate_psk(const char *received_psk, const char *expected_psk);

const char* get_default_psk(void);

// authenticate user from users.txt file
// returns 1 if success, 0 if fail
// also fills in the role buffer with the user's role
int authenticate_user(const char *username, const char *password, char *role);

#endif // AUTH_H
