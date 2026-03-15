#ifndef AUTH_H
#define AUTH_H

int authenticate_psk(const char *received_psk, const char *expected_psk);

const char* get_default_psk(void);

#endif // AUTH_H
