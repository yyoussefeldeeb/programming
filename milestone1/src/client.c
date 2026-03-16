#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/auth.h"
#include "../include/encryption.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
    int sock;
    struct sockaddr_in server_address;
    unsigned char buffer[BUFFER_SIZE] = {0};
    char decrypted_buffer[BUFFER_SIZE] = {0};
    char message[BUFFER_SIZE] = {0};
    unsigned char encrypted_message[BUFFER_SIZE] = {0};
    const char *psk;
    int recv_bytes;
    char auth_response[20] = {0};

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    psk = get_default_psk();

    // Phase 1: Send PSK for authentication
    printf("\n--- Authentication Phase ---\n");
    send(sock, psk, strlen(psk), 0);
    printf("Sent PSK to server\n");

    // Receive authentication response
    memset(auth_response, 0, sizeof(auth_response));
    recv_bytes = read(sock, auth_response, sizeof(auth_response) - 1);
    if (recv_bytes > 0 && recv_bytes < sizeof(auth_response)) {
        auth_response[recv_bytes] = '\0';
    }

    if (strcmp(auth_response, "AUTH_OK") == 0) {
        printf("Authentication successful\n");
    } else {
        printf("Authentication failed\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Phase 2: Send encrypted message
    printf("\n--- Communication Phase ---\n");
    strcpy(message, "Hello from secure client");
    size_t message_len = strlen(message);

    memset(encrypted_message, 0, BUFFER_SIZE);
    encrypt_message(message, psk, encrypted_message, message_len);

    printf("Sending: %s\n", message);
    send(sock, encrypted_message, message_len, 0);

    // Receive and decrypt response from server
    memset(buffer, 0, BUFFER_SIZE); - 1);

    if (recv_bytes > 0) {
        decrypt_message(buffer, psk, decrypted_buffer, recv_bytes);
        if (recv_bytes < BUFFER_SIZE) {
            decrypted_buffer[recv_bytes] = '\0';
        }
    }
    decrypt_message(buffer, psk, decrypted_buffer, recv_bytes);
    decrypted_buffer[recv_bytes] = '\0';
    printf("Server: %s\n", decrypted_buffer);

    // Close socket
    close(sock);

    return 0;
}
