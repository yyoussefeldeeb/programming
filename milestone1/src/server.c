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
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    unsigned char buffer[BUFFER_SIZE] = {0};
    char decrypted_buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};
    unsigned char encrypted_response[BUFFER_SIZE] = {0};
    const char *psk;
    int recv_bytes;
    int auth_result;

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept a client connection
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected\n");

    psk = get_default_psk();

    // Phase 1: Authentication
    printf("\n--- Authentication Phase ---\n");
    memset(buffer, 0, BUFFER_SIZE);
    recv_bytes = read(new_socket, buffer, BUFFER_SIZE - 1);
    if (recv_bytes > 0 && recv_bytes < BUFFER_SIZE) {
        buffer[recv_bytes] = '\0';
    }
    printf("Received PSK from client\n");

    auth_result = authenticate_psk((char *)buffer, psk);
    if (auth_result) {
        printf("Client authenticated successfully\n");
        send(new_socket, "AUTH_OK", 7, 0);
    } else {
        printf("Authentication failed\n");
        send(new_socket, "AUTH_FAIL", 9, 0);
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Phase 2: Receive and decrypt message
    printf("\n--- Communication Phase ---\n");
    memset(buffer, 0, BUFFER_SIZE);
    memset(decrypted_buffer, 0, BUFFER_SIZE);
    recv_bytes = read(new_socket, buffer, BUFFER_SIZE - 1);

    if (recv_bytes > 0) {
        decrypt_message(buffer, psk, decrypted_buffer, recv_bytes);
        if (recv_bytes < BUFFER_SIZE) {
            decrypted_buffer[recv_bytes] = '\0';
        }
    }
    printf("Client: %s\n", decrypted_buffer);

    // Prepare and send encrypted response
    strcpy(response, "Hello from secure server");
    size_t response_len = strlen(response);

    memset(encrypted_response, 0, BUFFER_SIZE);
    encrypt_message(response, psk, encrypted_response, response_len);

    send(new_socket, encrypted_response, response_len, 0);

    // Close sockets
    close(new_socket);
    close(server_fd);

    return 0;
}
