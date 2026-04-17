#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/auth.h"
#include "../include/encryption.h"

#define ENTRY_PORT 9001
#define MEDIUM_PORT 9002
#define TOP_PORT 9003
#define BUFFER_SIZE 1024

int main()
{
    int sock;
    struct sockaddr_in server_address;
    unsigned char buffer[BUFFER_SIZE] = {0};
    char decrypted_buffer[BUFFER_SIZE] = {0};
    char message[BUFFER_SIZE] = {0};
    unsigned char encrypted_message[BUFFER_SIZE] = {0};
    int recv_bytes;
    char auth_response[20] = {0};
    char username[64] = {0};
    char password[64] = {0};
    int port = ENTRY_PORT;
    char level_choice[10] = {0};

    // ask which level to connect to
    printf("=== Secure Client ===\n");
    printf("Which level? (1=entry, 2=medium, 3=top): ");
    fgets(level_choice, sizeof(level_choice), stdin);
    
    if (level_choice[0] == '2') {
        port = MEDIUM_PORT;
        printf("Connecting to MEDIUM level...\n");
    } else if (level_choice[0] == '3') {
        port = TOP_PORT;
        printf("Connecting to TOP level...\n");
    } else {
        printf("Connecting to ENTRY level...\n");
    }

    // Make a socket to talk to server
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Tell socket where the server is
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server on port %d\n", port);

    // ask user for credentials
    printf("\n--- Login ---\n");
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0; // remove newline
    
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0; // remove newline

    // send username and password to server
    printf("\n--- Authentication Phase ---\n");
    char auth_packet[256];
    snprintf(auth_packet, sizeof(auth_packet), "%s:%s", username, password);
    send(sock, auth_packet, strlen(auth_packet), 0);
    printf("Sent credentials to server\n");

    // Listen for server to say if password is right
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

    // Send commands to server in a loop
    printf("\n--- Command Phase ---\n");
    printf("Available commands:\n");
    printf("  ls              - List files\n");
    printf("  cat <file>      - Read file\n");
    printf("  cp <src> <dst>  - Copy file\n");
    printf("  edit <file> <content> - Edit file\n");
    printf("  rm <file>       - Delete file\n");
    printf("  quit            - Exit\n\n");

    char command[BUFFER_SIZE] = {0};
    
    while (1) {
        printf("> ");
        memset(command, 0, BUFFER_SIZE);
        memset(message, 0, BUFFER_SIZE);
        
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = 0; // remove newline
        
        // quit command
        if (strcmp(command, "quit") == 0) {
            printf("Disconnecting...\n");
            break;
        }
        
        // skip empty commands
        if (strlen(command) == 0) {
            continue;
        }
        
        // prepare message
        strcpy(message, command);
        
        size_t message_len = strlen(message);
        size_t padded_len = ((message_len + 15) / 16) * 16;

        memset(encrypted_message, 0, BUFFER_SIZE);
        encrypt_message(message, password, encrypted_message);

        printf("Sending: %s\n", message);
        send(sock, encrypted_message, padded_len, 0);

        // Get and decode the response from server
        memset(buffer, 0, BUFFER_SIZE);
        memset(decrypted_buffer, 0, BUFFER_SIZE);
        recv_bytes = read(sock, buffer, BUFFER_SIZE - 1);

        if (recv_bytes > 0) {
            decrypt_message(buffer, password, decrypted_buffer, recv_bytes);
            decrypted_buffer[recv_bytes] = '\0';
            printf("Response:\n%s\n", decrypted_buffer);
        }
    }

    // close socket
    close(sock);

    return 0;
}
