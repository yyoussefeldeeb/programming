#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../include/auth.h"
#include "../include/encryption.h"

#define PORT 8080
#define BUFFER_SIZE 1024

// container to pass stuff to thread
struct client_info {
    int socket;
    const char *psk;
};

// this is what a thread does when a client connects
void *handle_client(void *arg)
{
    struct client_info *info = (struct client_info *)arg;
    int client_socket = info->socket;
    const char *psk = info->psk;
    
    unsigned char buffer[BUFFER_SIZE] = {0};
    char decrypted_buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};
    unsigned char encrypted_response[BUFFER_SIZE] = {0};
    int recv_bytes;
    int auth_result;

    // Check if they know the password
    printf("\n--- Authentication Phase ---\n");
    memset(buffer, 0, BUFFER_SIZE);
    recv_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (recv_bytes > 0 && recv_bytes < BUFFER_SIZE) {
        buffer[recv_bytes] = '\0';
    }
    printf("Received PSK from client\n");

    auth_result = authenticate_psk((char *)buffer, psk);
    if (auth_result) {
        printf("Client authenticated successfully\n");
        send(client_socket, "AUTH_OK", 7, 0);
    } else {
        printf("Authentication failed\n");
        send(client_socket, "AUTH_FAIL", 9, 0);
        close(client_socket);
        free(info);
        return NULL;
    }

    // Get the secret message from client and decode it
    printf("\n--- Communication Phase ---\n");
    memset(buffer, 0, BUFFER_SIZE);
    memset(decrypted_buffer, 0, BUFFER_SIZE);
    recv_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);

    if (recv_bytes > 0) {
        decrypt_message(buffer, psk, decrypted_buffer, recv_bytes);
        if (recv_bytes < BUFFER_SIZE) {
            decrypted_buffer[recv_bytes] = '\0';
        }
        printf("Client: %s\n", decrypted_buffer);
    }

    // Send back a secret message
    strcpy(response, "Hello from secure server");
    size_t response_len = strlen(response);

    memset(encrypted_response, 0, BUFFER_SIZE);
    encrypt_message(response, psk, encrypted_response, response_len);

    send(client_socket, encrypted_response, response_len, 0);

    // Close this client connection
    close(client_socket);
    // don't forget to free the thing we allocated
    free(info);
    
    return NULL;
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;
    const char *psk;

    // Make socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Set up address so we can listen
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Stick the socket to a port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Wait for someone to connect
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);
    
    psk = get_default_psk();

    // loop forever accepting clients
    while (1) {
        // Accept when a client comes in
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");

        // make a container for the client info
        struct client_info *client_data = (struct client_info *)malloc(sizeof(struct client_info));
        if (client_data == NULL) {
            perror("Memory allocation failed");
            close(new_socket);
            continue;
        }
        
        client_data->socket = new_socket;
        client_data->psk = psk;

        // spawn a thread to handle this client
        if (pthread_create(&thread_id, NULL, handle_client, (void *)client_data) != 0) {
            perror("Thread creation failed");
            free(client_data);
            close(new_socket);
            continue;
        }
        
        // don't wait for thread to finish, next client can connect while this one talks
        pthread_detach(thread_id);
    }

    // Put main socket away
    close(server_fd);

    return 0;
}
