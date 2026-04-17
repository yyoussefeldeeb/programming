#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../include/auth.h"
#include "../include/encryption.h"
#include "../include/fileops.h"

#define BUFFER_SIZE 1024

// ports for different levels
#define ENTRY_PORT 9001
#define MEDIUM_PORT 9002
#define TOP_PORT 9003

// forward declaration
void *handle_client(void *arg);

// info for port listener thread
struct port_listener {
    int port;
    const char *level_name;
};

// info for client handler thread
struct client_info {
    int socket;
    const char *password;
    const char *username;
    const char *role;
    int port;
};

// this thread listens on a specific port for clients
void *listen_on_port(void *arg)
{
    struct port_listener *listener = (struct port_listener *)arg;
    int port = listener->port;
    const char *level_name = listener->level_name;
    
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Make socket for this port
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        pthread_exit(NULL);
    }

    // Set up address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Stick socket to port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        pthread_exit(NULL);
    }

    // Wait for clients
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("Server listening on port %d (%s level)...\n", port, level_name);

    // accept clients on this port forever
    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        printf("\nNew connection on port %d\n", port);

        // spawn thread to handle this client
        pthread_t client_thread;
        struct client_info *client_data = (struct client_info *)malloc(sizeof(struct client_info));
        if (client_data == NULL) {
            perror("Memory allocation failed");
            close(new_socket);
            continue;
        }
        
        client_data->socket = new_socket;
        client_data->port = port;

        if (pthread_create(&client_thread, NULL, handle_client, (void *)client_data) != 0) {
            perror("Thread creation failed");
            free(client_data);
            close(new_socket);
            continue;
        }
        
        pthread_detach(client_thread);
    }

    close(server_fd);
    free(listener);
    return NULL;
}

// handle a single client
void *handle_client(void *arg)
{
    struct client_info *info = (struct client_info *)arg;
    int client_socket = info->socket;
    int port = info->port;
    
    unsigned char buffer[BUFFER_SIZE] = {0};
    char decrypted_buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};
    unsigned char encrypted_response[BUFFER_SIZE] = {0};
    int recv_bytes;
    int auth_result;
    char username[64] = {0};
    char password[64] = {0};
    char role[64] = {0};

    // Check if they know the password
    printf("\n--- Authentication Phase (Port %d) ---\n", port);
    memset(buffer, 0, BUFFER_SIZE);
    recv_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (recv_bytes > 0 && recv_bytes < BUFFER_SIZE) {
        buffer[recv_bytes] = '\0';
    }

    // parse username:password from buffer
    if (sscanf((char *)buffer, "%63[^:]:%63s", username, password) == 2) {
        printf("Received login: %s\n", username);
    }

    // authenticate from users.txt
    auth_result = authenticate_user(username, password, role);
    if (auth_result) {
        printf("%s (%s level) logged in on port %d\n", username, role, port);
        send(client_socket, "AUTH_OK", 7, 0);
    } else {
        printf("Authentication failed for user: %s\n", username);
        send(client_socket, "AUTH_FAIL", 9, 0);
        close(client_socket);
        free(info);
        return NULL;
    }

    // Get the secret message from client and decode it
    printf("\n--- Communication Phase ---\n");
    
    // main command loop for this client
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        memset(decrypted_buffer, 0, BUFFER_SIZE);
        recv_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);

        // client disconnected
        if (recv_bytes <= 0) {
            printf("%s disconnected from port %d\n", username, port);
            break;
        }

        // decrypt command
        decrypt_message(buffer, password, decrypted_buffer, recv_bytes);
        decrypted_buffer[recv_bytes] = '\0';
        printf("%s: %s\n", username, decrypted_buffer);

        // parse command
        char command[64] = {0};
        char arg1[256] = {0};
        char arg2[256] = {0};
        char arg3[1024] = {0};
        
        int parts = sscanf(decrypted_buffer, "%63s %255s %255s %1023s", command, arg1, arg2, arg3);

        // check permissions
        if (!check_permission(role, command)) {
            sprintf(response, "Permission denied: %s not allowed for %s level", command, role);
        } else {
            // execute command
            char *role_dir = get_role_directory(role);
            
            // ls command
            if (strcmp(command, "ls") == 0) {
                list_files(role_dir, response);
            }
            // cat command
            else if (strcmp(command, "cat") == 0) {
                if (parts < 2) {
                    sprintf(response, "Usage: cat <filename>");
                } else {
                    read_file_content(role_dir, arg1, response);
                }
            }
            // cp command
            else if (strcmp(command, "cp") == 0) {
                if (parts < 3) {
                    sprintf(response, "Usage: cp <source> <destination>");
                } else {
                    copy_file_op(role_dir, arg1, arg2, response);
                }
            }
            // edit command
            else if (strcmp(command, "edit") == 0) {
                if (parts < 3) {
                    sprintf(response, "Usage: edit <filename> <content>");
                } else {
                    write_file_op(role_dir, arg1, arg3, response);
                }
            }
            // rm command
            else if (strcmp(command, "rm") == 0) {
                if (parts < 2) {
                    sprintf(response, "Usage: rm <filename>");
                } else {
                    delete_file_op(role_dir, arg1, response);
                }
            }
            else {
                sprintf(response, "Unknown command: %s", command);
            }
        }

        // encrypt and send response
        size_t response_len = strlen(response);
        size_t padded_len = ((response_len + 15) / 16) * 16;

        memset(encrypted_response, 0, BUFFER_SIZE);
        encrypt_message(response, password, encrypted_response);

        send(client_socket, encrypted_response, padded_len, 0);
    }

    // Close this client connection
    close(client_socket);
    free(info);
    
    return NULL;
}

int main()
{
    pthread_t entry_thread, medium_thread, top_thread;

    // create thread for each port level
    struct port_listener *entry_listener = (struct port_listener *)malloc(sizeof(struct port_listener));
    entry_listener->port = ENTRY_PORT;
    entry_listener->level_name = "entry";
    pthread_create(&entry_thread, NULL, listen_on_port, (void *)entry_listener);

    struct port_listener *medium_listener = (struct port_listener *)malloc(sizeof(struct port_listener));
    medium_listener->port = MEDIUM_PORT;
    medium_listener->level_name = "medium";
    pthread_create(&medium_thread, NULL, listen_on_port, (void *)medium_listener);

    struct port_listener *top_listener = (struct port_listener *)malloc(sizeof(struct port_listener));
    top_listener->port = TOP_PORT;
    top_listener->level_name = "top";
    pthread_create(&top_thread, NULL, listen_on_port, (void *)top_listener);

    printf("=== Secure Server Started ===\n");

    // wait for all threads (they run forever)
    pthread_join(entry_thread, NULL);
    pthread_join(medium_thread, NULL);
    pthread_join(top_thread, NULL);

    return 0;
}
