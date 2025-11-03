
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <math.h>

#define PORT "8080"
#define BUFFER_SIZE 1024

volatile sig_atomic_t running = 1;

struct client_info {
    int socket_fd;
    SSL *ssl;
    struct sockaddr_storage address;
};

void *handle_client(void *arg);
int parse_and_sum(const char *query, long *result);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void signal_handler(int sig);

int main() {
    int server_fd;
    struct addrinfo hints, *res;
    SSL_CTX *ctx;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = create_context();
    configure_context(ctx);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // For wildcard IP address

    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        exit(EXIT_FAILURE);
    }

    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (bind(server_fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %s\n", PORT);

    while (running) {
        struct client_info *client = malloc(sizeof(struct client_info));
        if (!client) {
            perror("malloc for client_info failed");
            continue;
        }

        socklen_t client_len = sizeof(client->address);
        client->socket_fd = accept(server_fd, (struct sockaddr *)&client->address, &client_len);

        if (client->socket_fd == -1) {
            if (running) perror("accept failed");
            free(client);
            continue;
        }

        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(client->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        client->ssl = SSL_new(ctx);
        SSL_set_fd(client->ssl, client->socket_fd);

        if (SSL_accept(client->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client->socket_fd);
            SSL_free(client->ssl);
            free(client);
            continue;
        }

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client) != 0) {
            perror("pthread_create failed");
            close(client->socket_fd);
            SSL_free(client->ssl);
            free(client);
        }
        pthread_detach(thread_id);
    }

    printf("\nShutting down server...\n");
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

void *handle_client(void *arg) {
    struct client_info *client = (struct client_info *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    char client_addr_str[INET6_ADDRSTRLEN];
    if (client->address.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&client->address;
        inet_ntop(AF_INET, &s->sin_addr, client_addr_str, sizeof(client_addr_str));
        printf("Client connected from %s:%d\n", client_addr_str, ntohs(s->sin_port));
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client->address;
        inet_ntop(AF_INET6, &s->sin6_addr, client_addr_str, sizeof(client_addr_str));
        printf("Client connected from %s:%d\n", client_addr_str, ntohs(s->sin6_port));
    }

    while ((bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = 0;
        printf("Received: %s", buffer);

        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        if (strncmp(buffer, "GET /calc?query=", 16) == 0) {
            char *query_start = buffer + 16;
            char *query_end = strchr(query_start, ' ');
            if (query_end) {
                *query_end = 0;
                long result;
                if (parse_and_sum(query_start, &result) == 0) {
                    char response[BUFFER_SIZE];
                    snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n%ld", (long)log10(result == 0 ? 1 : result) + 1, result);
                    SSL_write(client->ssl, response, strlen(response));
                } else {
                    char *response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
                    SSL_write(client->ssl, response, strlen(response));
                }
            }
        }
    }

    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    close(client->socket_fd);
    free(client);
    printf("Client disconnected from %s\n", client_addr_str);
    return NULL;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
    }
}

int parse_and_sum(const char *query, long *result) {
    char query_copy[256];
    strncpy(query_copy, query, sizeof(query_copy) - 1);
    query_copy[sizeof(query_copy) - 1] = '\0';
    
    *result = 0;
    char *token = strtok(query_copy, "+");
    
    if (token == NULL) {
        return -1;  // クエリが空
    }
    
    while (token != NULL) {
        char *endptr;
        
        while (isspace((unsigned char)*token)) token++;
        
        long val = strtol(token, &endptr, 10);
        
        while (isspace((unsigned char)*endptr)) endptr++;
        
        if (*endptr != '\0' || endptr == token) {
            return -1;  // 無効な数値
        }
        
        *result += val;
        token = strtok(NULL, "+");
    }
    
    return 0;  // 成功
}