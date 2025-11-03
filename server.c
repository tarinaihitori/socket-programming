#define _DEFAULT_SOURCE

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
#include <limits.h>
#include <errno.h>

#define PORT "8080"
#define BUFFER_SIZE 1024
#define MAX_QUERY_LENGTH 256
#define MAX_RESPONSE_SIZE 4096
#define MAX_CONNECTIONS 100

volatile sig_atomic_t running = 1;
static int active_connections = 0;
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

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
int get_content_length(long value);
void cleanup_client(struct client_info *client, const char *client_addr_str);
int validate_http_request(const char *buffer);

int main() {
    int server_fd;
    struct addrinfo hints, *res;
    SSL_CTX *ctx;

    // Set up signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction failed");
        exit(EXIT_FAILURE);
    }

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    ctx = create_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        exit(EXIT_FAILURE);
    }
    
    configure_context(ctx);

    // Set up server address info
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // Use wildcard IP address

    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Create socket
    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd == -1) {
        perror("socket creation failed");
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Bind socket
    if (bind(server_fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind failed");
        close(server_fd);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    // Listen for connections
    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        close(server_fd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("Secure server listening on port %s\n", PORT);
    printf("Press Ctrl+C to shutdown gracefully\n");

    // Main server loop
    while (running) {
        struct client_info *client = malloc(sizeof(struct client_info));
        if (!client) {
            perror("malloc for client_info failed");
            continue;
        }

        socklen_t client_len = sizeof(client->address);
        client->socket_fd = accept(server_fd, (struct sockaddr *)&client->address, &client_len);

        if (client->socket_fd == -1) {
            if (running && errno != EINTR) {
                perror("accept failed");
            }
            free(client);
            continue;
        }

        // Check connection limit
        pthread_mutex_lock(&conn_mutex);
        if (active_connections >= MAX_CONNECTIONS) {
            pthread_mutex_unlock(&conn_mutex);
            fprintf(stderr, "Maximum connections reached, rejecting new connection\n");
            close(client->socket_fd);
            free(client);
            continue;
        }
        active_connections++;
        pthread_mutex_unlock(&conn_mutex);

        // Set socket timeouts
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(client->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        // Set up SSL
        client->ssl = SSL_new(ctx);
        if (!client->ssl) {
            fprintf(stderr, "SSL_new failed\n");
            close(client->socket_fd);
            free(client);
            pthread_mutex_lock(&conn_mutex);
            active_connections--;
            pthread_mutex_unlock(&conn_mutex);
            continue;
        }

        SSL_set_fd(client->ssl, client->socket_fd);

        if (SSL_accept(client->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(client->ssl);
            close(client->socket_fd);
            free(client);
            pthread_mutex_lock(&conn_mutex);
            active_connections--;
            pthread_mutex_unlock(&conn_mutex);
            continue;
        }

        // Create thread to handle client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client) != 0) {
            perror("pthread_create failed");
            SSL_shutdown(client->ssl);
            SSL_free(client->ssl);
            close(client->socket_fd);
            free(client);
            pthread_mutex_lock(&conn_mutex);
            active_connections--;
            pthread_mutex_unlock(&conn_mutex);
            continue;
        }
        pthread_detach(thread_id);
    }

    printf("\nShutting down server gracefully...\n");
    
    // Wait for active connections to finish
    int wait_count = 0;
    while (active_connections > 0 && wait_count < 30) {
        sleep(1);
        wait_count++;
        printf("Waiting for %d active connections to close...\n", active_connections);
    }
    
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    pthread_mutex_destroy(&conn_mutex);
    
    printf("Server shutdown complete\n");
    return 0;
}

void *handle_client(void *arg) {
    struct client_info *client = (struct client_info *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char client_addr_str[INET6_ADDRSTRLEN];
    
    // Get client address string
    if (client->address.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&client->address;
        inet_ntop(AF_INET, &s->sin_addr, client_addr_str, sizeof(client_addr_str));
        printf("[%s:%d] Client connected\n", client_addr_str, ntohs(s->sin_port));
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client->address;
        inet_ntop(AF_INET6, &s->sin6_addr, client_addr_str, sizeof(client_addr_str));
        printf("[%s:%d] Client connected\n", client_addr_str, ntohs(s->sin6_port));
    }

    // Handle client requests
    while ((bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Basic HTTP request validation
        if (!validate_http_request(buffer)) {
            const char *response = "HTTP/1.1 400 Bad Request\r\n"
                                 "Content-Type: text/plain\r\n"
                                 "Content-Length: 11\r\n"
                                 "\r\n"
                                 "Bad Request";
            SSL_write(client->ssl, response, strlen(response));
            break;
        }
        
        printf("[%s] Received: %.100s%s\n", 
               client_addr_str, 
               buffer, 
               strlen(buffer) > 100 ? "..." : "");

        // Check for exit command
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        // Handle calculation endpoint
        if (strncmp(buffer, "GET /calc?query=", 16) == 0) {
            char *query_start = buffer + 16;
            char *query_end = strchr(query_start, ' ');
            
            if (query_end) {
                *query_end = '\0';
                
                // URL decode the query (basic implementation)
                char decoded_query[MAX_QUERY_LENGTH];
                size_t decoded_len = 0;
                for (size_t i = 0; query_start[i] && decoded_len < MAX_QUERY_LENGTH - 1; i++) {
                    if (query_start[i] == '%' && query_start[i+1] && query_start[i+2]) {
                        char hex[3] = {query_start[i+1], query_start[i+2], '\0'};
                        decoded_query[decoded_len++] = (char)strtol(hex, NULL, 16);
                        i += 2;
                    } else if (query_start[i] == '+' && query_start[i+1] != '\0') {
                        // '+' in URL means space, but we need actual '+' for our parser
                        decoded_query[decoded_len++] = '+';
                    } else {
                        decoded_query[decoded_len++] = query_start[i];
                    }
                }
                decoded_query[decoded_len] = '\0';
                
                long result;
                if (parse_and_sum(decoded_query, &result) == 0) {
                    char response[MAX_RESPONSE_SIZE];
                    char result_str[32];
                    snprintf(result_str, sizeof(result_str), "%ld", result);
                    int content_length = strlen(result_str);
                    
                    snprintf(response, sizeof(response), 
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: %d\r\n"
                            "Cache-Control: no-cache\r\n"
                            "\r\n"
                            "%s", 
                            content_length, result_str);
                    SSL_write(client->ssl, response, strlen(response));
                } else {
                    const char *response = "HTTP/1.1 400 Bad Request\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 22\r\n"
                                         "\r\n"
                                         "Invalid query format";
                    SSL_write(client->ssl, response, strlen(response));
                }
            }
        } else if (strncmp(buffer, "GET / ", 6) == 0) {
            // Handle root path
            const char *response = "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: 145\r\n"
                                 "\r\n"
                                 "<html><body><h1>Calculator Server</h1>"
                                 "<p>Usage: GET /calc?query=number1+number2+...</p>"
                                 "<p>Example: /calc?query=10+20+30</p>"
                                 "</body></html>";
            SSL_write(client->ssl, response, strlen(response));
        } else {
            // 404 for other paths
            const char *response = "HTTP/1.1 404 Not Found\r\n"
                                 "Content-Type: text/plain\r\n"
                                 "Content-Length: 9\r\n"
                                 "\r\n"
                                 "Not Found";
            SSL_write(client->ssl, response, strlen(response));
        }
    }

    if (bytes_read < 0) {
        int ssl_error = SSL_get_error(client->ssl, bytes_read);
        if (ssl_error != SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "[%s] SSL read error: %d\n", client_addr_str, ssl_error);
        }
    }

    cleanup_client(client, client_addr_str);
    return NULL;
}

void cleanup_client(struct client_info *client, const char *client_addr_str) {
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    close(client->socket_fd);
    free(client);
    
    pthread_mutex_lock(&conn_mutex);
    active_connections--;
    pthread_mutex_unlock(&conn_mutex);
    
    printf("[%s] Client disconnected (active connections: %d)\n", 
           client_addr_str, active_connections);
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use modern TLS method instead of deprecated SSLv23
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set minimum TLS version to 1.2 for security
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Configure cipher suites (use strong ciphers only)
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4:!3DES");
    
    // Disable SSL compression (CRIME attack mitigation)
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate from cert.pem\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading private key from key.pem\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Verify that the key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
        printf("\nReceived shutdown signal...\n");
    }
}

int validate_http_request(const char *buffer) {
    // Basic validation: check if it starts with a valid HTTP method
    if (strncmp(buffer, "GET ", 4) != 0 && 
        strncmp(buffer, "POST ", 5) != 0 &&
        strncmp(buffer, "exit", 4) != 0) {
        return 0;
    }
    
    // Check for basic HTTP structure
    if (strstr(buffer, " HTTP/") == NULL && strncmp(buffer, "exit", 4) != 0) {
        return 0;
    }
    
    return 1;
}

int parse_and_sum(const char *query, long *result) {
    if (!query || !result) {
        return -1;
    }
    
    // Create a copy of the query to work with
    char query_copy[MAX_QUERY_LENGTH];
    strncpy(query_copy, query, sizeof(query_copy) - 1);
    query_copy[sizeof(query_copy) - 1] = '\0';
    
    *result = 0;
    char *saveptr;
    char *token = strtok_r(query_copy, "+", &saveptr);
    
    if (token == NULL) {
        return -1;  // Empty query
    }
    
    while (token != NULL) {
        char *endptr;
        
        // Skip leading whitespace
        while (isspace((unsigned char)*token)) token++;
        
        // Check for empty token
        if (*token == '\0') {
            return -1;
        }
        
        // Parse the number
        errno = 0;
        long val = strtol(token, &endptr, 10);
        
        // Check for conversion errors
        if (errno == ERANGE) {
            return -1;  // Number out of range
        }
        
        // Skip trailing whitespace
        while (isspace((unsigned char)*endptr)) endptr++;
        
        // Check if entire token was consumed
        if (*endptr != '\0' || endptr == token) {
            return -1;  // Invalid number format
        }
        
        // Check for overflow when adding
        if ((val > 0 && *result > LONG_MAX - val) ||
            (val < 0 && *result < LONG_MIN - val)) {
            return -1;  // Overflow would occur
        }
        
        *result += val;
        token = strtok_r(NULL, "+", &saveptr);
    }
    
    return 0;  // Success
}

int get_content_length(long value) {
    if (value == 0) return 1;
    if (value < 0) {
        // Account for negative sign
        value = -value;
        int digits = 1;  // For the minus sign
        while (value > 0) {
            digits++;
            value /= 10;
        }
        return digits;
    }
    int digits = 0;
    while (value > 0) {
        digits++;
        value /= 10;
    }
    return digits;
}