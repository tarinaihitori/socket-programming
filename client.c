#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>

#define PORT "8080"
#define BUFFER_SIZE 4096
#define MAX_INPUT_SIZE 1024

// ANSI color codes for better UI
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

typedef struct {
    int socket_fd;
    SSL_CTX *ctx;
    SSL *ssl;
    char server_addr[INET6_ADDRSTRLEN];
    int connected;
} client_context_t;

// Function prototypes
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
int connect_to_server(client_context_t *client, const char *server_ip, const char *port);
void print_banner();
void print_help();
int parse_http_response(const char *response, char **body);
char *url_encode(const char *input);
void signal_handler(int sig);
void cleanup_client(client_context_t *client);

volatile sig_atomic_t running = 1;

int main(int argc, char *argv[]) {
    client_context_t client = {0};
    char *server_ip = "127.0.0.1";
    char *port = PORT;
    
    // Parse command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Usage: %s [server_ip] [port]\n", argv[0]);
            printf("Default: %s 127.0.0.1 8080\n", argv[0]);
            return 0;
        }
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = argv[2];
    }

    // Set up signal handler for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    // Create SSL context
    client.ctx = create_context();
    if (!client.ctx) {
        fprintf(stderr, COLOR_RED "Failed to create SSL context\n" COLOR_RESET);
        return 1;
    }
    configure_context(client.ctx);

    print_banner();
    
    // Connect to server
    printf(COLOR_BLUE "Connecting to %s:%s...\n" COLOR_RESET, server_ip, port);
    if (connect_to_server(&client, server_ip, port) != 0) {
        fprintf(stderr, COLOR_RED "Failed to connect to server\n" COLOR_RESET);
        cleanup_client(&client);
        return 1;
    }
    
    printf(COLOR_GREEN "✓ Connected successfully with %s encryption\n" COLOR_RESET, 
           SSL_get_cipher(client.ssl));
    
    // Print SSL/TLS version
    printf(COLOR_GREEN "✓ Protocol: %s\n" COLOR_RESET, 
           SSL_get_version(client.ssl));
    
    print_help();
    
    // Main interaction loop
    char user_input[MAX_INPUT_SIZE];
    while (running && client.connected) {
        printf("\n" COLOR_YELLOW "calc> " COLOR_RESET);
        fflush(stdout);
        
        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            if (errno == EINTR) continue;
            break;
        }
        
        // Remove newline
        user_input[strcspn(user_input, "\n")] = '\0';
        
        // Skip empty input
        if (strlen(user_input) == 0) continue;
        
        // Handle special commands
        if (strcmp(user_input, "exit") == 0 || strcmp(user_input, "quit") == 0) {
            printf("Closing connection...\n");
            SSL_write(client.ssl, "exit", 4);
            break;
        } else if (strcmp(user_input, "help") == 0) {
            print_help();
            continue;
        } else if (strcmp(user_input, "status") == 0) {
            printf("Server: %s:%s\n", server_ip, port);
            printf("Connection: %s\n", client.connected ? "Active" : "Inactive");
            printf("Cipher: %s\n", SSL_get_cipher(client.ssl));
            printf("Protocol: %s\n", SSL_get_version(client.ssl));
            continue;
        } else if (strncmp(user_input, "test", 4) == 0) {
            // Run test calculations
            const char *tests[] = {
                "10+20",
                "100+200+300",
                "1000+-500",
                "5+5+5+5+5",
                "42"
            };
            printf("Running test calculations...\n");
            for (int i = 0; i < 5; i++) {
                char request[BUFFER_SIZE];
                char *encoded = url_encode(tests[i]);
                snprintf(request, sizeof(request), 
                        "GET /calc?query=%s HTTP/1.1\r\n"
                        "Host: %s:%s\r\n"
                        "User-Agent: SecureCalcClient/1.0\r\n"
                        "Connection: keep-alive\r\n"
                        "\r\n", 
                        encoded, server_ip, port);
                free(encoded);
                
                SSL_write(client.ssl, request, strlen(request));
                
                char buffer[BUFFER_SIZE];
                int bytes = SSL_read(client.ssl, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    char *body = NULL;
                    int status = parse_http_response(buffer, &body);
                    if (status == 200 && body) {
                        printf("  %s = %s\n", tests[i], body);
                    }
                }
            }
            continue;
        }
        
        // Check if input is a calculation expression
        int is_calc = 0;
        for (int i = 0; user_input[i]; i++) {
            if (user_input[i] == '+' || user_input[i] == '-' || isdigit(user_input[i]) || isspace(user_input[i])) {
                is_calc = 1;
            } else {
                is_calc = 0;
                break;
            }
        }
        
        if (!is_calc) {
            printf(COLOR_RED "Invalid expression. Use format: number1+number2+...\n" COLOR_RESET);
            printf("Examples: 10+20, 100+-50, 5+5+5\n");
            continue;
        }
        
        // URL encode the query
        char *encoded_query = url_encode(user_input);
        
        // Build HTTP request
        char request[BUFFER_SIZE];
        snprintf(request, sizeof(request), 
                "GET /calc?query=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "User-Agent: SecureCalcClient/1.0\r\n"
                "Connection: keep-alive\r\n"
                "\r\n", 
                encoded_query, server_ip, port);
        
        free(encoded_query);
        
        // Send request
        int sent = SSL_write(client.ssl, request, strlen(request));
        if (sent <= 0) {
            int ssl_error = SSL_get_error(client.ssl, sent);
            fprintf(stderr, COLOR_RED "Failed to send request (SSL error: %d)\n" COLOR_RESET, ssl_error);
            client.connected = 0;
            continue;
        }
        
        // Read response
        char buffer[BUFFER_SIZE];
        int bytes = SSL_read(client.ssl, buffer, sizeof(buffer) - 1);
        
        if (bytes > 0) {
            buffer[bytes] = '\0';
            
            // Parse HTTP response
            char *body = NULL;
            int status_code = parse_http_response(buffer, &body);
            
            if (status_code == 200 && body) {
                printf(COLOR_GREEN "Result: %s\n" COLOR_RESET, body);
            } else if (status_code == 400) {
                printf(COLOR_RED "Error: Invalid query format\n" COLOR_RESET);
            } else if (status_code == 404) {
                printf(COLOR_RED "Error: Endpoint not found\n" COLOR_RESET);
            } else {
                printf(COLOR_RED "Error: Server returned status %d\n" COLOR_RESET, status_code);
                if (body) {
                    printf("Message: %s\n", body);
                }
            }
        } else if (bytes == 0) {
            printf(COLOR_YELLOW "Server closed connection\n" COLOR_RESET);
            client.connected = 0;
        } else {
            int ssl_error = SSL_get_error(client.ssl, bytes);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                fprintf(stderr, COLOR_RED "Failed to read response (SSL error: %d)\n" COLOR_RESET, ssl_error);
                client.connected = 0;
            }
        }
    }
    
    printf("\nGoodbye!\n");
    cleanup_client(&client);
    return 0;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use modern TLS client method
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Configure cipher suites (use strong ciphers only)
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4:!3DES");
    
    // Disable SSL compression
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // For self-signed certificates in development, skip verification
    // WARNING: Remove this in production!
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    // In production, you would load CA certificates:
    // SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

int connect_to_server(client_context_t *client, const char *server_ip, const char *port) {
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(server_ip, port, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }
    
    client->socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (client->socket_fd < 0) {
        perror("socket creation failed");
        freeaddrinfo(res);
        return -1;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(client->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(client->socket_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect failed");
        close(client->socket_fd);
        freeaddrinfo(res);
        return -1;
    }
    
    // Store server address for display
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), client->server_addr, INET6_ADDRSTRLEN);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), client->server_addr, INET6_ADDRSTRLEN);
    }
    
    freeaddrinfo(res);
    
    // Create SSL connection
    client->ssl = SSL_new(client->ctx);
    if (!client->ssl) {
        fprintf(stderr, "SSL_new failed\n");
        close(client->socket_fd);
        return -1;
    }
    
    SSL_set_fd(client->ssl, client->socket_fd);
    
    if (SSL_connect(client->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(client->ssl);
        close(client->socket_fd);
        return -1;
    }
    
    client->connected = 1;
    return 0;
}

void print_banner() {
    printf("\n");
    printf(COLOR_BLUE "╔════════════════════════════════════════╗\n");
    printf("║     Secure Calculator Client v1.0      ║\n");
    printf("╚════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
}

void print_help() {
    printf("\n" COLOR_YELLOW "Commands:\n" COLOR_RESET);
    printf("  Expression  : Enter a calculation (e.g., 10+20, 100+-50)\n");
    printf("  help        : Show this help message\n");
    printf("  test        : Run test calculations\n");
    printf("  status      : Show connection status\n");
    printf("  exit/quit   : Close connection and exit\n");
    printf("\n" COLOR_YELLOW "Examples:\n" COLOR_RESET);
    printf("  10+20       : Adds 10 and 20\n");
    printf("  100+-50     : Subtracts 50 from 100\n");
    printf("  5+5+5+5     : Adds multiple numbers\n");
}

int parse_http_response(const char *response, char **body) {
    int status_code = 0;
    
    // Parse status line
    if (sscanf(response, "HTTP/%*[^ ] %d", &status_code) != 1) {
        return -1;
    }
    
    // Find body (after \r\n\r\n)
    const char *body_start = strstr(response, "\r\n\r\n");
    if (body_start) {
        body_start += 4;  // Skip \r\n\r\n
        if (body && *body_start) {
            *body = (char *)body_start;
        }
    }
    
    return status_code;
}

char *url_encode(const char *input) {
    size_t len = strlen(input);
    char *encoded = malloc(len * 3 + 1);  // Worst case: every char needs encoding
    if (!encoded) return NULL;
    
    char *p = encoded;
    for (size_t i = 0; i < len; i++) {
        if (isalnum((unsigned char)input[i]) || input[i] == '-' || input[i] == '_' || 
            input[i] == '.' || input[i] == '~') {
            *p++ = input[i];
        } else if (input[i] == ' ') {
            *p++ = '+';
        } else if (input[i] == '+') {
            // Keep '+' as is for our calculator
            *p++ = '+';
        } else {
            sprintf(p, "%%%02X", (unsigned char)input[i]);
            p += 3;
        }
    }
    *p = '\0';
    
    return encoded;
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
        printf("\n\nReceived interrupt signal. Shutting down...\n");
    }
}

void cleanup_client(client_context_t *client) {
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    if (client->socket_fd > 0) {
        close(client->socket_fd);
    }
    if (client->ctx) {
        SSL_CTX_free(client->ctx);
    }
    EVP_cleanup();
}