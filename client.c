
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT "8080"
#define BUFFER_SIZE 1024

SSL_CTX *create_context();

int main(int argc, char *argv[]) {
    int server_fd;
    struct addrinfo hints, *res;
    char *server_ip = "127.0.0.1";
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc > 1) {
        server_ip = argv[1];
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = create_context();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(server_ip, PORT, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        exit(EXIT_FAILURE);
    }

    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (connect(server_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected to server %s:%s with SSL\n", server_ip, PORT);
        char user_input[BUFFER_SIZE];
        while (1) {
            printf("> ");
            fgets(user_input, sizeof(user_input), stdin);
            user_input[strcspn(user_input, "\n")] = 0;

            if (strlen(user_input) == 0) continue;

            char request[BUFFER_SIZE];
            if (strcmp(user_input, "exit") == 0) {
                SSL_write(ssl, "exit", strlen("exit"));
                break;
            }

            snprintf(request, sizeof(request), "GET /calc?query=%s HTTP/1.1\r\n\r\n", user_input);
            SSL_write(ssl, request, strlen(request));

            char buffer[BUFFER_SIZE];
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = 0;
                printf("Received: %s\n", buffer);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}
