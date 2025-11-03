# Makefile for Secure Calculator Server and Client

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -pthread -D_REENTRANT
LDFLAGS = -lssl -lcrypto -pthread -lm

# Target executables
SERVER = secure_server
CLIENT = secure_client
TARGETS = $(SERVER) $(CLIENT)

# Source files
SERVER_SRC = secure_server.c
CLIENT_SRC = secure_client.c

# Default target - build both server and client
all: $(TARGETS)

# Build the server
$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER_SRC) $(LDFLAGS)

# Build the client
$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC) $(LDFLAGS)

# Generate SSL certificate (for development)
cert:
	@if [ -f generate_cert.sh ]; then \
		chmod +x generate_cert.sh; \
		./generate_cert.sh; \
	else \
		echo "Generating self-signed certificate..."; \
		openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
			-sha256 -days 365 -nodes \
			-subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"; \
		chmod 600 key.pem; \
		chmod 644 cert.pem; \
	fi

# Clean build artifacts
clean:
	rm -f $(TARGETS)
	rm -f *.o
	rm -f test_output.txt

# Clean everything including certificates
distclean: clean
	rm -f cert.pem key.pem

# Run the server
run-server: $(SERVER)
	@if [ ! -f cert.pem ] || [ ! -f key.pem ]; then \
		echo "Certificates not found. Generating..."; \
		$(MAKE) cert; \
	fi
	./$(SERVER)

# Run the client (default: connect to localhost)
run-client: $(CLIENT)
	./$(CLIENT)

# Run client with custom server
run-client-remote: $(CLIENT)
	@echo "Usage: make run-client-remote SERVER=<ip_address>"
	./$(CLIENT) $(SERVER)

# Build with debug symbols
debug: CFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGETS)

# Run tests
test: $(TARGETS)
	@if [ ! -f cert.pem ] || [ ! -f key.pem ]; then \
		$(MAKE) cert; \
	fi
	@if [ -f test_server.sh ]; then \
		chmod +x test_server.sh; \
		echo "Starting server for tests..."; \
		./$(SERVER) & SERVER_PID=$$!; \
		sleep 2; \
		./test_server.sh; \
		TEST_RESULT=$$?; \
		kill $$SERVER_PID 2>/dev/null || true; \
		exit $$TEST_RESULT; \
	else \
		echo "test_server.sh not found"; \
	fi

# Static analysis with clang
analyze:
	@if command -v clang >/dev/null 2>&1; then \
		clang --analyze $(SERVER_SRC); \
		clang --analyze $(CLIENT_SRC); \
	else \
		echo "clang not found. Install clang for static analysis."; \
	fi

# Check for memory leaks with valgrind
memcheck-server: $(SERVER)
	valgrind --leak-check=full --show-leak-kinds=all ./$(SERVER)

memcheck-client: $(CLIENT)
	valgrind --leak-check=full --show-leak-kinds=all ./$(CLIENT)

# Format code with clang-format
format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SERVER_SRC) $(CLIENT_SRC); \
	else \
		echo "clang-format not found."; \
	fi

# Help target
help:
	@echo "Available targets:"
	@echo "  make              - Build both server and client"
	@echo "  make secure_server - Build only the server"
	@echo "  make secure_client - Build only the client"
	@echo "  make cert         - Generate SSL certificates"
	@echo "  make run-server   - Build and run the server"
	@echo "  make run-client   - Build and run the client"
	@echo "  make test         - Run automated tests"
	@echo "  make debug        - Build with debug symbols and AddressSanitizer"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make distclean    - Remove everything including certificates"
	@echo "  make analyze      - Run static analysis"
	@echo "  make memcheck-*   - Check for memory leaks with valgrind"
	@echo "  make format       - Format code with clang-format"
	@echo "  make help         - Show this help message"

.PHONY: all clean distclean run-server run-client run-client-remote cert debug test analyze memcheck-server memcheck-client format help