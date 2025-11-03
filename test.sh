#!/bin/bash

# Exit on error
set -e

# Build the project
make

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=JP/ST=Tokyo/L=Tokyo/O=Gemini/OU=Gemini/CN=localhost"

# Run server in the background
./server &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test IPv4
echo "Testing IPv4..."
echo "1+2+3" | ./client 127.0.0.1 > test_output_ipv4.txt
cat test_output_ipv4.txt
grep "Received: HTTP/1.1 200 OK" test_output_ipv4.txt
grep "6" test_output_ipv4.txt

# Test IPv6
echo "Testing IPv6..."
echo "1+2+3" | ./client ::1 > test_output_ipv6.txt
cat test_output_ipv6.txt
grep "Received: HTTP/1.1 200 OK" test_output_ipv6.txt
grep "6" test_output_ipv6.txt

# Test graceful shutdown
echo "Testing graceful shutdown..."
kill -SIGINT $SERVER_PID
sleep 3
if ps -p $SERVER_PID > /dev/null; then
   echo "Server did not shut down gracefully."
   exit 1
else
   echo "Server shut down gracefully."
fi

# Clean up
rm -f key.pem cert.pem test_output_ipv4.txt test_output_ipv6.txt

echo "All tests passed!"
