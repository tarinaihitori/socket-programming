#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = {0};
    char send_buffer[BUFFER_SIZE] = {0};
    char *server_ip = "127.0.0.1";
    
    // コマンドライン引数でサーバーIPを指定可能
    if (argc > 1) {
        server_ip = argv[1];
    }
    
    // ソケットの作成
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // サーバーアドレスの設定
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // IPアドレスの変換
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // サーバーに接続
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("接続に失敗しました");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("サーバー(%s:%d)に接続しました\n", server_ip, PORT);
    printf("メッセージを入力してください(終了するには 'exit' を入力):\n");
    
    // 通信ループ
    while (1) {
        printf("> ");
        fflush(stdout);
        
        // ユーザー入力を取得
        if (fgets(send_buffer, BUFFER_SIZE, stdin) == NULL) {
            break;
        }
        
        // サーバーにメッセージを送信
        send(client_fd, send_buffer, strlen(send_buffer), 0);
        
        // "exit"が入力されたら終了
        if (strncmp(send_buffer, "exit", 4) == 0) {
            printf("終了します\n");
            break;
        }
        
        // サーバーからの応答を受信
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = read(client_fd, buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            printf("サーバーが切断されました\n");
            break;
        }
        
        printf("サーバーからの応答: %s", buffer);
    }
    
    // ソケットのクローズ
    close(client_fd);
    
    return 0;
}
