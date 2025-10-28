#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char *buffer = NULL; 
    
    // バッファを動的に確保
    buffer = (char *)calloc(BUFFER_SIZE, sizeof(char));
    if (buffer == NULL) {
        perror("calloc failed");
        exit(EXIT_FAILURE);
    }
    
    // ソケットの作成
    //TCPの場合は、domain=AF_INET、type=SOCK_STREAM、protocol=0を指定する。
    //UDPの場合は、domain=AF_INET、type=SOCK_DGRAM、protocol=0を指定する。
    server_fd = socket(AF_INET, SOCK_STREAM, 0)
    //エラー時は-1が返ってくるとドキュメントに書いてあるため-1と比較している。
    //https://man7.org/linux/man-pages/man2/socket.2.html#:~:text=and%20get%20options.-,RETURN%20VALUE,-top
    if (server_fd == -1) {
        perror("socket creaing failed");
        free(buffer);  // メモリ解放
        exit(EXIT_FAILURE);
    }
    
    // ソケットオプションの設定(アドレスの再利用を許可)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        free(buffer);  // メモリ解放
        exit(EXIT_FAILURE);
    }
    
    // サーバーアドレスの設定
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // ソケットにアドレスをバインド
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        close(server_fd);
        free(buffer);  // メモリ解放
        exit(EXIT_FAILURE);
    }
    
    // 接続待ち受け開始
    if (listen(server_fd, 5) == -1) {
        perror("listen failed");
        close(server_fd);
        free(buffer);  // メモリ解放
        exit(EXIT_FAILURE);
    }
    
    printf("サーバーがポート %d で起動しました\n", PORT);
    printf("クライアントからの接続を待っています...\n");
    
    // クライアントからの接続を受け入れ
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) == -1) {
        perror("accept failed");
        close(server_fd);
        free(buffer);  // メモリ解放
        exit(EXIT_FAILURE);
    }
    
    printf("クライアント(%s:%d)が接続しました\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));
    
    // クライアントとの通信ループ
    while (1) {
        // バッファをゼロクリア
        memset(buffer, 0, BUFFER_SIZE);
        
        // クライアントからメッセージを受信
        int bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            printf("クライアントが切断しました\n");
            break;
        }
        
        printf("受信 (%d bytes): %s", bytes_read, buffer);
        
        // "exit"が送られてきたら終了
        if (strncmp(buffer, "exit", 4) == 0) {
            printf("終了コマンドを受信しました\n");
            break;
        }
        
        // エコーバック(受信したメッセージをそのまま返す)
        send(client_fd, buffer, bytes_read, 0);
    }
    
    // リソースのクリーンアップ
    close(client_fd);
    close(server_fd);
    free(buffer);  
    
    printf("メモリを解放しました\n");
    printf("サーバーを終了します\n");
    return 0;
}