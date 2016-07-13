/*
    Proof of concept code for BMP steganography server.
    (This code is a mess, i don't care.)
    rm -rf send_* && gcc -o send_file file_send.c -lssl -lcrypto && ./send_file [filename]
*/
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define SERVER "127.0.0.1"
#define PORT 1337
#define TIMEOUT 5
#define CIPHERS "HIGH:+MEDIUM:!aNULL:!eNULL:!3DES:!RC4:!RC2!DES"

SSL_CTX *initCTX(void){
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_cipher_list(ctx, CIPHERS);
    if(!ctx){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void DestroySSL(){
    ERR_free_strings();
    EVP_cleanup();
}

void ShutdownSSL(SSL *ssl){
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void ShowCerts(SSL *ssl){
    X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if(cert != NULL){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}


int main(int argc, char **argv){
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = TIMEOUT;
    if(argc != 2){
        fprintf(stderr, "Usage is: %s [filename]\n", argv[0]);
        return -1;
    }
    
    char buff[1024];
    struct stat fileStat;
    char *filename = argv[1];
    
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_library_init();
    
    if(stat(filename, &fileStat) < 0){
        fprintf(stderr, "Cannot get stats for input file.\n");
        return -1;
    }
    
//    printf("File size: %d\n", fileStat.st_size);
    long fs = htonl(fileStat.st_size);

    FILE *IN = fopen(filename, "r");
    FILE *OUT = fopen("send_enc.enc", "w+");
    FILE *OUT_DEC = fopen("send_enc.dec", "w+");
    
    if(IN <= 0 || OUT <= 0 || OUT_DEC <= 0){
        fprintf(stderr, "Error opening file.\n");
        return -1;
    }

    int sock;
    int true = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
    
    struct sockaddr_in server;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(SERVER);
    server.sin_port = htons(PORT);
    
    if(connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0){
        puts("Cannot connect to server.");
        return -1;
    }
    
    ctx = initCTX();
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    
    if(SSL_connect(ssl) == -1)
        ShutdownSSL(ssl);
        
    long enc = htonl(1);
    SSL_write(ssl, &enc, 6);
    
    // Send file size to socket.
    SSL_write(ssl, &fs, sizeof(fs));
    puts("Sending file.");
    
    int x = 0;
    while((x=fread(&buff, 1, 1, IN)) > 0)
        SSL_write(ssl, &buff, 1);
    puts("File sent.");
        
    puts("Recv. ciphertext.");
    // Make temp file to recv enc. file on.
    while((x=SSL_read(ssl, &buff, 1024)) > 0)
        fwrite(&buff, x, 1, OUT);

    puts("Done.");
    ShutdownSSL(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    ctx = initCTX();
    ssl = SSL_new(ctx);
    
    // Seek to begining of the file.
    fseek(OUT, 0, SEEK_SET);
    puts("Decrypting file.");
    
    if(stat("send_enc.enc", &fileStat) < 0){
        fprintf(stderr, "Cannot get stats for input file.\n");
        return -1;
    }
    
    int sock2;
    sock2 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(SERVER);
    server.sin_port = htons(PORT);

    if(connect(sock2, (struct sockaddr *) &server, sizeof(server)) < 0){
        puts("Cannot connect to server.");
        return -1;
    }
    
    SSL_set_fd(ssl, sock2);
    if(SSL_connect(ssl) < 0)
        ShutdownSSL(ssl);

    fs = htonl(fileStat.st_size);
    puts("Sending flag and size.");
    enc = htonl(0);

    SSL_write(ssl, &enc, 6); // Send dec flag.
    SSL_write(ssl, &fs, sizeof(fs)); // Send file size.
    puts("Sending file.");
    
    x = 0;
    int n = 0;
    fread(buff, 1, 54, OUT);
    SSL_write(ssl, &buff, 54);
    
    while((x=fread(buff, 1, 344, OUT)) > 0)
        SSL_write(ssl, &buff, 344);
        
    puts("File sent.");
        
    puts("Recv. plaintext.");
    // Make temp file to recv enc. file on.
    while((x=SSL_read(ssl, buff, 256)) > 0)
        fwrite(&buff, x, 1, OUT_DEC);
    puts("Dec write done.");
    
    fclose(IN);
    fclose(OUT);
    fclose(OUT_DEC);
    close(sock2);
    
    ShutdownSSL(ssl);
    close(sock2);
    SSL_CTX_free(ctx);
    DestroySSL();
    return 0;
}
