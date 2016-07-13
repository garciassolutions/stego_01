/*
    Copyright (c) 2016, Three Stone Solutions
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    BMP Steganography Server v3.0
    Written by nue - irc.oftc.net #nerds

    openssl genrsa -des3 -out server.key 2048
    openssl rsa -in server.key -out server.key
    openssl req -sha256 -new -key server.key -out server.csr -subj '/CN=localhost'
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
    cat server.crt server.key > test.pem
    
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -out public.pem -outform PEM -pubout
    
    gcc -lssl -lpthread -lc -lcrypto -o ldn ldn.c && ./ldn
    
    TODO:
        . Generate key pairs, return public keys. Ask for public keys on decode???
        . Add mp3 stegano methods.
        . Have decrypt MAX_FILESIZE account for embedding length?
        . Correct filenames for disc I/O
*/
#include <math.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <signal.h>
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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define MAX_THREADS 16 // Max threads to be used.
#define MAX_CONNECTIONS 8 // Max connections the server will handle.
#define TIMEOUT 3 // Seconds to time out, and disregard data.
#define DEFAULT_PORT 1337
#define MAX_FILESIZE 4096
#define BLOCK_SIZE 256
#define JUMBLE_SIZE 344
#define PUB_KEY "public.pem"
#define PRI_KEY "private.pem"
#define CIPHERS "HIGH:+MEDIUM:!aNULL:!eNULL:!3DES:!RC4:!RC2!DES" 

// Some shit...
void usage(char *);
void int_catch(int);
void handle_client(SSL *);
void swap(unsigned char *, unsigned char *);
void *thread_main(void *);
void unjumble(unsigned char [][8], int);
void jumble(unsigned char [][8], int);
void die_with_err(char *, int, int);

char *RSA_BUFF; // For RSA encoding/decoding.
struct timeval tv; // For socket timeouts.
int sock, port = DEFAULT_PORT;

struct threadArgs { SSL *socket; };

struct bitmap_DIB_header{ // Windows BITMAPINFOHEADER
    int size;
    int width;
    int height;
    short planes;
    short bytes_per_pix;
    int method;
    int img_size;
    int hor_rez;
    int ver_rez;
    int palette;
    int important;
};

struct bitmap_header {
    char pad[2]; // Bullshit padding.
    char h1;
    char h2;
    unsigned int size; // The size of the BMP file in bytes.
    int reserved; // Reserved noise.
    int offset; // Starting address of the byte where the bitmap image data (pixel array) can be found.
};

RSA *createRSAWithFilename(char *filename, int public){
    FILE *fp = fopen(filename, "rb"); 
    if(fp == NULL){
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;    
    }
    RSA *rsa = RSA_new();
    if(public)
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    return rsa;
}

SSL_CTX *InitializeSSL(void){
    SSL_CTX *ctx;    
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_cipher_list(ctx, CIPHERS);
    if(!ctx){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void loadCerts(SSL_CTX *ctx, char *CertFile, char *KeyFile){
    int x=0;
    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();
    }
    if(!SSL_CTX_check_private_key(ctx)){
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShutdownSSL(SSL *ssl){
    SSL_shutdown(ssl);
    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
    ERR_print_errors_fp(stderr);
    ERR_free_strings();
    EVP_cleanup();
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *filename, unsigned char *decrypted, int pad){
    RSA *rsa = createRSAWithFilename(filename, 0);
    int result;
    if(pad)
        result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
    else
        result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_NO_PADDING);
    return result;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *filename, unsigned char *encrypted, int pad){
    RSA *rsa = createRSAWithFilename(filename, 1);
    int result;
    if(pad)
        result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
    else
        result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_NO_PADDING);
    return result;
} 

int main(int argc, char **argv){
    SSL_library_init();
    SSL_CTX *ctx;
    int opt, sock, output=0;
    struct sockaddr_in localhost;
    struct threadArgs *threadData; // Thread argument data.
    pthread_t threadID;
    
    tv.tv_usec = 0;
    tv.tv_sec = TIMEOUT; // Socket timeout on recv() or send()
    
    while((opt = getopt(argc, argv, "p:h")) != -1)
        switch(opt){
            case 'p': port = atoi(optarg); break;
            case 'h': usage(argv[0]);
            default: break;
        }

    signal(SIGINT, int_catch); // SIGINT handler.

    ctx = InitializeSSL(); /* Initialize SSL */
    loadCerts(ctx, "test.pem", "test.pem");
        
    // Setup server to listen for connections.
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
    
    memset(&localhost, 0, sizeof(localhost));
    localhost.sin_family = AF_INET;
    localhost.sin_addr.s_addr = htonl(INADDR_ANY);
    localhost.sin_port = htons(port);
    
    if(bind(sock, (struct sockaddr *) &localhost, sizeof(localhost)) < 0) // Gimme a socket!
        die_with_err("Cannot bind socket.", 0, 1);
    
    if(listen(sock, MAX_CONNECTIONS) < 0) // Listen on host.
        die_with_err("Socket unable to listen.", 0, 1);

    unsigned int local_size = sizeof(localhost);
    
    for(;;){ // Handle connections.
        int client;
        SSL *ssl;
        
        if((client = accept(sock, (struct sockaddr *) &localhost, &local_size)) < 0) // Accept an incoming connection.
            die_with_err("Cannot accept new socket.", 0, 0);
        else if((threadData = (struct threadArgs *) malloc(sizeof(struct threadArgs))) == NULL)
            die_with_err("malloc() failed.", client, 0);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        threadData -> socket = ssl;
        pthread_t threadID;
        if(pthread_create(&threadID, NULL, thread_main, (void *)threadData) != 0)
            die_with_err("pthread_create() failed.", client, 0);
    }
    return 0;
}

void usage(char *prog){
    fprintf(stderr, "Usage is: %s (-p PORT)\n", prog);
    fputs("-p : Port number.\n", stderr);
}

void *thread_main(void *args){
    SSL *clientSock;
    pthread_detach(pthread_self());
    clientSock = ((struct threadArgs *) args) -> socket;
    handle_client(clientSock);
    return NULL;
}

void handle_client(SSL *client){
    long enc_type=0, file_size=0;
    int x=0, y=0;
    unsigned long ttl_recv = 0;
    unsigned char buff[BLOCK_SIZE] = {0}, ciphertext[2048/8], xor_key;
    
    if(SSL_accept(client) == -1) // See if a connection can be accepted.
        ShutdownSSL(client);
        
    if(SSL_read(client, &enc_type, sizeof(enc_type)) < 0) // Read in encode/decode flag.
        ShutdownSSL(client);
    enc_type = ntohl(enc_type);
    
    SSL_read(client, &file_size, sizeof(file_size)); // Get the filesize
    file_size = ntohl(file_size);
    
    // Check if filesize is > MAX_FILESIZE, die if it is here.
    if(file_size > MAX_FILESIZE){
        die_with_err("Filesize too large.", 0, 0);
        ShutdownSSL(client);
    }

    srand(time(NULL)); // Seed random function w. time.
    
    if(enc_type >= 1){
        unsigned char *hackrf = malloc(BLOCK_SIZE); // HackRF buffer.
        int ttl_wrote = 0, counter=0;
        struct bitmap_header BMH = {0}; // Header for output file.
        struct bitmap_DIB_header BDH = {0}; // Fill the rest in after img read.
        BMH.reserved = 0;

        if(hackrf == NULL){
            die_with_err("Cannot malloc.", 0, 0);
            ShutdownSSL(client);
        }
        
        FILE *TMP_OUT = fopen("tmp.enc", "w+"); // Change the filename to allow more then one thread. JUST TESTING!!
        // MAKE SURE FILES ARE OPENED CORRECTLY?!

        while((SSL_read(client, hackrf+counter, 1) > 0) && ttl_recv <= file_size){
            if(++ttl_recv > MAX_FILESIZE){
                die_with_err("Filesize too large.", 0, 0);
                ShutdownSSL(client);
            }
            if(++counter==BLOCK_SIZE){ // The block size was reached.
                int enc_len = public_encrypt(hackrf, counter, PUB_KEY, ciphertext, 0);
                if(enc_len == -1){
                    die_with_err("Error encrypting data.", 0, 0);
                    ShutdownSSL(client);
                }
                ttl_wrote += enc_len;
                fwrite(ciphertext, enc_len, 1, TMP_OUT); // Write to temp file.
                counter ^= counter;
                memset(hackrf, 0, BLOCK_SIZE);
            }
        }

        if(counter && counter != BLOCK_SIZE){ // Padding is needed when block size alignment isn't reached.
            BMH.reserved = 1; // Set padding byte in BMP reserved header field.
            if(public_encrypt(hackrf, counter, PUB_KEY, ciphertext, 1) == -1) // Will always return block_size on encode?
                ShutdownSSL(client);
            ttl_wrote += BLOCK_SIZE;
            fwrite(ciphertext, BLOCK_SIZE, 1, TMP_OUT); // Write to temp file.
        }

        // Hide in bmp
        fseek(TMP_OUT, 0, SEEK_SET); // Seek to begining of file for read.        
        int img_size = ceil(ttl_wrote/6.0)*8; // 1 byte per pixel. (MAKE SURE THIS WONT OVERFLOW INT SIZE?)
        img_size += 54; // BMP and DIB header size.
        
        BMH.h1 = 'B';
        BMH.h2 = 'M';
        BMH.size = img_size;
        BMH.offset = 54;
        
        img_size -= 54; // Get rid of header size.
        
        BDH.size = 40;
        BDH.width = 8;
        BDH.height = (ttl_wrote/8)/8; // Change this to reflect 344 bytes?
        BDH.planes = 1;
        BDH.bytes_per_pix = 24;
        BDH.method = 0;
        BDH.img_size = img_size;
        BDH.hor_rez = 2835;
        BDH.ver_rez = 2835;
        BDH.palette = 0;
        BDH.important = 0;
        
        // Write bmp header information to the socket.
        SSL_write(client, &BMH.h1, 14);
        SSL_write(client, &BDH, sizeof(BDH));
        
        while(fread(hackrf, 1, BLOCK_SIZE, TMP_OUT) > 0){
            counter ^= counter;
            unsigned char jumbled_data[43][8] = {0};
            for(x=0;x<42;x++){ // Flatten the array.
                xor_key = rand()%255;
                for(y=0;y<6;y++)
                    jumbled_data[x][y] = (hackrf[counter++]^xor_key);
                jumbled_data[x][6] = x;
                jumbled_data[x][7] = xor_key;
            }
            xor_key = rand()%255;
            for(x=0;x<4;x++) // 42*6 = 252
                jumbled_data[42][x] = (hackrf[counter++]^xor_key);
            jumbled_data[42][4] = rand()%255; // Padding byte for alignment.
            jumbled_data[42][5] = rand()%255; // Padding byte for alignment.
            jumbled_data[42][6] = 42;
            jumbled_data[42][7] = xor_key;
            
            jumble(jumbled_data, 43); // Reorder the list.
            SSL_write(client, jumbled_data, 344); // Write data to SSL.
        }
        fclose(TMP_OUT);
        free(hackrf); // Give memory back to system.
        
        // Delete tmp_out file also. MAKE SURE NO RACE CONDITION / NAME CONFLICT
        remove("tmp.enc"); // Remove temp file. FIX FILENAMES, THIS IS JUST FOR TESTING!
        
        puts("Enc. complete.");        
    }

    /*** DECRYPTION ***/ 
    else{
        unsigned char decrypted[4096];
        struct bitmap_header client_header = {0};
        for(x=0;x<54;x++) // Read in BMP headers.
            SSL_read(client, buff+x, 1);
        memcpy(&client_header.h1, buff, 14);
        
        unsigned char jumbled_ciphertext[43][8] = {0};
        int n = 0;
        // AND ttl_recv < MAX_FILE_SIZE
        while(SSL_read(client, jumbled_ciphertext, 344) > 0){
            ttl_recv+=344;
            unjumble(jumbled_ciphertext, 43);
            for(x=0;x<43;x++)
                for(y=0;y<6;y++)
                    if(x != 42 || y < 4)
                        buff[(x*6)+y] = (jumbled_ciphertext[x][y] ^ jumbled_ciphertext[x][7]);
            int dec = 0;
            if(ttl_recv == client_header.size-54 && client_header.reserved) // Padding is needed.
                dec = private_decrypt(buff, BLOCK_SIZE, PRI_KEY, decrypted, 1);
            else
                dec = private_decrypt(buff, BLOCK_SIZE, PRI_KEY, decrypted, 0); // There is no padding.
            if(dec > 0)
                SSL_write(client, decrypted, dec); // Send decrypted data to the client.
            else{
                ERR_load_crypto_strings();
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        puts("Dec. complete.");
    }
    ShutdownSSL(client);
}

void die_with_err(char *err, int s, int die){
    fprintf(stderr, "[!] Thread died: %s\n", err);
    if(s)
        close(s);
    if(sock)
        close(sock); // Close main socket.
    if(die)
        exit(-1); // End program.
}

void swap(unsigned char *a, unsigned char *b){
    int column;
    for(column=0;column<8;column++){
        unsigned char tmp = a[column];
        a[column] = b[column];
        b[column] = tmp;
    }
}

void unjumble(unsigned char arr[][8], int size){
    int x;
    unsigned char y;
    for(y=0;y<size;y++)
        for(x=y+1;x<size;x++)
            if(arr[x][6] == y){
                swap(&arr[y], &arr[x]);
                break;
            }
}

void jumble(unsigned char arr[][8], int size){ // Jumble up the offsets when encrypting.
    srand(time(NULL));
    int x = size-1;
    for(;x>0;x--){
        int j = rand()%(x+1);
        swap(&arr[x], &arr[j]);
    }
}

void int_catch(int sig){
    signal(sig, SIG_IGN); // Ignore the caught signal.
    ERR_free_strings(); // Cleanup shit.
    EVP_cleanup();
    exit(1);
}
