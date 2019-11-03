#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <stdlib.h> 
#include <netinet/in.h> 
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <string.h> 

#define PORT 8080 
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define FILENAME "public_key"


int decryptRSA(unsigned char* encrypt,int encrypt_len,unsigned char* decrypt){//, char *public_key,int pub_key_len
    // printf("%s",public_key);
    int decrypt_len;

    RSA *pub_key = RSA_new();
    
    FILE *fp = fopen(FILENAME,"rb");
    if(fp == NULL){
        printf("Error opening file\n");
        fclose(fp);
        return -1;
    }
    if(PEM_read_RSAPublicKey(fp, &pub_key, NULL, NULL) == NULL)
    {
        printf("\n%s\n", "Error Reading public key");
        fclose(fp);
        return -1;
    }
    else{
        printf("Public key read successfully\n");
    }
    fclose(fp);
    decrypt_len = RSA_public_decrypt(encrypt_len,encrypt,decrypt,pub_key,RSA_PKCS1_PADDING);

    RSA_free(pub_key);
    return decrypt_len;
}

   
int main(int argc, char const *argv[]) 
{ 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char *hello = "Hello from client"; 
    unsigned char buffer[1024] = {0}; 
    unsigned char   *encrypt = NULL;    // Decrypted message
    unsigned char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
    unsigned char md[SHA_DIGEST_LENGTH];// Buffer for hash digest

    err = malloc(130);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    // send(sock , hello , strlen(hello) , 0 ); 
    // printf("Hello message sent\n"); 
    int encrypt_len,msg_size;

    valread = read( sock , &encrypt_len, sizeof(encrypt_len)); 
    printf("%d\n",ntohl(encrypt_len) ); 
    encrypt_len = ntohl(encrypt_len);
    
    valread = read( sock , &msg_size, sizeof(msg_size)); 
    printf("%d\n",ntohl(msg_size) ); 
    msg_size = ntohl(msg_size);

    valread = read(sock, md,strlen(md));
    // printf("%d\n",msg_size);
    encrypt = malloc(msg_size);
    decrypt = malloc(msg_size);

    valread = read(sock, encrypt, strlen(decrypt));
    printf("%s\n",encrypt);
    
    int decrypt_len;

    decrypt_len = decryptRSA(encrypt,encrypt_len,decrypt);//,pub_key,pub_len

    if(decrypt_len == -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stdout, "Error decrypting message: %s\n", err);
        goto free_stuff;
    }
    printf("\n%d",decrypt_len);
    printf("\nDecrypted Signature\n");
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
            printf("%02x",decrypt[i]);
    decrypt[SHA_DIGEST_LENGTH] = '\0';

    bool flag = true;
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
        if(md[i] != decrypt[i]){
            flag = false;
            printf("\n%d\n",i);
            break;
        }
    }
    if(flag){
        printf("\nSignature Verification successfull\n");
    }
    else{
        printf("\nSignature Verification failed\n");
    }

    free_stuff:
    // RSA_free(keyPair);
    // BIO_free_all(pub);
    // BIO_free_all(pri);
    // free(pri_key);
    // free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0; 
} 