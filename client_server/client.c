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
#define MSGLENGTH 1024

bool simpleSHA1(void *input, unsigned long length, unsigned char* md){
    SHA_CTX context;

    if(!SHA1_Init(&context)){
        printf("Error initialising context\n");
        return false;
    }
    if(!SHA1_Update(&context,input,length)){
        printf("Error updating data\n");
        return false;
    }
    if(!SHA1_Final(md,&context)){
        printf("Error hashing data\n");
        return false;
    }

    return true;
}


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
    unsigned char   *encrypt = NULL;    // Encrypted message
    unsigned char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
    unsigned char msg[MSGLENGTH];// Buffer for store recieved message
    unsigned char md[SHA_DIGEST_LENGTH];//Buffer to store hashed message

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

    valread = read( sock , &msg_size, sizeof(msg_size)); 
    printf("Length of Message: %d\n",msg_size); 
    msg_size = msg_size;

    valread = read( sock , &encrypt_len, sizeof(encrypt_len)); 
    printf("Length of Signature : %d\n",encrypt_len); 
    encrypt_len = encrypt_len;

    valread = read(sock, msg,msg_size); // Reading Message
    printf("Message Recieved: %s\n",msg);

    encrypt = malloc(256*sizeof(unsigned char));
    decrypt = malloc(256*sizeof(unsigned char));

    valread = read(sock, encrypt, encrypt_len); // Reading Signature
    printf("Signature\n");
    for(int i =0; i < encrypt_len; i++)
        printf("%02x",encrypt[i]);
    printf("\n");
    int decrypt_len;

    decrypt_len = decryptRSA(encrypt,encrypt_len,decrypt);//,pub_key,pub_len

    if(decrypt_len == -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stdout, "Error decrypting message: %s\n", err);
        goto free_stuff;
    }
    // printf("\n%d",decrypt_len);
    // printf("\nDecrypted Signature\n");
    // for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
    //         printf("%02x",decrypt[i]);
    // decrypt[SHA_DIGEST_LENGTH] = '\0';

    if(!simpleSHA1((void *)msg,strlen(msg), md)){
        printf("Error occurred while hashing message at reciever\n");
        return -1;
    }
    else
    {
        printf("Hashing message at reciever successfull\n");
        // for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
        //     printf("%02x",md[i]);
    }

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