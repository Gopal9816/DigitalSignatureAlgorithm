#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
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



int main(int argc, char const *argv[]) 
{ 
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 

    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[MSGLENGTH];  // Message to encrypt
    unsigned char   *encrypt = NULL;    // Encrypted message
    unsigned char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
    unsigned char md[SHA_DIGEST_LENGTH];// Buffer for hash digest
    FILE *public_key_file;

    printf("Enter message to be sent\n");
    scanf("%[^\n]%*c",msg);
    printf("msg_len: %d\n",strlen(msg));
    // Hashing th message
    if(!simpleSHA1((void *)msg,strlen(msg), md)){
        printf("Error occurred while hashing message at sender\n");
        return -1;
    }
    else
    {
        printf("Hashing at sender successfull\n");
        // for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
        //     printf("%02x",md[i]);
    }
    
    RSA *keyPair = RSA_generate_key(KEY_LENGTH,PUB_EXP,NULL,NULL);// Generate key pair

    // To get the C-string PEM Format from RSA Object
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri,keyPair,NULL,NULL,0,NULL,NULL);
    PEM_write_bio_RSAPublicKey(pub,keyPair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len+1);
    pub_key = malloc(pub_len+1);

    BIO_read(pri,pri_key,pri_len);
    BIO_read(pub,pub_key,pub_len);

    pri_key[pri_len] = '\0';

    //Send this public key to client
    pub_key[pub_len] = '\0';
    public_key_file = fopen(FILENAME,"w");
    if(!PEM_write_RSAPublicKey(public_key_file, keyPair))
    {
        printf("\n%s\n", "Error writing public key");
    }
    else{
        printf("\n%s\n","Successfully wriiten key to PEM file");
    }
    fflush(public_key_file);
    fclose(public_key_file);

    //Encryption

    encrypt = malloc(RSA_size(keyPair));
    int encrypt_len;
    err = malloc(130);

    encrypt_len = RSA_private_encrypt(strlen(md)+1,md,encrypt,keyPair,RSA_PKCS1_PADDING);

    if(encrypt_len == -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_stuff;
    }
    else{
        // printf("%d",encrypt_len);
        
        printf("\nSignature Encrypted Successfully\n");
        // for(int i =0; i < encrypt_len; i++)
        //     printf("%02x",encrypt[i]);
        // printf("\n");
    }    

          
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    else{
        printf("Server listening on port 8080\n");
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        printf("Accepting new connection\n");
    }
    // valread = read( new_socket , buffer, 1024); 
    // printf("%s\n",buffer ); 

    printf("Sending length of message\n");
    int msg_len = strlen(msg);
    write(new_socket , &msg_len , sizeof(msg_len)); 

    printf("Sending signature length\n");
    write(new_socket , &encrypt_len , sizeof(encrypt_len)); 

    printf("Sending message\n");
    send(new_socket, msg, msg_len, 0);

    // printf("\n%s",encrypt);
    printf("Sending signature\n");
    write(new_socket,(void *)encrypt, encrypt_len);
    // printf("Hello message sent\n"); 


    free_stuff:
    RSA_free(keyPair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0; 
} 