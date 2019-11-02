#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <string.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3

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

int main(){
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[] = "Hello World, the sunshine smiles brightly";  // Message to encrypt
    unsigned char   *encrypt = NULL;    // Encrypted message
    unsigned char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
    unsigned char md[KEY_LENGTH/8];// Buffer for hash digest

    if(!simpleSHA1((void *)msg,strlen(msg), md)){
        printf("Error occurred while hashing message at sender\n");
        return -1;
    }
    else
    {
        printf("Hashing at sender successfull\n");
        for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
            printf("%02x",md[i]);
    }
    
    // Generate key pair
    RSA *keyPair = RSA_generate_key(KEY_LENGTH,PUB_EXP,NULL,NULL);

    // To get the C-string PEM Format
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

    decrypt = malloc(RSA_size(keyPair));
    int decrypt_len;

    decrypt_len = RSA_public_decrypt(encrypt_len,encrypt,decrypt,keyPair,RSA_PKCS1_PADDING);

    if(decrypt_len == -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stdout, "Error encrypting message: %s\n", err);
        goto free_stuff;
    }
    printf("\n%d",decrypt_len);
    printf("\nDecrypted Signature\n");
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
            printf("%02x",decrypt[i]);
    decrypt[SHA_DIGEST_LENGTH] = '\0';
    if(strcmp(md,decrypt) == 0){
        printf("\nSignature Verification successfull\n");
    }
    else{
        printf("\nSignature Verification failed\n");
    }

    free_stuff:
    RSA_free(keyPair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    
    
}
