#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <string.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define FILENAME "public_key"

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

int decryptRSA(unsigned char* encrypt,int encrypt_len,unsigned char* decrypt, char *public_key,int pub_key_len){
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

int main(){
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur sollicitudin laoreet maximus. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Proin vitae mi at risus elementum feugiat. Proin ultricies erat metus, quis vestibulum nibh laoreet id. Phasellus a sodales quam. Proin in sapien lacinia, mollis augue eget, lobortis leo. Pellentesque in nibh nec erat mattis rutrum et ac nisl. Vestibulum et ante sodales, suscipit ante condimentum, eleifend purus. Cras efficitur quam sit amet mauris vehicula, vel consectetur lorem interdum. Vestibulum fringilla fermentum blandit. Maecenas sit amet accumsan ante. Vestibulum posuere arcu eget neque auctor vulputate. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur vulputate dolor non elit porta porta. Etiam vulputate, ligula et facilisis iaculis, est sem dapibus odio, nec commodo ipsum ex a magna. Etiam malesuada, tellus ut maximus molestie, mauris turpis maximus nulla, vel fringilla metus ante quis enim. ";  // Message to encrypt
    unsigned char   *encrypt = NULL;    // Encrypted message
    unsigned char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
    unsigned char md[SHA_DIGEST_LENGTH];// Buffer for hash digest
    FILE *public_key_file;

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
        printf("\nSignature Encrypted Successfully\n");
    }

    decrypt = malloc(RSA_size(keyPair));
    int decrypt_len;

    decrypt_len = decryptRSA(encrypt,encrypt_len,decrypt,pub_key,pub_len);

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
    RSA_free(keyPair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    
    
}
