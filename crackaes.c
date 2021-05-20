#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <omp.h>

int success = 0;

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv ){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    /* Create and initialise the context */
  
    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

  
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleOpenSSLErrors();
   
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    
    // return 1 if decryption successful, otherwise 0
    if(1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //delete [] plaintext;
    return plaintext;
}


size_t calcDecodeLength(char* b64input) { 
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}


void Base64Decode( char* b64message, unsigned char** buffer, size_t* length) {

    
    BIO *bio, *b64;  // A BIO is an I/O strean abstraction

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}


void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}


int checkPlaintext(char* plaintext, char* result){

    int length = 10; // we just check the first then characters
    return strncmp(plaintext, result, length);

}


int main (void)
{
    
    // pasword Mar10 it took 213 seconds to work out this password
    char* ciphertext_base64 = (char*) "U2FsdGVkX1/x92BdYvopo2z2ZE5u68vEA+00lPDdMF0rr7SGaWdB3+INMw3TWtKNsEI4SKIA0mf87dj7/Q8KiJ2Wzh6MtdxKAfrjvueXod32tU7F35IdyMWCxJGQZcIey0/DLIW3SHqYhuTSP0GBBQ==\n";
    
    // password 12345 it took 9 seconds to work out this password
    //char* ciphertext_base64 = (char*) "U2FsdGVkX19q3SzS6GhhzAKgK/YhFVTkM3RLVxxZ+nM6yXdfLZtvhyRR4oGohDotiifnR1iKyitSpiBM3hng+eoFfGbtgCu3Zh9DwIhgfS5A+OTl5a4L7pRFG4yL432HsMGRC1hy1RNPSzA0U5YyWA==\n";   

    //Cipher Text 1 password is Zest in 672 seconds
    //char* ciphertext_base64 = (char*) "U2FsdGVkX18IzeFxDZrMxL56zmCxpJTpMMCShpV02j9QRvgeAuvSc6V406zzfuwETgIxJXaqvFHMVuFXfR+X6ZDFm2SClHRuI9C1yL+JRRRAUZS22BrE8y0XS0Zwhk5JZS3IBRuNSRNgELQ+Fimmsw==\n";

    //Cipher Text 2 password is 29Apr in 41 seconds
    //char* ciphertext_base64 = (char*) "U2FsdGVkX1/Y+mHv2oZdo5MLKEQWCATfc31jSGWXZ6D3gWuLdZYVUrRnGNecV+EdFsMYSWhEh1nsP9tMwpQaPeWMP3MZ6G0HCLVw+fjRjYY1Fi+lpuGKd/jmZh0Loylw0gVo2SUxNigSvjnn3xAGHg==\n";
    
    //Cipher Text 3
    //char* ciphertext_base64 = (char*) "U2FsdGVkX1+Wf7hqP9ONZTPpSlJzoAHwTh6mLZGp+aH7WVG2lQTjOBkfM+xaQ/gTScaKYEuKFnPMS3xun9e/MXD9MWjKzCVe0vfs9U66T+EcCa1upL4aXwAHgvTEWmPx/Z209HHgDfKSjSLz2RlgUQ==\n";
    

    //char* ciphertext_base64 = (char*) "";

    char* plaintext = "This is the top seret message in parallel computing! Please keep it in a safe place.";
    char dict[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    //char dict[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    int decryptedtext_len, ciphertext_len, dict_len;

    // cipher (binary) pointer and length
    size_t cipher_len; // size_t is sizeof(type)
    unsigned char* ciphertext;
  
    unsigned char salt[8];
    
    ERR_load_crypto_strings();
    
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    unsigned char key[16];
    unsigned char iv[16];

    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    
    // retrive the slater from ciphertext (binary)
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) { // find the keyword "Salted__"
        
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16; 
        cipher_len -= 16;
    
    }

    dict_len = strlen(dict);
    
    time_t begin = time(NULL);

    int ALI = 5;


//PASSWORD LENGTH 3 CODE START

    if(ALI == 3){

        for(int i=0; i<dict_len; i++){
            for(int j=0; j<dict_len; j++){
                for(int k=0; k<dict_len; k++){
                    for(int l=0; l<dict_len; l++){
                        for(int m=0; m<dict_len; m++){
                            *password = dict[i];
                            *(password+1) = dict[j];
                            *(password+2) = dict[k];
                            *(password+3) = '\0';
                            *(password+4) = '\0';

                            
                            initAES(password, salt, key, iv);
                            unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
                            
                            if (success == 1){
                                if(checkPlaintext(plaintext, result)==0){
                                    
                                    printf("Password is %s\n", password);
                                    
                                    time_t end = time(NULL);
                                    printf("Time elpased is %ld seconds\n", (end - begin));
    
                                    exit(0);
                                    }
                                }
                        
                            free(result);
                            
                        }
                    }
                }
            }
        }
    }



//PASSWORD LENGTH 4 CODE START

    if(ALI == 4){

        for(int i=0; i<dict_len; i++){
            for(int j=0; j<dict_len; j++){
                for(int k=0; k<dict_len; k++){
                    for(int l=0; l<dict_len; l++){
                        for(int m=0; m<1; m++){
                            *password = dict[i];
                            *(password+1) = dict[j];
                            *(password+2) = dict[k];
                            *(password+3) = dict[l];
                            *(password+4) = '\0';

                            
                            initAES(password, salt, key, iv);
                            unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
                            
                            if (success == 1){
                                if(checkPlaintext(plaintext, result)==0){
                                    
                                    printf("Password is %s\n", password);
                                    
                                    time_t end = time(NULL);
                                    printf("Time elpased is %ld seconds\n", (end - begin));
    
                                    exit(0);
                                    }
                                }
                        
                            free(result);
                            
                        }
                    }
                }
            }
        }
    }


//PASSWORD LENGTH 5 CODE START

    if(ALI == 5){

        #pragma omp parallel for collapse(5)
        for(int i=0; i<dict_len; i++){
            for(int j=0; j<dict_len; j++){
                for(int k=0; k<dict_len; k++){
                    for(int l=0; l<dict_len; l++){
                        for(int m=0; m<dict_len; m++){
                            *password = dict[i];
                            *(password+1) = dict[j];
                            *(password+2) = dict[k];
                            *(password+3) = dict[l];
                            *(password+4) = dict[m];

                            
                            initAES(password, salt, key, iv);
                            unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
                            
                            if (success == 1){
                                if(checkPlaintext(plaintext, result)==0){
                                    
                                    printf("Password is %s\n", password);
                                    
                                    time_t end = time(NULL);
                                    printf("Time elpased is %ld seconds\n", (end - begin));
    
                                    exit(0);
                                    }
                                }
                        
                            free(result);
                            
                        }
                    }
                }
            }
        }
    }


//PASSWORD LENGTH 6 CODE START

    if(ALI == 6){

        for(int i=0; i<dict_len; i++){
            for(int j=0; j<dict_len; j++){
                for(int k=0; k<dict_len; k++){
                    for(int l=0; l<dict_len; l++){
                        for(int m=0; m<dict_len; m++){
                            for(int n=0; n<dict_len; n++){

                                *password = dict[i];
                                *(password+1) = dict[j];
                                *(password+2) = dict[k];
                                *(password+3) = dict[l];
                                *(password+4) = dict[m];
                                *(password+5) = dict[n];
                                
                                initAES(password, salt, key, iv);
                                unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
                                
                                if (success == 1){
                                    if(checkPlaintext(plaintext, result)==0){
                                        
                                        printf("Password is %s\n", password);
                                        
                                        time_t end = time(NULL);
                                        printf("Time elpased is %ld seconds\n", (end - begin));
        
                                        exit(0);
                                    }
                                }
                            
                                free(result);
                            
                            }
                            
                        }
                    }
                }
            }
        }
    }


    // Clean up
    
    EVP_cleanup();
    ERR_free_strings();


    return 0;
}