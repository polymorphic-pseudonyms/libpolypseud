#include "polypseud.h"

#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <assert.h>

//Base64 functions taken and adapted from https://gist.github.com/barrysteyn/7308212
size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input),
           padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
    BIO *bio, *b64;

    size_t decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text=(*bufferPtr).data;

    return (0); //success
}

void pseudonym_free(pseudonym *pseud) {
    EC_POINT_free(pseud->a);
    EC_POINT_free(pseud->b);
    EC_POINT_free(pseud->c);
    free(pseud);
}

EC_POINT *decode_base64_point(const EC_GROUP *ec_group, char *string, BN_CTX *bn_ctx) {
    unsigned char *bytes;
    size_t length;

    if(Base64Decode(string, &bytes, &length) != 0)
        return NULL;

    EC_POINT *point = EC_POINT_new(ec_group);

    EC_POINT_oct2point(ec_group, point, bytes, length, bn_ctx);

    free(bytes);

    return point;
}

unsigned int hash(unsigned char *message, size_t message_len, unsigned char **digest)
{
    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
        return 0;

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        return 0;

    if(1 != EVP_DigestUpdate(mdctx, message, message_len))
        return 0;

    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return 0;

    unsigned int digest_len;
    if(1 != EVP_DigestFinal_ex(mdctx, *digest, &digest_len))
        return 0;

    EVP_MD_CTX_destroy(mdctx);

    return digest_len;
}

pseudonym *decode(const EC_GROUP *ec_group, const char *pseudonym_string, BN_CTX *bn_ctx) {
    char pseud_str[strlen(pseudonym_string)+1];
    strcpy(pseud_str, pseudonym_string);

    char* partA = strtok(pseud_str, ",");
    char* partB = strtok(NULL, ",");
    char* partC = strtok(NULL, ",");
    if(partA == NULL || partB == NULL || partC == NULL) {
        return NULL;
    }
    pseudonym *pseud = (pseudonym*)malloc(sizeof(pseudonym));

    pseud->a = decode_base64_point(ec_group, partA, bn_ctx);
    pseud->b = decode_base64_point(ec_group, partB, bn_ctx);
    pseud->c = decode_base64_point(ec_group, partC, bn_ctx);

    return pseud;
}

size_t decrypt(const EC_GROUP *ec_group, pseudonym* ep, const BIGNUM *privkey, const BIGNUM *closingkey, unsigned char **pp, BN_CTX *bn_ctx) {
   if(EC_POINT_mul(ec_group, ep->a, NULL, ep->a, privkey, bn_ctx) == 0) 
       return 0;
   
   if(EC_POINT_invert(ec_group, ep->a, bn_ctx) == 0) 
        return 0;

   if(EC_POINT_add(ec_group, ep->a, ep->b, ep->a, bn_ctx) == 0)
       return 0;

   if(EC_POINT_mul(ec_group, ep->a, NULL, ep->a, closingkey, bn_ctx) == 0) 
       return 0;
   
   unsigned char octstring[100];

   size_t len = EC_POINT_point2oct(ec_group, ep->a, POINT_CONVERSION_UNCOMPRESSED, octstring, 100, bn_ctx);
   
   return hash(octstring, len, pp); 
}

char* decrypt_ep(const char* ep, const char* privkey, const char* closingkey) {
    BN_CTX *bn_ctx = BN_CTX_new();
    //EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP320r1);
    
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BN_hex2bn(&bn_p, "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27");
    BN_hex2bn(&bn_a, "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4");
    BN_hex2bn(&bn_b, "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6");
    EC_GROUP *ec_group = EC_GROUP_new_curve_GFp(bn_p, bn_a, bn_b, bn_ctx);
    if(ec_group == NULL) {
        return NULL;
    }

    pseudonym *pseudonym = decode(ec_group, ep, bn_ctx);

    BIGNUM *bn_privkey = BN_new();
    BIGNUM *bn_closingkey = BN_new();
    BN_hex2bn(&bn_privkey, privkey);
    BN_hex2bn(&bn_closingkey, closingkey);
    
    unsigned char *pp;
    size_t len = decrypt(ec_group, pseudonym, bn_privkey, bn_closingkey, &pp, bn_ctx);

    if(len == 0) {
        return NULL;
    }
    
    char *base64;
    Base64Encode(pp, len, &base64);
    
    free(pp);
    BN_clear_free(bn_closingkey);
    BN_clear_free(bn_privkey);
    pseudonym_free(pseudonym);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(ec_group);
    return base64;
}
