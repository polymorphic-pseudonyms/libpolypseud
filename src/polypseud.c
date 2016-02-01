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

char *Base64Encode(const unsigned char* buffer, size_t length) { //Encodes a binary safe base 64 string
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

    char *b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';   
 
    BIO_free_all(bio);
    BUF_MEM_free(bufferPtr);

    return b64text;
}

void pseudonym_free(pseudonym *pseud) {
    if(!pseud)
        return;
    EC_POINT_free(pseud->a);
    EC_POINT_free(pseud->b);
    EC_POINT_free(pseud->c);
    free(pseud);
}

polypseud_ctx *polypseud_ctx_new() {
    polypseud_ctx *ctx = (polypseud_ctx*)malloc(sizeof(polypseud_ctx));
    ctx->bn_ctx = BN_CTX_new();
    ctx->p = BN_new();
    ctx->a = BN_new();
    ctx->b = BN_new();
    BN_hex2bn(&ctx->p, "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27");
    BN_hex2bn(&ctx->a, "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4");
    BN_hex2bn(&ctx->b, "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6");
    ctx->ec_group = EC_GROUP_new_curve_GFp(ctx->p, ctx->a, ctx->b, ctx->bn_ctx);
    if(ctx->ec_group == NULL) {
        BN_free(ctx->p);
        BN_free(ctx->a);
        BN_free(ctx->b);
        BN_CTX_free(ctx->bn_ctx);
        return NULL;
    }
    ctx->q = BN_new();
    BN_hex2bn(&ctx->q, "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311");
    ctx->g = EC_POINT_new(ctx->ec_group);
    EC_POINT_hex2point(ctx->ec_group,
            "0443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            ctx->g, ctx->bn_ctx);
    EC_GROUP_set_generator(ctx->ec_group, ctx->g, ctx->q, BN_value_one());
    return ctx;
}

void polypseud_ctx_free(polypseud_ctx *ctx) {
    if(!ctx)
        return;
    EC_POINT_free(ctx->g);
    EC_GROUP_free(ctx->ec_group);
    BN_free(ctx->p);
    BN_free(ctx->q);
    BN_free(ctx->a);
    BN_free(ctx->b);
    BN_CTX_free(ctx->bn_ctx);
    free(ctx);
}

EC_POINT *decode_base64_point(const polypseud_ctx *ctx, char *string) {
    unsigned char *bytes;
    size_t length;

    if(Base64Decode(string, &bytes, &length) != 0)
        return NULL;

    EC_POINT *point = EC_POINT_new(ctx->ec_group);

    EC_POINT_oct2point(ctx->ec_group, point, bytes, length, ctx->bn_ctx);

    free(bytes);

    return point;
}

char *encode_base64_point(const polypseud_ctx *ctx, EC_POINT *point) {
    unsigned char bytes[100];

    size_t len = EC_POINT_point2oct(ctx->ec_group, point, POINT_CONVERSION_COMPRESSED, bytes, 100, ctx->bn_ctx);
    char *encoded = Base64Encode(bytes, len);

    return encoded;
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

pseudonym *pseudonym_decode(const polypseud_ctx *ctx, const char *pseudonym_string) {
    char pseud_str[strlen(pseudonym_string)+1];
    strcpy(pseud_str, pseudonym_string);

    char* partA = strtok(pseud_str, ",");
    char* partB = strtok(NULL, ",");
    char* partC = strtok(NULL, ",");
    if(partA == NULL || partB == NULL || partC == NULL) {
        return NULL;
    }
    pseudonym *pseud = (pseudonym*)malloc(sizeof(pseudonym));

    pseud->a = decode_base64_point(ctx, partA);
    pseud->b = decode_base64_point(ctx, partB);
    pseud->c = decode_base64_point(ctx, partC);

    return pseud;
}

char* pseudonym_encode(const polypseud_ctx *ctx, const pseudonym *pseud) {
    char *partA = encode_base64_point(ctx, pseud->a);
    char *partB = encode_base64_point(ctx, pseud->b);
    char *partC = encode_base64_point(ctx, pseud->c);
    char *encoded = (char*)calloc(strlen(partA) + strlen(partB) + strlen(partC) + 3, sizeof(char));
    
    strcpy(encoded, partA);
    strcat(encoded, ",");
    strcat(encoded, partB);
    strcat(encoded, ",");
    strcat(encoded, partC);

    free(partA);
    free(partB);
    free(partC);

    return encoded;
}

size_t polypseud_decrypt(const polypseud_ctx *ctx, pseudonym* ep, const BIGNUM *privkey, const BIGNUM *closingkey, unsigned char **pp) {
   if(EC_POINT_mul(ctx->ec_group, ep->a, NULL, ep->a, privkey, ctx->bn_ctx) == 0) 
       return 0;
   
   if(EC_POINT_invert(ctx->ec_group, ep->a, ctx->bn_ctx) == 0) 
        return 0;

   if(EC_POINT_add(ctx->ec_group, ep->a, ep->b, ep->a, ctx->bn_ctx) == 0)
       return 0;

   if(EC_POINT_mul(ctx->ec_group, ep->a, NULL, ep->a, closingkey, ctx->bn_ctx) == 0) 
       return 0;
   
   unsigned char octstring[100];

   size_t len = EC_POINT_point2oct(ctx->ec_group, ep->a, POINT_CONVERSION_UNCOMPRESSED, octstring, 100, ctx->bn_ctx);
   
   return hash(octstring, len, pp); 
}

char *polypseud_decrypt_ep(const char *ep, char *privkey, char *closingkey) {
    polypseud_ctx *ctx = polypseud_ctx_new();
    if(ctx == NULL) {
        return NULL;
    }

    pseudonym *pseudonym = pseudonym_decode(ctx, ep);

    unsigned char *bin_privkey, *bin_closingkey;
    size_t len_privkey, len_closingkey;
    Base64Decode(privkey, &bin_privkey, &len_privkey);
    Base64Decode(closingkey, &bin_closingkey, &len_closingkey);
    BIGNUM *bn_privkey = BN_bin2bn(bin_privkey, len_privkey, NULL);
    BIGNUM *bn_closingkey = BN_bin2bn(bin_closingkey, len_closingkey, NULL);
    free(bin_privkey);
    free(bin_closingkey);
    /*BIGNUM *bn_privkey = BN_new();
    BIGNUM *bn_closingkey = BN_new();
    BN_hex2bn(&bn_privkey, privkey);
    BN_hex2bn(&bn_closingkey, closingkey);*/
    
    unsigned char *pp;
    size_t len = polypseud_decrypt(ctx, pseudonym, bn_privkey, bn_closingkey, &pp);
    BN_clear_free(bn_closingkey);
    BN_clear_free(bn_privkey);

    if(len == 0) {
        return NULL;
    }
    
    char *base64 = Base64Encode(pp, len);
    
    free(pp);
    pseudonym_free(pseudonym);
    polypseud_ctx_free(ctx);
    return base64;
}

EC_POINT *embed(const polypseud_ctx *ctx, const unsigned char *data, const size_t len) {
   BIGNUM *t1 = BN_bin2bn(data, len, NULL);
   BIGNUM *x = BN_new();
   BN_mod(x, t1, ctx->p, ctx->bn_ctx);

   EC_POINT *point = EC_POINT_new(ctx->ec_group);
   unsigned char counter = 0;
   int success = 0;
   while(!success) {
       success = EC_POINT_set_compressed_coordinates_GFp(ctx->ec_group, point, x, 1, ctx->bn_ctx);
       if(!success) {
           if(counter == 0) {
               BN_lshift(x, x, 8);
           }
           BN_add(x, x, BN_value_one());
       }
   }
   BN_free(x);
   BN_free(t1);
   return point;
}

pseudonym *polypseud_encrypt(const polypseud_ctx *ctx, EC_POINT *yK, const char *uid) {
    BIGNUM *k = BN_new();
    if(BN_rand_range(k, ctx->p) == 0)
        return NULL;
    EC_POINT *point = embed(ctx, (unsigned char*)uid, strlen(uid));
    
    char *hex = EC_POINT_point2hex(ctx->ec_group, point, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);
    printf("embedded: %s\n", hex);

    pseudonym *pseud = (pseudonym*)malloc(sizeof(pseudonym));
    pseud->a = EC_POINT_new(ctx->ec_group);
    pseud->b = EC_POINT_new(ctx->ec_group);
    pseud->c = EC_POINT_dup(yK, ctx->ec_group);

    EC_POINT_mul(ctx->ec_group, pseud->a, NULL, ctx->g, k, ctx->bn_ctx);
    EC_POINT_mul(ctx->ec_group, pseud->b, NULL, yK, k, ctx->bn_ctx);
    EC_POINT_add(ctx->ec_group, pseud->b, pseud->b, point, ctx->bn_ctx);

    EC_POINT_free(point);
    BN_free(k);
    return pseud;
}

char* polypseud_generate_pp(char *yK, const char *uid) {
    polypseud_ctx *ctx = polypseud_ctx_new();
    EC_POINT *yK_point = decode_base64_point(ctx, yK);
    pseudonym *pseud=polypseud_encrypt(ctx, yK_point, uid);
    
    char* encoded = pseudonym_encode(ctx, pseud);

    pseudonym_free(pseud);
    EC_POINT_free(yK_point);
    polypseud_ctx_free(ctx);

    return encoded;
}
