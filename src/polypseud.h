#include <openssl/ec.h>
#include <openssl/bn.h>

typedef struct {
    EC_POINT *a;
    EC_POINT *b;
    EC_POINT *c;
} pseudonym;

typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *a;
    BIGNUM *b;
    EC_GROUP *ec_group;
    EC_POINT *g;
    BN_CTX *bn_ctx;
} polypseud_ctx;


#if defined (__cplusplus)
extern "C" {
#endif

    void pseudonym_free(pseudonym *pseud);

    polypseud_ctx *polypseud_ctx_new();
    void polypseud_ctx_free(polypseud_ctx *ctx);
    
    pseudonym *pseudonym_decode(const polypseud_ctx *ctx, const char* pseudonym_string);
    size_t polypseud_decrypt(const polypseud_ctx *ctx, pseudonym* ep, const BIGNUM *privkey, const BIGNUM *closingkey, unsigned char **pp);
    char* polypseud_decrypt_ep(const char* ep, char* privkey, char* closingkey);

    pseudonym *polypseud_encrypt(const polypseud_ctx *ctx, EC_POINT *yK, const char *uid);
    char* polypseud_generate_pp(char *yK, const char *uid);

#if defined (__cplusplus)
}
#endif
