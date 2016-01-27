#include <openssl/ec.h>
#include <openssl/bn.h>

typedef struct {
    EC_POINT *a;
    EC_POINT *b;
    EC_POINT *c;
} pseudonym;

typedef struct {
    BIGNUM *p;
    BIGNUM *a;
    BIGNUM *b;
    EC_GROUP *ec_group;
    BN_CTX *bn_ctx;
} polypseud_ctx;


#if defined (__cplusplus)
extern "C" {
#endif

    void pseudonym_free(pseudonym *pseud);

    polypseud_ctx *polypseud_ctx_new();
    void polypseud_ctx_free(polypseud_ctx *ctx);
    
    pseudonym *decode(const polypseud_ctx *ctx, const char* pseudonym_string);
    size_t decrypt(const polypseud_ctx *ctx, pseudonym* ep, const BIGNUM *privkey, const BIGNUM *closingkey, unsigned char **pp);
    char* decrypt_ep(const char* ep, const char* privkey, const char* closingkey);

#if defined (__cplusplus)
}
#endif
