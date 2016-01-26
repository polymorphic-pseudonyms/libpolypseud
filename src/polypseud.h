#include <openssl/ec.h>
#include <openssl/bn.h>

typedef struct {
    EC_POINT *a;
    EC_POINT *b;
    EC_POINT *c;
} pseudonym;

#if defined (__cplusplus)
extern "C" {
#endif

    void pseudonym_free(pseudonym *pseud);

    pseudonym *decode(const EC_GROUP *ec_group, const char* pseudonym_string, BN_CTX *bn_ctx);

    size_t decrypt(const EC_GROUP *ec_group, pseudonym* ep, const BIGNUM *privkey, const BIGNUM *closingkey, unsigned char **pp, BN_CTX *bn_ctx);

    char* decrypt_ep(const char* ep, const char* privkey, const char* closingkey);

#if defined (__cplusplus)
}
#endif
