#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    // use BN_bn2hex(a) for hex string
    // use BN_bn2dec(a) for decimal string 

    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *tn = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res1 = BN_new();
    BIGNUM *res2 = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *vm = BN_new();
    BIGNUM *signature = BN_new();

    // initialize numbers
    //BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
    //BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_dec2bn(&e,"65537");
    BN_hex2bn(&m,"4C61756E63682061206D697373696C652E");
    BN_hex2bn(&signature,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

    // verify signature
    BN_mod_exp(vm,signature,e,n,ctx);

    printBN("verified message: ",vm);

    return 0;
}

