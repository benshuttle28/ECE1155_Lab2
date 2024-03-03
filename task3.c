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
    BIGNUM *dm = BN_new();

    // initialize numbers
    BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
    BN_dec2bn(&e,"65537");
    BN_hex2bn(&m,"4120746f702073656372657421");

    // calculate n 
    BN_mul(n,p,q,ctx);

    // calculate totient n 
    BN_sub(res1,p,BN_value_one());
    BN_sub(res2,q,BN_value_one());
    BN_mul(tn,res1,res2,ctx);

    // calculate d for private key 
    BN_mod_inverse(d,e,tn,ctx);

    // get encrypted message
    BN_mod_exp(c,m,e,n,ctx);

    // decrypt message
    BN_mod_exp(dm,c,d,n,ctx);
    
    printBN("encrypted message: ",c);
    printBN("decrypted message: ",dm);

    return 0;
}

