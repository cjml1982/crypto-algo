#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>


//BN-s 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141

int main(int argc, char * argv []){
    // First step: create a EC_KEY object (note: this part is not ECDSA specific)
    int        ret;
    int        nid;
    ECDSA_SIG *sig;
    ECDSA_SIG *sig_s;
    EC_KEY    *eckey;
    unsigned char digest [20];

    BIGNUM *n = BN_new();
    BIGNUM *minus_s = BN_new();    

    const char* str_n = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    //BN_hex2bn(&n,str_n);
    //int r=  BN_hex2bn(&n,"0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141");
    int r=  BN_hex2bn(&n,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    printf("The result of BN_hex2bn is:\n\tresult=%d\n", r);

    printf("The n hex is:\n\tn-hex=%s\n", BN_bn2hex(n));


    memset(digest, 0xaa, sizeof(digest));// 
    
    //nid = OBJ_sn2nid("secp256k1");
    
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == NULL)
        {
        /* error */
        perror("EC_KEY_new_by_curve_name");
        }
        
    if (!EC_KEY_generate_key(eckey))
        {
        /* error */
        }
    else
        {// 打印一下ec的私钥和公钥
        EC_KEY_print_fp(stdout, eckey, 0);
        }
    // Second step: compute the ECDSA signature of a SHA-1 hash value using ECDSA_do_sign


    sig = ECDSA_do_sign(digest, 20, eckey);// 
    sig_s = ECDSA_do_sign(digest, 20, eckey);   
    BN_sub(minus_s,n,sig->s); 
    sig_s->r=sig->r;
    sig_s->s=minus_s;
    
    if (sig == NULL)
        {
        /* error */
        perror("ECDSA_do_sign");
        }
    else
        {
        printf("Signature:\n\tr=%s\n\ts=%s\n", BN_bn2hex(sig->r), BN_bn2hex(sig->s));
        printf("The Num n:\n\tn=%s\n", BN_bn2hex(n));
	printf("Signature:\n\tr=%s\n\t-s=%s\n", BN_bn2hex(sig_s->r), BN_bn2hex(sig_s->s));

        }
        
    // Third step: verify the created ECDSA signature using ECDSA_do_verify        
    ret = ECDSA_do_verify(digest, 20, sig, eckey);// 
    
    if (ret == -1)
        {
        /* error */
        perror("ECDSA_do_verify");
        }
    else if (ret == 0)
        {
        /* incorrect signature */
        printf("Verified Failure\n");
        }
    else   /* ret == 1 */
        {
        /* signature ok */
        printf("Verified OK\n");
        }    
    ret = ECDSA_do_verify(digest, 20, sig_s, eckey);// 

    if (ret == -1)
        {
        /* error */
        perror("ECDSA_do_verify");
        }
    else if (ret == 0)
        {
        /* incorrect signature */
        printf("Verified Failure\n");
        }
    else   /* ret == 1 */
        {
        /* signature ok */
        printf("Verified OK\n");
        }

    BN_free(n);
    BN_free(minus_s);
    return 0;
}
