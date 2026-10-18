/* Fixed Windows UTC ECDSA-P256/SHA256/P1363 helper. It supplies cryptography,
 * never time, provisioning, custody, revocation, or installation authority.
 * Scalar32 is anonymous locked memory, never argv/environment/disk output. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

static const unsigned char purpose[] = "luma-windows-hosted-utc-v1";
static const unsigned char cng[8] = {0x45,0x43,0x53,0x31,0x20,0,0,0};
#define PROOF_BYTES (4U + sizeof(purpose) - 1U + 96U + 16U)
static uint32_t u32(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint64_t u64(const unsigned char *p) { return ((uint64_t)u32(p)<<32)|u32(p+4); }
static int transfer(int writing, unsigned char *data, size_t length) {
    while(length) { ssize_t n=writing?send(0,data,length,MSG_NOSIGNAL):read(0,data,length);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return 0;
        data+=(size_t)n;length-=(size_t)n;
    } return 1;
}
static int nonzero(const unsigned char *p,size_t length) {unsigned char v=0;for(size_t i=0;i<length;i++)v|=p[i];return v!=0;}
static int proof(const unsigned char *p,size_t length) {
    if(length!=PROOF_BYTES || u32(p)!=sizeof(purpose)-1 || memcmp(p+4,purpose,sizeof(purpose)-1)) return 0;
    const unsigned char *body=p+4+sizeof(purpose)-1;
    uint64_t lower=u64(body+96),upper=u64(body+104);
    return nonzero(body,32)&&nonzero(body+32,32)&&nonzero(body+64,32)
        && lower>0 && upper>=lower && upper<=4102444800000ULL && upper-lower<=10000;
}
static int private_descriptor(void) {
    struct stat s;struct statfs v;
    return fstat(3,&s)==0 && S_ISREG(s.st_mode) && s.st_nlink==0 && s.st_uid==geteuid() && s.st_size==32
        && fstatfs(3,&v)==0 && v.f_type==0x01021994 && fcntl(3,F_GET_SEALS)>=0;
}
static EVP_PKEY *import_key(OSSL_LIB_CTX *library,const unsigned char *scalar,unsigned char public_blob[72]) {
    EVP_PKEY *key=NULL;EVP_PKEY_CTX *context=NULL,*check=NULL;
    OSSL_PARAM_BLD *builder=NULL;OSSL_PARAM *parameters=NULL;
    EC_GROUP *group=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point=group?EC_POINT_new(group):NULL;
    BN_CTX *bn_context=BN_CTX_new();BIGNUM *d=NULL;
    unsigned char sec1[65];int ok=0;
    if(!group||!point||!bn_context)goto done;
    if(scalar) {
        d=BN_bin2bn(scalar,32,NULL);
        if(!d||BN_is_zero(d)||BN_cmp(d,EC_GROUP_get0_order(group))>=0)goto done;
        BN_set_flags(d,BN_FLG_CONSTTIME);
        if(EC_POINT_mul(group,point,d,NULL,NULL,bn_context)!=1
            || EC_POINT_point2oct(group,point,POINT_CONVERSION_UNCOMPRESSED,sec1,sizeof(sec1),bn_context)!=sizeof(sec1))goto done;
        memcpy(public_blob,cng,8);memcpy(public_blob+8,sec1+1,64);
    } else {
        if(memcmp(public_blob,cng,8))goto done;
        sec1[0]=4;memcpy(sec1+1,public_blob+8,64);
        if(EC_POINT_oct2point(group,point,sec1,sizeof(sec1),bn_context)!=1
            || EC_POINT_is_on_curve(group,point,bn_context)!=1 || EC_POINT_is_at_infinity(group,point))goto done;
    }
    builder=OSSL_PARAM_BLD_new();
    if(!builder || OSSL_PARAM_BLD_push_utf8_string(builder,OSSL_PKEY_PARAM_GROUP_NAME,"prime256v1",0)!=1
        || OSSL_PARAM_BLD_push_octet_string(builder,OSSL_PKEY_PARAM_PUB_KEY,sec1,sizeof(sec1))!=1
        || (d && OSSL_PARAM_BLD_push_BN(builder,OSSL_PKEY_PARAM_PRIV_KEY,d)!=1))goto done;
    parameters=OSSL_PARAM_BLD_to_param(builder);context=EVP_PKEY_CTX_new_from_name(library,"EC","provider=default");
    if(!parameters||!context||EVP_PKEY_fromdata_init(context)!=1
        ||EVP_PKEY_fromdata(context,&key,d?EVP_PKEY_KEYPAIR:EVP_PKEY_PUBLIC_KEY,parameters)!=1)goto done;
    check=EVP_PKEY_CTX_new_from_pkey(library,key,"provider=default");
    if(!check||EVP_PKEY_public_check(check)!=1 || (d&&EVP_PKEY_pairwise_check(check)!=1))goto done;
    ok=1;
done:
    EVP_PKEY_CTX_free(check);EVP_PKEY_CTX_free(context);OSSL_PARAM_free(parameters);OSSL_PARAM_BLD_free(builder);
    BN_clear_free(d);BN_CTX_free(bn_context);EC_POINT_free(point);EC_GROUP_free(group);OPENSSL_cleanse(sec1,sizeof(sec1));
    if(!ok){EVP_PKEY_free(key);key=NULL;}return key;
}
static int signature(OSSL_LIB_CTX *library,EVP_PKEY *key,int signing,const unsigned char *input,unsigned char raw[64]) {
    EVP_MD_CTX *context=EVP_MD_CTX_new();ECDSA_SIG *sig=NULL;
    unsigned char der[80];size_t length=sizeof(der);int ok=0;
    if(!context)goto done;
    if(signing) {
        if(EVP_DigestSignInit_ex(context,NULL,"SHA256",library,"provider=default",key,NULL)!=1
            ||EVP_DigestSign(context,der,&length,input,PROOF_BYTES)!=1)goto done;
        const unsigned char *cursor=der;sig=d2i_ECDSA_SIG(NULL,&cursor,(long)length);
        if(!sig||cursor!=der+length)goto done;
        const BIGNUM *r,*s;ECDSA_SIG_get0(sig,&r,&s);
        ok=BN_bn2binpad(r,raw,32)==32 && BN_bn2binpad(s,raw+32,32)==32;
    } else {
        BIGNUM *r=BN_bin2bn(raw,32,NULL),*s=BN_bin2bn(raw+32,32,NULL);
        sig=ECDSA_SIG_new();
        if(!r||!s||!sig||BN_is_zero(r)||BN_is_zero(s)){BN_free(r);BN_free(s);goto done;}
        if(ECDSA_SIG_set0(sig,r,s)!=1){BN_free(r);BN_free(s);goto done;}
        unsigned char *cursor=der;int size=i2d_ECDSA_SIG(sig,&cursor);
        if(size<=0 || (size_t)size>sizeof(der))goto done;
        ok=EVP_DigestVerifyInit_ex(context,NULL,"SHA256",library,"provider=default",key,NULL)==1
            &&EVP_DigestVerify(context,der,(size_t)size,input,PROOF_BYTES)==1;
    }
done: ECDSA_SIG_free(sig);EVP_MD_CTX_free(context);OPENSSL_cleanse(der,sizeof(der));return ok;
}
int main(int argc,char **argv) {
    (void)argv;struct rlimit memory={64U*1024U*1024U,64U*1024U*1024U},core={0,0},cpu={10,10};
    int type=0;socklen_t type_length=sizeof(type);
    if(argc!=1 || close_range(4,~0U,0) || setrlimit(RLIMIT_AS,&memory)||setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_CPU,&cpu)
        ||prctl(PR_SET_DUMPABLE,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)
        ||getsockopt(0,SOL_SOCKET,SO_TYPE,&type,&type_length)||type_length!=sizeof(type)||type!=SOCK_STREAM)return 1;
    alarm(15);
    unsigned char header[32],scalar[32]={0},public_blob[72]={0},input[PROOF_BYTES],raw[64]={0};
    OSSL_LIB_CTX *library=NULL;OSSL_PROVIDER *provider=NULL;EVP_PKEY *key=NULL;int ok=0;
    if(!transfer(0,header,sizeof(header))||memcmp(header,"LUMAUTCP25601!!\n",16))goto done;
    unsigned char mode=header[16];for(size_t i=17;i<24;i++)if(header[i])goto done;
    uint32_t length=u32(header+24),public_length=u32(header+28);
    if(mode<1||mode>4 || ((mode<=2)&&(length||public_length))
        ||((mode==3)&&(length!=PROOF_BYTES||public_length))
        ||((mode==4)&&(length!=PROOF_BYTES||public_length!=72)))goto done;
    if(mode<=3 && (mlockall(MCL_CURRENT|MCL_FUTURE)||!private_descriptor()))goto done;
    if(mode>=3 && (!transfer(0,input,sizeof(input))||!proof(input,sizeof(input))))goto done;
    library=OSSL_LIB_CTX_new();provider=library?OSSL_PROVIDER_load(library,"default"):NULL;if(!provider)goto done;
    if(mode<=3) {
        if(mode==1) {
            for(unsigned int attempt=0;attempt<8&&!key;attempt++) {
                if(RAND_priv_bytes_ex(library,scalar,sizeof(scalar),256)!=1)goto done;
                key=import_key(library,scalar,public_blob);
            }
            if(!key||pwrite(3,scalar,sizeof(scalar),0)!=(ssize_t)sizeof(scalar))goto done;
        } else {
            if(pread(3,scalar,sizeof(scalar),0)!=(ssize_t)sizeof(scalar))goto done;
            key=import_key(library,scalar,public_blob);
        }
    } else {
        if(close(3)!=0&&errno!=EBADF)goto done;
        if(!transfer(0,public_blob,sizeof(public_blob))||!transfer(0,raw,sizeof(raw)))goto done;
        key=import_key(library,NULL,public_blob);
    }
    if(!key)goto done;
    unsigned char trailing;
    if(read(0,&trailing,1)!=0)goto done;
    if(mode<=2)ok=transfer(1,public_blob,sizeof(public_blob));
    else if(signature(library,key,mode==3,input,raw)) {
        unsigned char verified=1;ok=mode==3?transfer(1,raw,sizeof(raw)):transfer(1,&verified,1);
    }
done:
    OPENSSL_cleanse(scalar,sizeof(scalar));OPENSSL_cleanse(raw,sizeof(raw));EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(provider);OSSL_LIB_CTX_free(library);return ok?0:1;
}
