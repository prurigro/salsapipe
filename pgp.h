#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<gpgme.h>
#include<string.h>
#include<nettle/salsa20.h>

#define TRUE 1
#define FALSE 0

/*
 *xmalloc 
 *	crummy wrapper for malloc to pick up failures.
 */
void *xmalloc(size_t sz){
	void *ret=NULL;
	if(sz<1){
		fprintf(stderr,"xmalloc:malloc size specified is 0\n");
	}else{
		if((ret=malloc(sz))==NULL){
			perror("xmalloc:malloc");
		}else{
			memset(ret,0,sz);
		}
	}
	return ret;
}
/*
 *gpgErr
 *	Print error messages relating to GPG failures.
 */
static int gpgErr(gpgme_error_t err){
	if(err){
		fprintf(stderr,"gpgErr:%s:\t%s\n",gpgme_strsource(err),gpgme_strerror(err));
		return TRUE;
	}else{
		return FALSE;
	}
}
/*
 *InitPGP
 *	Initialise a PGP Context with GPGME
 */
static int InitPGP(gpgme_ctx_t *gpgctx){
	gpgme_check_version(NULL);
	if(gpgme_new(gpgctx)){
		fprintf(stderr,"InitPGP: Failed, abandon ship!\n");
		return FALSE;
	}else{
		return TRUE;
	}
}
/*
 *EncryptSalsaKey
 *	Encrypts a Salsa20 key with the PGP key for 'encTo' and returns a malloc'd
 *	buffer containing the resulting encrypted content.
 */
void *EncryptSalsaKey(const uint8_t *salsaKey,const char *encTo,size_t *sz){
	gpgme_ctx_t				gpgctx;
	gpgme_data_t			in,
							out;
	gpgme_key_t				gpgk[2];
	char					*ret=NULL;

	if(InitPGP(&gpgctx)!=FALSE){
		gpgk[1]=NULL;
		gpgErr(gpgme_get_key(gpgctx,encTo,&gpgk[0],0));
		gpgErr(gpgme_data_new_from_mem(&in,(const char *)salsaKey,SALSA20_KEY_SIZE,0));
		gpgErr(gpgme_data_new(&out));
		gpgErr(gpgme_op_encrypt(gpgctx,gpgk,GPGME_ENCRYPT_ALWAYS_TRUST,in,out));
		ret=gpgme_data_release_and_get_mem(out,sz);
		gpgme_data_release(in);
		gpgme_release(gpgctx);
	}
	return ret;
}
/*
 *DecryptSalsaKey
 *	Decrypts a Salsa20 key with the PGP key for 'decTo' and places the decrypted key inside 'salsaKey'.
 */
void DecryptSalsaKey(void *esalsaKey,void *salsaKey,const char *decTo,size_t sz){
	gpgme_ctx_t		gpgctx;
	gpgme_data_t	in,
					out;
	gpgme_key_t		gpgk[2];

	if(InitPGP(&gpgctx)==FALSE){
		return;
	}else{
		gpgk[1]=NULL;
		gpgErr(gpgme_get_key(gpgctx,decTo,&gpgk[0],1));
		gpgErr(gpgme_data_new_from_mem(&in,esalsaKey,sz,0));
		gpgErr(gpgme_data_new(&out));
		gpgErr(gpgme_op_decrypt(gpgctx,in,out));
		gpgme_data_seek(out,0,SEEK_SET);
		gpgme_data_read(out,salsaKey,SALSA20_KEY_SIZE);
		gpgme_release(gpgctx);
		gpgme_data_release(out);
		gpgme_data_release(in);
	}
}
