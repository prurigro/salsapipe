#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<nettle/salsa20.h>
#include<sys/socket.h>
#include<sys/select.h>
#include"pgp.h"

#define E_SOURCE "/dev/urandom"
#define	SKTYPE	0
#define	SMTYPE	1

struct salsa20_ctx		lsalsactx,
						rsalsactx;

struct cipherPacket{
	uint8_t	type;
	size_t	sz;
};
/*
 *ReadRandom
 *	Reads 'sz' bytes from the defined E_SOURCE file into buffer 'buf'
 */
void ReadRandom(void *buf,size_t sz){
	size_t	tot=0;
	ssize_t	tmp;
	int		efd;

	if((efd=open(E_SOURCE,0))<0){
		perror("ReadRandom:open");
	}else{
		while(tot<sz){
			if((tmp=read(efd,buf+tot,sz-tot))<0){
				perror("ReadRandom:read");
			}else{
				tot+=tmp;
			}
		}
		close(efd);
	}
}
/*
 *GetMsg
 *	Retrieve SALSA20_BLOCK_SIZE of message from fd.
 */
 /*
 static void GetMsg(uint8_t *buf){
	 int	s=0;
	 size_t tot=0;
	 
	 while(tot<SALSA20_BLOCK_SIZE&&s!=EOF){
		 s=fgetc(stdin);
		 buf[tot++]=s;
	 }
 }
 */
static void GetMsg(int fd,uint8_t *buf){
	memset(buf,0,SALSA20_BLOCK_SIZE);
	if(read(fd,buf,SALSA20_BLOCK_SIZE)<0){
		perror("GetMsg:read");
	}
}
/* 
 *SendMsg
 *	Send encrypted message to 'ext'.
 */
static void SendMsg(int ext,uint8_t *msg){
	size_t	tot=0;
	ssize_t	tmp;
	struct cipherPacket	phdr;

	phdr.type=SMTYPE;
	phdr.sz=SALSA20_BLOCK_SIZE;
	while(tot<sizeof(phdr)){
		if((tmp=send(ext,&phdr+tot,sizeof(phdr)-tot,MSG_MORE))<0){
			perror("SendMsg:header:send");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	while(tot<phdr.sz){
		if((tmp=send(ext,msg+tot,phdr.sz-tot,MSG_MORE))<0){
			perror("SendMsg:content:send");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *RcvMsg
 *	Receives an encrypted Salsa20 message
 */
static void RecvMsg(int ext,uint8_t *msg){
	size_t	tot=0;
	ssize_t	tmp;
	struct cipherPacket	phdr;

	while(tot<sizeof(phdr)){
		if((tmp=recv(ext,&phdr+tot,sizeof(phdr)-tot,MSG_WAITALL))<0){
			perror("RecvMsg:header:recv");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	if(phdr.sz==SALSA20_BLOCK_SIZE){
		while(tot<phdr.sz){
			if((tmp=recv(ext,msg+tot,phdr.sz-tot,MSG_WAITALL))<0){
				perror("RecvMsg:content:recv");
			}else{
				tot+=tmp;
			}
		}	
	}else{
		fprintf(stderr,"Error bad cipher packet\n");
	}
}
/*
 *PutMsg
 *	Writes a decrypted Salsa20 message to 'fd'
 */
static void PutMsg(int out,uint8_t *msg){
	size_t	tot=0;
	ssize_t	tmp;
	
	while(tot<SALSA20_BLOCK_SIZE){
		if((tmp=write(out,msg+tot,SALSA20_BLOCK_SIZE-tot))<0){
			perror("PutMsg:write");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *NewSalsaKey
 *	Generates a new Salsa20 key and initialises the salsa20 context with it and a reset iv.
 */
static void InitSalsaKey(uint8_t *key,struct salsa20_ctx *ctx){
	uint64_t	iv=0;

	salsa20_set_key(ctx,SALSA20_KEY_SIZE,key);
	salsa20_set_iv(ctx,(uint8_t *)&iv);
}
/*
 *SendSalsaKey
 *	Sends an encrypted Salsa20 key to 'ext'.
 */
static void SendSalsaKey(uint8_t *eKey,size_t eKeySz,int ext){
	size_t	tot=0;
	ssize_t	tmp;
	struct cipherPacket	phdr;

	phdr.type=SKTYPE;
	phdr.sz=eKeySz;
	while(tot<sizeof(phdr)){
		if((tmp=send(ext,&phdr+tot,sizeof(phdr)-tot,MSG_MORE))<0){
			perror("SendSalsaKey:header:send");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	while(tot<eKeySz){
		if((tmp=send(ext,eKey+tot,eKeySz-tot,MSG_MORE))<0){
			perror("SendSalsaKey:content:send");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *ReceiveSalsaKey
 *	Receives an encrypted Salsa20 key from 'ext' and returns the encrypted data in a buffer.
 */
static void *ReceiveSalsaKey(size_t *eKeySz,int ext){
	size_t	tot=0;
	ssize_t	tmp;
	uint8_t	*ret;
	struct cipherPacket	phdr;

	while(tot<sizeof(phdr)){
		if((tmp=recv(ext,&phdr+tot,sizeof(phdr)-tot,MSG_WAITALL))<0){
			perror("ReceiveSalsaKey:header:recv");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	ret=xmalloc(phdr.sz);
	while(tot<phdr.sz){
		if((tmp=recv(ext,ret+tot,phdr.sz-tot,MSG_WAITALL))<0){
			perror("ReceiveSalsaKey:content:recv");
		}else{
			tot+=tmp;
		}
	}
	*eKeySz=tot;
	return ret;
}
/*
 *CipherPipe
 *	Creates a tunnel for encrypted communication, reading from 'in', encryping and send to 'ext'
 *	and conversely receiving from 'ext', decrypting to and writing to 'out'.
 *	Will auto-renegotiate Salsa20 keys by exchanging new encrypted salsa20 keys as the iv is depleted.
 */
void CipherPipe(int in,int out,int ext,const char *them,const char *me){
	void		*ekey;
	uint8_t		*lkey=xmalloc(SALSA20_KEY_SIZE),
				*rkey=xmalloc(SALSA20_KEY_SIZE),
				*ptext=xmalloc(SALSA20_BLOCK_SIZE),
				*ctext=xmalloc(SALSA20_BLOCK_SIZE);
	uint64_t	rc=1,
				lc=1;
	int			maxfd;
	size_t		eKeySz;
	fd_set		fds;
	struct timeval timeOut;

	timeOut.tv_sec=5;
	timeOut.tv_usec=0;
	FD_ZERO(&fds);
	FD_SET(in,&fds);
	FD_SET(ext,&fds);
	if(in>ext){
		maxfd=in+1;
	}else{
		maxfd=ext+1;
	}
	ReadRandom(lkey,SALSA20_KEY_SIZE);
	InitSalsaKey(lkey,&lsalsactx);
	ekey=EncryptSalsaKey(lkey,them,&eKeySz);
	SendSalsaKey(ekey,eKeySz,ext);
	free(ekey);
	ekey=ReceiveSalsaKey(&eKeySz,ext);
	DecryptSalsaKey(ekey,rkey,me,eKeySz);
	InitSalsaKey(rkey,&rsalsactx);
	free(ekey);
	while(rc&&lc){
		if(select(maxfd,&fds,NULL,NULL,&timeOut)<0){
			perror("CipherPipe:select");
		}else{
			if(FD_ISSET(in,&fds)){
				GetMsg(in,ptext);
				salsa20_crypt(&lsalsactx,SALSA20_BLOCK_SIZE,ctext,ptext);
				SendMsg(ext,ctext);
				lc++;
			}
			if(FD_ISSET(ext,&fds)){
				RecvMsg(ext,ctext);
				salsa20_crypt(&rsalsactx,SALSA20_BLOCK_SIZE,ptext,ctext);
				PutMsg(out,ptext);
				rc++;
			}
		}
		timeOut.tv_sec=5;
		timeOut.tv_usec=0;
		FD_ZERO(&fds);
		FD_SET(in,&fds);
		FD_SET(ext,&fds);
	}
	free(lkey);
	free(rkey);
	free(ptext);
	free(ctext);
	fprintf(stderr,"Reached end of run of IVs, we do not want to re-use\n");
}
