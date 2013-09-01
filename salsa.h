#include<stdio.h>
#include<nettle/salsa20.h>
#include<sys/socket.h>
#include<sys/select.h>
#include"pgp.h"

#define	SKTYPE	0
#define	SMTYPE	1

struct salsa20_ctx	lsalsactx,
					rsalsactx;

typedef struct cipherPacket{
	uint8_t		type;
	uint64_t	sz;
} cipherPkt;

/*
 *GetMsg
 *	Retrieve SALSA20_BLOCK_SIZE of message from fd.
 */
static void GetMsg(int fd,uint8_t *buf,uint64_t *msgsz){
	int64_t tmp;

	memset(buf,0,SALSA20_BLOCK_SIZE);
	if((tmp=read(fd,buf,SALSA20_BLOCK_SIZE))<0){
		ec++;
		perror("GetMsg:read");
	}else{
		*msgsz=tmp;
	}
}
/* 
 *SendMsg
 *	Send encrypted message to 'ext'.
 */
static void SendMsg(int ext,uint8_t *msg,uint64_t eMsgSz){
	uint64_t	tot=0;
	int64_t		tmp;
	cipherPkt	phdr;

	phdr.type=SMTYPE;
	phdr.sz=eMsgSz;
	while(tot<sizeof(phdr)&&IsGood()){
		if((tmp=send(ext,&phdr+tot,sizeof(phdr)-tot,MSG_MORE))<0){
			ec++;
			perror("SendMsg:header:send");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	while(tot<phdr.sz&&IsGood()){
		if((tmp=send(ext,msg+tot,SALSA20_BLOCK_SIZE-tot,MSG_MORE))<0){
			ec++;
			perror("SendMsg:content:send");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *PutMsg
 *	Writes a decrypted Salsa20 message to 'fd'
 */
static void PutMsg(int out,uint8_t *msg,uint64_t sz){
	uint64_t	tot=0;
	int64_t		tmp;
	
	while(tot<sz&&IsGood()){
		if((tmp=write(out,msg+tot,sz-tot))<0){
			ec++;
			perror("PutMsg:write");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *InitSalsaKey
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
static void SendSalsaKey(uint8_t *eKey,uint64_t eKeySz,int ext){
	uint64_t	tot=0;
	int64_t		tmp;
	cipherPkt	phdr;

	phdr.type=SKTYPE;
	phdr.sz=eKeySz;
	while(tot<sizeof(phdr)&&IsGood()){
		if((tmp=send(ext,&phdr+tot,sizeof(phdr)-tot,MSG_MORE))<0){
			ec++;
			perror("SendSalsaKey:header:send");
		}else{
			tot+=tmp;
		}
	}
	tot=0;
	while(tot<eKeySz&&IsGood()){
		if((tmp=send(ext,eKey+tot,eKeySz-tot,MSG_MORE))<0){
			ec++;
			perror("SendSalsaKey:content:send");
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
	uint64_t	tot=0;
	int64_t		tmp;

	memset(msg,0,SALSA20_BLOCK_SIZE);
	while(tot<SALSA20_BLOCK_SIZE&&IsGood()){
		if((tmp=recv(ext,msg+tot,SALSA20_BLOCK_SIZE-tot,MSG_WAITALL))<0){
			ec++;
			perror("RecvMsg:content:recv");
		}else{
			tot+=tmp;
		}
	}
}
/*
 *ReceiveSalsaKey
 *	Receives an encrypted Salsa20 key from 'ext' and returns the encrypted data in a buffer.
 */
static void *ReceiveSalsaKey(size_t eKeySz,int ext){
	uint64_t	tot=0;
	int64_t		tmp;
	uint8_t		*ret;

	ret=xmalloc(eKeySz);
	if(ret!=NULL){
		while(tot<eKeySz&&IsGood()){
			if((tmp=recv(ext,ret+tot,eKeySz-tot,MSG_WAITALL))<0){
				ec++;
				perror("ReceiveSalsaKey:content:recv");
			}else{
				tot+=tmp;
			}
		}
	}
	return ret;
}
/*ParseIncMsg
 *	Parse the data from an incoming message and process it appropriately as
 *	either a new Salsa Key or a message encrypted with the current Salsa key.
 */
void ParseIncMsg(int out,int ext,uint8_t *ptext,uint8_t *ctext,uint8_t *rkey,const char *me){
	uint64_t	tot=0;
	int64_t		tmp;
	uint8_t		*tkey;
	cipherPkt	phdr;

	while(tot<sizeof(phdr)&&IsGood()){
		if((tmp=recv(ext,&phdr+tot,sizeof(phdr)-tot,MSG_WAITALL))<0){
			ec++;
			perror("ParseMsg:header:recv");
		}else{
			tot+=tmp;
		}
	}
	switch(phdr.type){
		case SKTYPE:
			tkey=ReceiveSalsaKey(phdr.sz,ext);
			DecryptSalsaKey(tkey,rkey,me,phdr.sz);
			xfree(tkey,phdr.sz);
			InitSalsaKey(rkey,&rsalsactx);
			break;
		case SMTYPE:
			if(phdr.sz<=SALSA20_BLOCK_SIZE){
				RecvMsg(ext,ctext);
				salsa20_crypt(&rsalsactx,SALSA20_BLOCK_SIZE,ptext,ctext);
				PutMsg(out,ptext,phdr.sz);
				break;
			}
		default:
			fprintf(stderr,"ParseMsg:Received Bad Packet (type (%d) - size (%lu))!\n",phdr.type,phdr.sz);
			ec=MAX_ERR;
	}
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
	int			maxfd;
	uint64_t	lc=1,
				eKeySz,
				eMsgSz=0;
	fd_set		fds;

	ec=0;
	FD_ZERO(&fds);
	FD_SET(in,&fds);
	FD_SET(ext,&fds);
	if(in>ext){
		maxfd=in+1;
	}else{
		maxfd=ext+1;
	}
	while(IsGood()){
		while(lc){
			ReadRandom(lkey,SALSA20_KEY_SIZE);
			InitSalsaKey(lkey,&lsalsactx);
			ekey=EncryptSalsaKey(lkey,them,&eKeySz);
			SendSalsaKey(ekey,eKeySz,ext);
			xfree(ekey,eKeySz);
			while(lc&&IsGood()){
				if(select(maxfd,&fds,NULL,NULL,NULL)<0){
					ec++;
					perror("CipherPipe:select");
				}else{
					if(FD_ISSET(in,&fds)&&IsGood()){
						if(IsGood())
							GetMsg(in,ptext,&eMsgSz);
						if(IsGood())
							salsa20_crypt(&lsalsactx,SALSA20_BLOCK_SIZE,ctext,ptext);
						if(IsGood())
							SendMsg(ext,ctext,eMsgSz);
						lc++;
					}
					if(FD_ISSET(ext,&fds)){
						if(IsGood())
							ParseIncMsg(out,ext,ptext,ctext,rkey,me);
					}
				}
				FD_ZERO(&fds);
				FD_SET(in,&fds);
				FD_SET(ext,&fds);
			}
		}
	}
	xfree(lkey,SALSA20_KEY_SIZE);
	xfree(rkey,SALSA20_KEY_SIZE);
	xfree(ptext,SALSA20_BLOCK_SIZE);
	xfree(ctext,SALSA20_BLOCK_SIZE);
}
