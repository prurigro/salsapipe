#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>

#define E_SOURCE "/dev/urandom"

/*
 *ReadRandom
 *	Reads 'sz' bytes from the defined E_SOURCE file into buffer 'buf'
 */
void ReadRandom(void *buf,size_t sz){
	size_t	tot=0;
	ssize_t	tmp;
	int		efd;

	if((efd=open(E_SOURCE,O_RDONLY))<0){
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
 *xmalloc 
 *	crummy wrapper for malloc to pick up failures.
 */
void *xmalloc(size_t sz){
	void *ret=NULL;
	if(sz<1){
		fprintf(stderr,"xmalloc:malloc size specified is 0\n");
	}else{
		if((ret=malloc(sz))==NULL){
			fprintf(stderr,"xmalloc:failed to allocate %lu bytes",sz);
			perror(":malloc");
		}else{
			memset(ret,0,sz);
		}
	}
	return ret;
}
/*
 *xfree
 *	crummy wrapper for free to clear mem & pick up failures.
 */
void xfree(void *mem,size_t sz){
	if(mem!=NULL){
		memset(mem,0,sz);
		free(mem);
		mem=NULL;
	}
}
