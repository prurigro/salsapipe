#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include"salsa.h"
#define VERSION "SalsaMsg v0.01"

void usage(void){
	fprintf(stderr,"%s Usage:\n\tsalsamsg -i <IP/Hostname> -p <Port> -m <l/c> -l <Local PGP Name> -r <Remote PGP Name>\n",VERSION);
	exit(1);
}

void getopts(int argc,char **argv,struct sockaddr_in *conn,char *mode,char *me,char *them){
	int	 opt,
			port=65536,
			ip=0;

	while((opt=getopt(argc,argv,"i:p:m:l:r:"))!=-1){
		switch(opt){
			case 'i':
				ip=inet_pton(AF_INET,optarg,&conn->sin_addr);
				break;
			case 'p':
				port=atoi(optarg);
				if((port<65536)&&(port>0)){
					conn->sin_port=htons(port%65536);
				}else{
					usage();
				}
				break;
			case 'm':
				mode[0]=optarg[0];
				break;
			case 'l':
				if(optarg[0]==0){
					usage();
				}
				strncpy(me,optarg,63);
				break;
			case 'r':
				if(optarg[0]==0){
					usage();
				}
				strncpy(them,optarg,63);
				break;
			default:
				usage();
		}
	}
	switch(ip){
		case 1:
			break;
		default:
			usage();
	}
	switch(port){
		case 65536:
			usage();
		default:
			break;
	}
	switch(mode[0]){
		case 'c':
			break;
		case 'l':
			break;
		default:
			usage();
	}
}

int main(int argc, char **argv){
	int					tcp_sock=socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in	remotehost;
	char				mode='x',
						*me=xmalloc(64),
						*them=xmalloc(64);

	remotehost.sin_family=AF_INET;
	getopts(argc,argv,&remotehost,&mode,me,them);
	fprintf(stderr,"l:%s<->r:%s\n",me,them);
	switch(mode){
		case 'c':
			if(connect(tcp_sock,(struct sockaddr *)&remotehost,sizeof(remotehost))!=0){
				perror("connect");
			}else{
				CipherPipe(fileno(stdin),fileno(stdout),tcp_sock,them,me);
			}
			break;
		case 'l':
			if(bind(tcp_sock,(struct sockaddr *)&remotehost,sizeof(remotehost))<0){
				perror("bind");
				break;
			}
			if(listen(tcp_sock,1)!=0){
				perror("listen");
				break;
			}else{
				CipherPipe(fileno(stdin),fileno(stdout),accept(tcp_sock,NULL,NULL),them,me);
			}
			break;
		default:
			close(tcp_sock);
			usage();
	}
	return 0;
}
