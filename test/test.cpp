#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cassert>
#include <signal.h>

const int BUF_SIZE=100;
int main(int argc, char *argv[]){
    while(true)sleep(3);
    return 0;
    /*
    for(int i=0;i<100;i++){
        int f=fork();
        assert(f>=0);
        if(f!=0)break;
    }
    sleep(2);
        printf("pid=%d\n",getpid());
    return 0;
    int client_sockfd;
    int len;
    struct sockaddr_in remote_addr; //服务器端网络地址结构体
    char buf[BUFSIZ];  //数据传送的缓冲区
    memset(&remote_addr,0,sizeof(remote_addr)); //数据初始化--清零
    remote_addr.sin_family=AF_INET; //设置为IP通信
    puts("inet_addr");
    fflush(stdout);
    remote_addr.sin_addr.s_addr=inet_addr("115.239.210.26");//服务器IP地址
    remote_addr.sin_port=htons(80); //服务器端口号
    
    puts("creating socket");
    fflush(stdout);
    if((client_sockfd=socket(PF_INET,SOCK_STREAM,0))<0)
    {
        perror("socket");
        return 1;
    }
    puts("socket ok");
    fflush(stdout);
    if(connect(client_sockfd,(struct sockaddr *)&remote_addr,sizeof(struct sockaddr))<0)
    {
        perror("connect");
        return 1;
    }
    printf("connected to server\n");
    fflush(stdout);
    
    strcpy(buf,"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
        len=send(client_sockfd,buf,strlen(buf),0);
        len=recv(client_sockfd,buf,BUFSIZ,0);
        buf[len]='\0';
        printf("received:%s\n",buf);
    close(client_sockfd);//关闭套接字
         return 0;
         */
}
