#include <stdio.h>
#include<sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include<iostream>

//to record the time and get the round trip delay
struct timeval Start;
struct timeval End;
//ICMP head
struct ICMPHeader
{
    unsigned char type;//icmp type
    unsigned char code;//icmp code 
    unsigned short checksum;//check sum
    struct{
       unsigned short id;
       unsigned short sequence;
    }echo;
    unsigned char data[0];//ICMP data parts
};

//ip head
struct IPHeader
{
    unsigned char headerLen:4;
    unsigned char version:4;
    unsigned char tos; //service type
    unsigned short totalLen; //total length
    unsigned short id; //tag
    unsigned short flagOffset; //3 bits flag+13 bits offset
    unsigned char ttl; //time to live
    unsigned char protocol; //protocol
    unsigned short checksum; //check sum
    unsigned int srcIP; //source ip address
    unsigned int dstIP; //destination ip address
};

//the algorithm of calculating the check sum
unsigned short check_sum(unsigned short *addr,int len)
{
    int sum=0;
    int index=0;
    //add the every 8 bytes part
    while(len>1)
    {
        sum+=addr[index];
	index++;
        len-=2;
    }

    //add the last single byte
    if( len==1)
        sum+=addr[index]&0xff;

    //add the hign 2 bytes as a short type into the low 2 bytes
    sum=(sum>>16)+(sum&0xffff);
    return ~sum;
}

//send icmp
void send_icmp_packet(unsigned int seq,int sockfd,sockaddr_in* dst_addr,int pid,bool build_ip_protocl)
{
    char sendBuf[1024] = "";

    int totalLen = sizeof(IPHeader) + sizeof(ICMPHeader)+56;
    //to get the postion of each head
    int pos = 0;
    //fill the ip packet
    if(build_ip_protocl)
    {
        IPHeader* ipHeader = (IPHeader *)sendBuf;
        ipHeader->headerLen = sizeof(IPHeader)>>2;
	//use ipv4
        ipHeader->version = 0x4;
        //service type
        ipHeader->tos = 0;
        ipHeader->totalLen = htons(totalLen);
        ipHeader->id=0;
        //zero flag tag
        ipHeader->flagOffset=0;
        //use icmp protocol
        ipHeader->protocol=IPPROTO_ICMP;
        //time to live
        ipHeader->ttl=255;
        //destination address
        ipHeader->dstIP = dst_addr->sin_addr.s_addr;
        pos = sizeof(IPHeader);
    }

    //fill the icmp
    ICMPHeader *icmpHeader = (ICMPHeader*)(sendBuf+pos);
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->echo.id = htons(pid);
    icmpHeader->echo.sequence=htons(seq);
    //caculate the check sum
    icmpHeader->checksum = check_sum( (unsigned short *)icmpHeader,totalLen); 
    if(sendto(sockfd,sendBuf,totalLen,0,(struct sockaddr *)dst_addr,sizeof(*dst_addr))<0){
        printf("sendto error!\n");
    }
    //after send, record the time
    gettimeofday(&Start,NULL);

}


//decode the recieve package
bool recieve_icmp_packet(unsigned int seq,int sockfd,int pid){
    sockaddr_in cliaddr;
    memset(&cliaddr,0,sizeof(cliaddr));
    socklen_t cliLen = sizeof(cliaddr);

    //use select unblock style
    fd_set rfds;
    struct timeval timeout={0,300000};
    FD_ZERO(&rfds);
    FD_SET(sockfd,&rfds);
    int tag=select(sockfd+1,&rfds,NULL,NULL,&timeout);
    if(tag<0)
	 return 0;

    //if overtime then remind you
    else if(tag==0){
    	printf("From This Host icmp_seq=%d Destination Host Unreachable\n",seq);
    	return 1;
    }

    //if not change return else recieve
    else if(FD_ISSET(sockfd,&rfds)==0){
	printf("not change\b");
    	return 0;
    }
    char recvBuf[256] = "";
    
    int recvLen = recvfrom(sockfd,recvBuf,sizeof(recvBuf),0,(sockaddr*)&cliaddr,&cliLen);
    //update the recieve time after recieve
    gettimeofday(&End,NULL);
	
    if( recvLen <0)
        return 0;

    IPHeader *ipHeader = (IPHeader*)recvBuf;
    int ipHeaderLen = sizeof(IPHeader);
    //find the head of icmp by skipping the ip head
    ICMPHeader *icmpHeader = (ICMPHeader *)(recvBuf+sizeof(IPHeader));  
    
    
    int icmpLen = recvLen - ipHeaderLen;
    //the icmp can not shorter than 8 bytes
    if( icmpLen < 8)
       	return 0;

    //ensure it is a reply icmp to my request icmp
    if(icmpHeader->type!=ICMP_ECHOREPLY || ntohs(icmpHeader->echo.id)!=pid)
	return 0;
    
    //print the information!
    printf("%d bytes from %s: icmp_seq=%d ttl=%d",icmpLen,inet_ntoa(cliaddr.sin_addr),ntohs(icmpHeader->echo.sequence),ipHeader->ttl);
    
    //caculate and print the round trip delay (ms)
      double t=((double)(End.tv_usec-Start.tv_usec))/1000;
      printf(" time=%.3lf ms\n",t);
    return 1;

}


int main(int argc,char* argv[])
{

    //create a socket
    int sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if( sockfd < 0)
    {
        printf("error create raw socket\n");
        return -1;
    }
    //config the socket
    //enhance the buffer to 100kb
    int bufSize=100*1024;
    setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&bufSize,sizeof(bufSize) );
    //build ip head on our own
    bool build_ip_protocol = true;
    int on = 1;
    setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

    //both host name and ip address are viable
    //host name like:www.baidu.com
    sockaddr_in dst_addr;
    //clear the dest address
    memset(&dst_addr,0,sizeof(dst_addr));
    dst_addr.sin_family=AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(argv[1]);
	
    //if internet address is 255.255.255.255,in other words,broadcast
    if( dst_addr.sin_addr.s_addr == INADDR_NONE)
    {
	//get the host name
        hostent *host=gethostbyname(argv[1]);
        if(host==NULL) 
        {
            printf("get host name error!\n");
            return -1;
        }
	//put the dest address from host structure to socketaddr_in structure
        memcpy( (char *)&dst_addr.sin_addr,host->h_addr,host->h_length);
    }

    //attain the process id of main to set the tag value of icmp package
    int pid=getpid();

    printf("PING %s",argv[1]);
    printf(" (%s",inet_ntoa(dst_addr.sin_addr));
    printf(") 56(84) bytes of data.\n");
    unsigned int seq=1;
   while(1){
	 send_icmp_packet(seq,sockfd,&dst_addr,pid,build_ip_protocol);
    	//decode the all the icmp, and end up with finding the respond icmp
    	while(recieve_icmp_packet(seq,sockfd,pid)==0)
		;
	seq++;
	//send one request icmp every second
	sleep(1);
}
    close(sockfd);
    return 0;

}

