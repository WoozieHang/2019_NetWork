#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include<sys/time.h>
#include <errno.h>            // errno, perror()
#define ETH_P_DEAN 0x8874 //自定义的以太网协议type
#define MAX_ARP_NUM 100
#define BUFFER_MAX 1024

//to record the time and get the round trip delay
struct timeval Start;
struct timeval End;

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
    unsigned char headerLen_version;
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


typedef struct Arphdr{
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_address_len;
	unsigned char protocol_address_len;
	unsigned short operation_field;
	unsigned char src_mac_addr[6];
	unsigned char src_ip_addr[4];
	unsigned char dest_mac_addr[6];
	unsigned char dest_ip_addr[4];
}ARP_HEADER;


typedef struct MACADDR{
uint8_t mac[6];
}MacAddr;

void InitialMac(MacAddr* mac_addr,uint8_t a,uint8_t b,uint8_t c,uint8_t d,uint8_t e,uint8_t f){
	mac_addr->mac[0] = a;
	mac_addr->mac[1] = b;
	mac_addr->mac[2] = c;
	mac_addr->mac[3] = d;
	mac_addr->mac[4] = e;
	mac_addr->mac[5] = f;
}

struct ARPITEM{
uint32_t ip;
MacAddr mac_addr;
}ArpTable[MAX_ARP_NUM];

int arp_num=0;

void InitialArp(){
	ArpTable[0].ip=(192<<24)+(168<<16)+(2<<8)+2;
	InitialMac(&(ArpTable[0].mac_addr),0x00,0x0c,0x29,0x5d,0x92,0xda);
	arp_num++;
}

int SearchArp(uint32_t ip,MacAddr* mac_addr){
	for(int i=0;i<arp_num;i++){
		if(ArpTable[i].ip==ip){
			*mac_addr=ArpTable[i].mac_addr;			
			return 1;
		}
	}
	return 0;
}

typedef struct LOCALINFO{
	uint32_t ip;
	uint32_t netmask;
	uint32_t gateway;//ip of gateway
	char interface[10];
}LocalInfo;

LocalInfo local_info;

void InitialLocalInfo(){
	local_info.ip=(192<<24)+(168<<16)+(2<<8)+1;
	local_info.netmask=0xffffff00;
	local_info.gateway=(192<<24)+(168<<16)+(2<<8)+2;
	strcpy(local_info.interface,"ens33");
}




uint32_t TranslateIp(char ip[]){
	uint8_t a[4];
	for(int k=0;k<4;k++) a[k]=0;
	
	int i=0;

	for(int j=0;j<4;j++){
		while(ip[i]!='.'&&ip[i]!='\0'){
			a[j]*=10;
			a[j]+=ip[i]-'0';
			i++;	
		}
		i++;
	}
	return (a[0]<<24)+(a[1]<<16)+(a[2]<<8)+a[3];
}

void send_icmp(char* interface,MacAddr dest_mac,uint32_t dest_ip,int pid,int seq){
	int  frame_length, sd;
	uint8_t data[IP_MAXPACKET];
	uint8_t src_mac[6];
	uint8_t ether_frame[IP_MAXPACKET];
	struct sockaddr_ll device;
	struct ifreq ifr;

	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {//第一次创建socket是为了获取本地网卡信息
		perror("socket() failed to get socket descriptor for using ioctl() ");
		exit(EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name,interface);
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl() failed to get source MAC address ");
		exit(EXIT_FAILURE);
	}
	close(sd);

	// Copy source MAC address.
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset(&device, 0, sizeof(device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
		perror("if_nametoindex() failed to obtain interface index ");
		exit(EXIT_FAILURE);
	}
	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, src_mac, 6);
	device.sll_halen = htons(6);

	// Fill out ethernet frame header.
	frame_length =14+20+8+ 56;
	// Destination and Source MAC addresses
	memcpy(ether_frame, dest_mac.mac, 6);
	memcpy(ether_frame + 6, src_mac, 6);

	ether_frame[12] = 0x08;
	ether_frame[13] = 0x00;

	//fill ip header
	IPHeader* ipHeader=(IPHeader*)(&ether_frame[14]);
       
	//use ipv4 and set headlen
         ipHeader->headerLen_version = 0x45;
        //service type
        ipHeader->tos = 0;
        ipHeader->totalLen = htons(sizeof(IPHeader) + sizeof(ICMPHeader)+56);
        ipHeader->id=0;
        //zero flag tag
        ipHeader->flagOffset=0;
        //use icmp protocol
        ipHeader->protocol=IPPROTO_ICMP;
        //time to live
        ipHeader->ttl=255;
	//src addr
	ipHeader->srcIP=htonl(local_info.ip);
        //destination address
        ipHeader->dstIP =htonl(dest_ip);
	//check sum
	ipHeader->checksum=0;
	ipHeader->checksum = htons(check_sum( (unsigned short *)ipHeader,sizeof(IPHeader) + sizeof(ICMPHeader)+56)); 
	
	//fill the icmp
    	ICMPHeader *icmpHeader = (ICMPHeader*)(ipHeader+1);
    	icmpHeader->type = ICMP_ECHO;
    	icmpHeader->code = 0;	
    	icmpHeader->echo.id = htons(pid);
    	icmpHeader->echo.sequence=htons(seq);
    	//caculate the check sum
	icmpHeader->checksum=0;
    	icmpHeader->checksum = check_sum( (unsigned short *)icmpHeader,sizeof(ICMPHeader)+56); 
	
	// Submit request for a raw socket descriptor.
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {//创建正真发送的socket
		perror("socket() failed ");
		exit(EXIT_FAILURE);
	}
	// Send ethernet frame to socket.
	if ((sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof(device))) <= 0) {
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	//after send, record the time
    	gettimeofday(&Start,NULL);
	//sleep(1);
	// Close socket descriptor.
	close(sd);
	
}


bool recieve_icmp(unsigned int seq,int pid){
	int sockfd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
   	 if( sockfd < 0)
    	{
      	  printf("error create raw socket\n");
       	 return -1;
    	}   
    int bufSize=100*1024;
    setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&bufSize,sizeof(bufSize) );
    //build ip head on our own
    bool build_ip_protocol = true;
    int on = 1;
    setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

    	sockaddr_in cliaddr;
    	memset(&cliaddr,0,sizeof(cliaddr));
    	socklen_t cliLen = sizeof(cliaddr);

    //use select unblock style
    fd_set rfds;
    struct timeval timeout={1,0};
    FD_ZERO(&rfds);
    FD_SET(sockfd,&rfds);
    int tag=select(sockfd+1,&rfds,NULL,NULL,&timeout);
    if(tag<0){
close(sockfd);
	 return 0;
}
    //if overtime then remind you
    else if(tag==0){
    	printf("From This Host icmp_seq=%d Destination Host Unreachable\n",seq);
	close(sockfd);
    	return 1;
    }

    //if not change return else recieve
    else if(FD_ISSET(sockfd,&rfds)==0){
	printf("not change\b");
	close(sockfd);
    	return 0;
    }
	
    char recvBuf[256] = "";
    int recvLen = recvfrom(sockfd,recvBuf,sizeof(recvBuf),0,(sockaddr*)&cliaddr,&cliLen);
    //update the recieve time after recieve
	/*printf("\n");
	for(int i=0;i<84;i++)	
	printf("%x",0xff&((uint32_t)recvBuf[i]));
	printf("\n");*/
    gettimeofday(&End,NULL);
	
    if( recvLen <0){
	close(sockfd);
        return 0;
    }
	//check dst mac whether is mine
if(recvBuf[0]!=0x00){
	//printf("buffer[0] wrong\n");
	close(sockfd);
	return 0;
}
if(recvBuf[1]!=0x0c){
	//printf("buffer[1] wrong\n");
	close(sockfd);
	return 0;
}
if(recvBuf[2]!=0x29){
	//printf("buffer[2] wrong\n");
	close(sockfd);
	return 0;
}
if(recvBuf[3]!=0x68){
	//printf("buffer[3] wrong\n");
	close(sockfd);
	return 0;
}
if(recvBuf[4]!=0x60){
	//printf("buffer[4] wrong\n");
	close(sockfd);
	return 0;
}
if(recvBuf[5]!=(char)(0xfb)){
	//printf("buffer[5] wrong\n");
	close(sockfd);
	return 0;
}
    IPHeader *ipHeader = (IPHeader*)(recvBuf+14);
    int ipHeaderLen = sizeof(IPHeader);
    //find the head of icmp by skipping the ip head
    ICMPHeader *icmpHeader = (ICMPHeader *)(recvBuf+sizeof(IPHeader)+14);  
    
    
    int icmpLen = recvLen - ipHeaderLen-14;
    //the icmp can not shorter than 8 bytes
    if( icmpLen < 8){
       	close(sockfd);
	return 0;
    }
//printf("icmp len check pass\n");
    //ensure it is a reply icmp to my request icmp
	//printf("type:%x,echo:0x00,id:%x,pid:%x\n",icmpHeader->type,ntohs(icmpHeader->echo.id),pid);
    if(icmpHeader->type!=ICMP_ECHOREPLY || ntohs(icmpHeader->echo.id)!=pid)
	return 0;
    //printf("icmp type and id check pass\n");
    //print the information!
    printf("%d bytes from %s: icmp_seq=%d ttl=%d",icmpLen,inet_ntoa(cliaddr.sin_addr),ntohs(icmpHeader->echo.sequence),ipHeader->ttl);
    
    //caculate and print the round trip delay (ms)
      double t=((double)(End.tv_usec-Start.tv_usec))/1000;
	printf(" time=%.3lf ms\n",t);
	close(sockfd);
    	return 1;

}


int main(int argc, char **argv)
{
	int pid=getpid();
	//initial arp( delete later)
	InitialArp();

	//first check if the input is legal and config the local infomation
	if(argc!=2){	
		printf("illegal input!\n");
		return 0;
	}
	
	InitialLocalInfo();
	//second, check the relationship between destination ip and local ip using netmask
	uint32_t dest_ip=TranslateIp(argv[1]);
	printf("PING %s ",argv[1]);
    	printf("56(84) bytes of data.\n");
	if((dest_ip&local_info.netmask)!=(local_info.ip&local_info.netmask)){
		//not same subnet
		MacAddr mac_addr;
		
		if(SearchArp(local_info.gateway,&mac_addr)){
			int seq=0;
			while(1){
				send_icmp(local_info.interface,mac_addr,dest_ip,pid,seq);
				while(recieve_icmp(seq,pid)==0)
						;
				seq++;
				if(seq%3==2)
				sleep(1);
			}		
		}
		else{
			printf("to do send arp package and update arp table\n");
		}
	}
	else printf("to do same subnet case\n");

	return 1;
}



