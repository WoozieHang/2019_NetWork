#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<netinet/in.h>
#include<string.h>
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

#define BUFFER_MAX 2048
#define MAX_TABLE_NUM 100

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


typedef struct Iphdr{
	unsigned char head_version_len;//4 bits for length of head and 4 bits for the version id
	unsigned char tos;//1 byte for service type tos
	unsigned short total_len;//2 bytes for total length
	unsigned short id;//2 bytes for identity
	unsigned short flags;//flags
	unsigned char ttl;//1 bytes time to live
	unsigned char proto;//1 bytes protocol
	unsigned short check_sum;//2 bytes check sum of ip head
	unsigned int src_ip;//4 bytes source address of ip
	unsigned int dest_ip;//4 bytes destination address of ip
}IP_HEADER;

typedef struct Icmphdr{
	unsigned char type;
	unsigned char code;
	unsigned short check_sum;
	unsigned short id;
	unsigned short seq_num;

}ICMP_HEADER;

typedef struct Tcphdr{
	unsigned short src_port;
	unsigned short dest_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char len_rest;
	unsigned char flag;
	unsigned short windows;
	unsigned short check_sum;
	unsigned short urgent_pointer;
}TCP_HEADER;

typedef struct Udphdrp{
	unsigned short src_port;
	unsigned short dest_port;
	unsigned int len;
	unsigned int check_sum;
}UDP_HEADER;

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

struct ROUTERITEM{
	uint32_t ip;
	uint32_t next_hop;
	char interface[10];
	uint32_t netmask;
}RouterTable[MAX_TABLE_NUM];

int router_num=0;

void InitialRouter(){
	RouterTable[0].ip=(192<<24)+(168<<16)+(4<<8)+2;
	RouterTable[0].next_hop=(192<<24)+(168<<16)+(3<<8)+2;
	strcpy(RouterTable[0].interface,"ens38");
	RouterTable[0].netmask=0xffffff00;
	router_num++;
}

int SearchRouter(uint32_t ip){
	for(int i=0;i<router_num;i++){
		//printf("router table[%d].ip:%x\n",i,RouterTable[i].ip);
		//printf("ip:%x\n",ip);
		if(RouterTable[i].ip==ip){	
			return i;
		}
	}
	//printf("ip:%d.%d.%d.%d\n",(ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,(ip)&0xff);	
	return -1;
}

struct ARPITEM{
uint32_t ip;
MacAddr mac_addr;
}ArpTable[MAX_TABLE_NUM];

int arp_num=0;

void InitialArp(){
	ArpTable[0].ip=(192<<24)+(168<<16)+(3<<8)+2;
	InitialMac(&(ArpTable[0].mac_addr),0x00,0x0c,0x29,0x3f,0x68,0xe4);
	arp_num++;
}

void DelArp(uint32_t ip){
	for(int i=0;i<arp_num;i++){
		if(ArpTable[i].ip==ip){
			for(int j=i+1;j<arp_num;j++)
			ArpTable[j-1]=ArpTable[j];
			arp_num--;
		}
	}
}

void UpdateArp(uint32_t ip,MacAddr mac_addr){
	DelArp(ip);
	ArpTable[arp_num].ip=ip;
	ArpTable[arp_num].mac_addr=mac_addr;
	arp_num++;
}

void ShowArp(){
	for(int i=0;i<arp_num;i++){
		printf("\n<arp table>\n");
		printf("ip:%d.%d.%d.%d ",(ArpTable[i].ip>>24)&0xff,(ArpTable[i].ip>>16)&0xff,(ArpTable[i].ip>>8)&0xff,ArpTable[i].ip&0xff);
		printf("<-> ");
		printf("mac:%x:%x:%x:%x",ArpTable[i].mac_addr.mac[0],ArpTable[i].mac_addr.mac[1],ArpTable[i].mac_addr.mac[2],ArpTable[i].mac_addr.mac[3]);
		printf(":%x:%x",ArpTable[i].mac_addr.mac[4],ArpTable[i].mac_addr.mac[5]);
		printf("\n");	
	}
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


//return the protocol, it is ip or arp or rarp?
int AnalyseEth(char* eth_head,int* interface_num,MacAddr* src_addr){
		
		//printf("(Ethernet analyse)\n");
		unsigned char* p=eth_head;
               // printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
		if(p[0]==0x00&&p[1]==0x0c&&p[2]==0x29&&p[3]==0x05&&p[4]==0xf6&&p[5]==0x08){
			*interface_num=0;
			printf("<start>\n===========================================================\n");
			printf("***********************************************************\n");		
			printf("an ether frame from interface ens39\n");
		}
		else {
			*interface_num=-1;
			return -1;
		}
		
		InitialMac(src_addr,p[6],p[7],p[8],p[9],p[10],p[11]);

                if(p[12]==0x08&&p[13]==0x00){
			//printf("type:ip\n");
			return 1;
		}
		else if(p[12]==0x08&&p[13]==0x06){
			//printf("type:arp\n");
			return 2;
		}
		else if(p[12]==0x80&&p[13]==0x35){
			//printf("type:rarp\n");
			return 3;
		}
		else{
			//printf("type:unknown\n");
			return 0;
		}

}
//return the protocol,it is tcp or udp or icmp or igmp
int AnalyseIp(IP_HEADER* ip_head,uint32_t* src_ip,uint32_t* dst_ip){
		printf("***********************************************************\n");
		printf("(Ip analyse)\n");
		unsigned head_len=(ip_head->head_version_len&0xf)*4;
		printf("head length of ip:0x%x(%d) bytes\n",head_len,head_len);
		
		unsigned version_id=(ip_head->head_version_len>>4)&0xf;
		printf("version id:0x%x\n",version_id);
		

		printf("tos:%x\ntotal len:0x%x\n",ip_head->tos,ntohs(ip_head->total_len));
		printf("id:0x%x\nflag:0x%x\nttl:0x%x\n",ntohs(ip_head->id),ntohs(ip_head->flags),ip_head->ttl);
		printf("protocol:0x%x",ip_head->proto);
		switch(ip_head->proto){
			 case IPPROTO_ICMP:printf("(icmp)\n");break;
                         case IPPROTO_IGMP:printf("(igmp)\n");break;
                         case IPPROTO_IPIP:printf("(ipip)\n");break;
                         case IPPROTO_TCP:printf("(tcp)\n");break;
                         case IPPROTO_UDP:printf("(udp)\n");break;
                         default:printf("(unknown)\n");
		}
                printf("check sum:0x%x\n",ntohs(ip_head->check_sum));

		unsigned char* src=(unsigned char*)&(ip_head->src_ip);
		unsigned char* dest=(unsigned char*)&(ip_head->dest_ip);
                printf("IP:%d.%d.%d.%d ==> %d.%d.%d.%d\n",src[0],src[1],src[2],src[3],dest[0],dest[1],dest[2],dest[3]);
		*src_ip=(src[0]<<24)+(src[1]<<16)+(src[2]<<8)+src[3];
		*dst_ip=(dest[0]<<24)+(dest[1]<<16)+(dest[2]<<8)+dest[3];
		printf("***********************************************************\n");
                return (int)ip_head->proto;
}

int AnalyseIcmp(ICMP_HEADER* icmp_head){
	printf("(icmp analysis)\n");
	printf("type:0x%x\ncode:0x%x\n",icmp_head->type,icmp_head->code);
	printf("check sum:0x%x\n",ntohs(icmp_head->check_sum));
	printf("identity:0x%x\n",ntohs(icmp_head->id));
	printf("sequent num:0x%x\n",ntohs(icmp_head->seq_num));
	printf("***********************************************************\n");	
	if(icmp_head->type==0x08)
		return 1;
	else return 0;
}

void AnalyseTCP(TCP_HEADER* tcp_head){
	printf("(tcp analysis)\n");
	printf("source port:0x%x\ndestination port:0x%x\n",ntohs(tcp_head->src_port),ntohs(tcp_head->dest_port));
	printf("sequence num:0x%x\nacknowledge id:0x%x\n",ntohs(tcp_head->seq),ntohs(tcp_head->ack));
	printf("len/res:0x%x\n",tcp_head->len_rest);
	printf("flag:0x%x\nwindows size:0x%x\ncheck sum:0x%x\nurgent pointer:0x%x\n",tcp_head->flag,ntohs(tcp_head->windows),ntohs(tcp_head->check_sum),ntohs(tcp_head->urgent_pointer));
	printf("***********************************************************\n");
}

void AnalyseUDP(UDP_HEADER* udp_head){
	printf("(udp analysis)\n");
        printf("source port:0x%x\ndestinaiton port:0x%x\n",ntohs(udp_head->src_port),ntohs(udp_head->dest_port));
        printf("length:0x%x\n",ntohs(udp_head->len));
        printf("check sum:0x%x\n",ntohs(udp_head->check_sum));
	printf("***********************************************************\n");
}

void AnalyseArp(ARP_HEADER* arp_head){
        printf("(arp analysis)\n");
        printf("hardware type:0x%x\n",ntohs(arp_head->hardware_type));
        printf("protocol type:0x%x\n",ntohs(arp_head->protocol_type));
        printf("hardward address len:0x%x\nprotocol address len:0x%x\n",arp_head->hardware_address_len,arp_head->protocol_address_len);
        printf("operation field:0x%x\n",ntohs(arp_head->operation_field));
        printf("source MAC address: ");
        printf("%x:%x:%x:%x:%x:%x\n",arp_head->src_mac_addr[0],arp_head->src_mac_addr[1],arp_head->src_mac_addr[2],arp_head->src_mac_addr[3],arp_head->src_mac_addr[4],arp_head->src_mac_addr[5]);
        printf("destination MAC field: ");
        printf("%x:%x:%x:%x:%x:%x\n",arp_head->dest_mac_addr[0],arp_head->dest_mac_addr[1],arp_head->dest_mac_addr[2],arp_head->dest_mac_addr[3],arp_head->dest_mac_addr[4],arp_head->dest_mac_addr[5]);
        printf("source ip address: ");
        printf("%d.%d.%d.%d\n",arp_head->src_ip_addr[0],arp_head->src_ip_addr[1],arp_head->src_ip_addr[2],arp_head->src_ip_addr[3]);
        printf("destination ip address: ");
        printf("%d.%d.%d.%d\n",arp_head->dest_ip_addr[0],arp_head->dest_ip_addr[1],arp_head->dest_ip_addr[2],arp_head->dest_ip_addr[3]);
        printf("***********************************************************\n");
}  

void AnalyseRarp(ARP_HEADER* arp_head){
        printf("(rarp analysis)\n");
        printf("hardware type:0x%x\n",ntohs(arp_head->hardware_type));
        printf("protocol type:0x%x\n",ntohs(arp_head->protocol_type));
        printf("hardward address len:0x%x\nprotocol address len:0x%x\n",arp_head->hardware_address_len,arp_head->protocol_address_len);
        printf("operation field:0x%x\n",ntohs(arp_head->operation_field));
        printf("source MAC address: ");
        printf("%x:%x:%x:%x:%x:%x\n",arp_head->src_mac_addr[0],arp_head->src_mac_addr[1],arp_head->src_mac_addr[2],arp_head->src_mac_addr[3],arp_head->src_mac_addr[4],arp_head->src_mac_addr[5]);
        printf("destination MAC field: ");
        printf("%x:%x:%x:%x:%x:%x\n",arp_head->dest_mac_addr[0],arp_head->dest_mac_addr[1],arp_head->dest_mac_addr[2],arp_head->dest_mac_addr[3],arp_head->dest_mac_addr[4],arp_head->dest_mac_addr[5]);
        printf("source ip address: ");
        printf("%d.%d.%d.%d\n",arp_head->src_ip_addr[0],arp_head->src_ip_addr[1],arp_head->src_ip_addr[2],arp_head->src_ip_addr[3]);
        printf("destination ip address: ");
        printf("%d.%d.%d.%d\n",arp_head->dest_ip_addr[0],arp_head->dest_ip_addr[1],arp_head->dest_ip_addr[2],arp_head->dest_ip_addr[3]);
        printf("***********************************************************\n");
}


void Reply(char* interface,uint32_t dest_ip,MacAddr dest_mac,char* buffer){
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

	ether_frame[12] = buffer[12];
	ether_frame[13] = buffer[13];

	//fill ip header
	IP_HEADER* ipHeader=(IP_HEADER*)(&ether_frame[14]);
       IP_HEADER* copy_ipHeader=(IP_HEADER*)(&buffer[14]);
	//use ipv4 and set headlen
         ipHeader->head_version_len =copy_ipHeader->head_version_len;
        //service type
        ipHeader->tos = copy_ipHeader->tos ;
        ipHeader->total_len = copy_ipHeader->total_len;
        ipHeader->id=copy_ipHeader->id;
        //zero flag tag
        ipHeader->flags=copy_ipHeader->flags;
        //use icmp protocol
        ipHeader->proto=copy_ipHeader->proto;
        //time to live
        ipHeader->ttl=255;
	//src addr
	ipHeader->src_ip=copy_ipHeader->dest_ip;
        //destination address
        ipHeader->dest_ip =copy_ipHeader->src_ip;
	//check sum
	ipHeader->check_sum=0;
	ipHeader->check_sum = htons(check_sum( (unsigned short *)ipHeader,sizeof(IP_HEADER) + sizeof(ICMP_HEADER)+56)); 
	
	//fill the icmp
    	ICMP_HEADER* icmpHeader = (ICMP_HEADER*)(ipHeader+1);
	ICMP_HEADER* copy_icmpHeader=(ICMP_HEADER*)(copy_ipHeader+1);
    	icmpHeader->type = 0x00;
    	icmpHeader->code = copy_icmpHeader->code;	
    	icmpHeader->id = copy_icmpHeader->id;
    	icmpHeader->seq_num=copy_icmpHeader->seq_num;
    	//caculate the check sum
	icmpHeader->check_sum=0;
    	icmpHeader->check_sum = check_sum( (unsigned short *)icmpHeader,sizeof(ICMP_HEADER)+56); 
	
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
	//sleep(1);
	// Close socket descriptor.
	close(sd);
	//sleep(1);
}

int main(int argc,char* argv[]){
	//remeber to delete it when finish arp protocol!
	InitialArp();

	InitialRouter();

	int sock_fd;
	int n_read;
	char buffer[BUFFER_MAX];
	char* eth_head;
	IP_HEADER* ip_head;
	TCP_HEADER* tcp_head;
	UDP_HEADER* udp_head;
	ICMP_HEADER* icmp_head;
	ARP_HEADER* arp_head;
	
	
	sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//printf("sock_fd:%d\n",sock_fd);
	if(sock_fd<0){
		printf("error create raw socket\n");
		return -1;
	}
	while(1){
		n_read=recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read<42){
			printf("error when recv msg\n");
			return -1;
		}
		
		//eth analysis
		eth_head=buffer;
		int interface_num;
		MacAddr src_mac;
		uint32_t src_ip,dst_ip;
		int proto_choice=AnalyseEth(eth_head,&interface_num,&src_mac);
		if(interface_num==-1)
			continue;
		
		//ip analysis
		if(proto_choice==1){
			ip_head=(IP_HEADER*)(eth_head+14);
			int proto=AnalyseIp(ip_head,&src_ip,&dst_ip);
			//update arp table using src ip and src mac			
			UpdateArp(src_ip,src_mac);
			unsigned int off=(ip_head->head_version_len&0xf)*4;
			switch(proto){
				case IPPROTO_ICMP:{
					//icmp analysis
				       	icmp_head=(ICMP_HEADER*)((char*)ip_head+off);
					if(AnalyseIcmp(icmp_head)==1){
						//send reply icmp
						Reply("ens39",src_ip,src_mac,buffer);
					}
					break;
				}
				case IPPROTO_IGMP:{printf("igmp\n");break;}
				case IPPROTO_IPIP:printf("ipip\n");break;
				case IPPROTO_TCP:{
					//tcp analysis
					tcp_head=(TCP_HEADER*)((char*)ip_head+off);
					AnalyseTCP(tcp_head);
					break;		 
				}
				case IPPROTO_UDP:{
					//udp analysis
                                       	udp_head=(UDP_HEADER*)((char*)ip_head+off);
                                        AnalyseUDP(udp_head);
                                        break;
                                }
				default:printf("Pls query yourself\n");
			}
		}
		else if(proto_choice==2){
			//arp analysis
			arp_head=(ARP_HEADER*)(eth_head+14);
			AnalyseArp(arp_head);
		}
		else if(proto_choice==3){
			//rarp analysis
			arp_head=(ARP_HEADER*)(eth_head+14);
			AnalyseRarp(arp_head);
		}
		else {
			printf("unknown protocol!\n");
		}
		printf("===========================================================\n<end>\n\n\n\n\n");
	}
	return -1;
}
