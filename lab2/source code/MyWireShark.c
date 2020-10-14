#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<netinet/in.h>
#define BUFFER_MAX 2048
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

//return the protocol, it is ip or arp or rarp?
int AnalyseEth(char* eth_head){
		printf("***********************************************************\n");
		printf("(Ethernet analyse)\n");
		unsigned char* p=eth_head;
                printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
                if(p[12]==0x08&&p[13]==0x00){
			printf("type:ip\n");
			return 1;
		}
		else if(p[12]==0x08&&p[13]==0x06){
			printf("type:arp\n");
			return 2;
		}
		else if(p[12]==0x80&&p[13]==0x35){
			printf("type:rarp\n");
			return 3;
		}
		else{
			printf("type:unknown\n");
			return 0;
		}

}
//return the protocol,it is tcp or udp or icmp or igmp
int AnalyseIp(IP_HEADER* ip_head){
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

		unsigned char* src=&(ip_head->src_ip);
		unsigned char* dest=&(ip_head->dest_ip);
                printf("IP:%d.%d.%d.%d ==> %d.%d.%d.%d\n",src[0],src[1],src[2],src[3],dest[0],dest[1],dest[2],dest[3]);
		printf("***********************************************************\n");
                return (int)ip_head->proto;
}

void AnalyseIcmp(ICMP_HEADER* icmp_head){
	printf("(icmp analysis)\n");
	printf("type:0x%x\ncode:0x%x\n",icmp_head->type,icmp_head->code);
	printf("check sum:0x%x\n",ntohs(icmp_head->check_sum));
	printf("identity:0x%x\n",ntohs(icmp_head->id));
	printf("sequent num:0x%x\n",ntohs(icmp_head->seq_num));
	printf("***********************************************************\n");	
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

int main(int argc,char* argv[]){
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
		printf("<start>\n===========================================================\n");
		//eth analysis
		eth_head=buffer;
		int proto_choice=AnalyseEth(eth_head);
	
	//ip analysis
		if(proto_choice==1){
			ip_head=(IP_HEADER*)(eth_head+14);
			int proto=AnalyseIp(ip_head);
			unsigned int off=(ip_head->head_version_len&0xf)*4;
			switch(proto){
				case IPPROTO_ICMP:{
					//icmp analysis
				       	icmp_head=(ICMP_HEADER*)((char*)ip_head+off);
					AnalyseIcmp(icmp_head);
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
