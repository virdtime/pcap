#include "stdio.h"
#include "pcap.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include "stdint.h"

struct ip_header
{
	u_char ip_ver:4;
	u_char ip_hl:4;
	u_char ip_tos:8;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_char ip_ttl;
	u_char protocol;								struct in_addr ip_src, ip_dst;
};

typedef struct Ethernet_
{
	u_char dst[6];
	u_char src[6];
	unsigned short type;
	u_char h_len;
}eth;

typedef struct IP_
{
	u_char h_len;
}IP;

typedef struct TCP_
{
	unsigned int s_port;
	unsigned int d_port;
	u_char h_len;
}TCP;

int main(void)
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[]="port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;
	eth e;
	struct ip_header *ip;
	IP p;
	TCP t;

	dev=pcap_lookupdev(errbuf);
	if(dev==NULL) return(2);
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1) {net=0; mask=0;}
	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL) return(2);
	if(pcap_compile(handle, &fp, filter_exp, 0, net)==-1) return(2);
	if(pcap_setfilter(handle, &fp)==-1) return(2);
	
	while(1)
	{
		pcap_next_ex(handle,&header,&packet);

		for(int i=0; i<6; i++){e.dst[i]=packet[i]; e.src[i]=packet[i+6];}
		e.type=packet[12]+packet[13]*16*16;
		e.h_len=14;

		printf("발신지 MAC주소: ");
		for(int i=0; i<5; i++){printf("%02X:",e.src[i]);}
		printf("%02X\n목적지 MAC주소: ",e.dst[5]);
		for(int i=0; i<5; i++){printf("%02X:",e.dst[i]);}
		printf("%02X\n",e.src[5]);
		if(ntohs(e.type)!=0x800) continue;
		
		ip = (struct ip_header *)(packet + 14);
		
		printf("발신지 IP주소: %s\n",inet_ntoa(ip->ip_src));
		printf("목적지 IP주소: %s\n",inet_ntoa(ip->ip_dst));
		if(ip->protocol !=0x06) continue;
		p.h_len=*(packet+14)*4;
	
		t.s_port=0;
		t.d_port=0;
		t.s_port=packet[e.h_len+p.h_len]*256+packet[e.h_len+p.h_len+1];
		t.d_port=packet[e.h_len+p.h_len+2]*256+packet[e.h_len+p.h_len+3];
		t.h_len=packet[e.h_len+p.h_len+12]/4;

		printf("발신지 포트: ");
		printf("%d\n목적지 포트:",t.s_port);
		printf("%d\n\n",t.d_port);
	
		printf(">>data\n");
		int vird=p.h_len+e.h_len+t.h_len;
		int i=0;
		int j=0;
		u_char buff[16];
		while(1)
		{
			buff[j]=packet[vird+i];
			i++;
			j++;
			if(i%16==0)
			{
				for(int k=0; k<16; k++){printf("%02X ",buff[k]);}
				printf("\t");
				for(int k=0; k<16; k++)
				{
					if(((buff[k]>=0x00) && (buff[k]<=0x20))||buff[k]==0x7f)
					{
						printf("."); 
						continue;
					}
					printf("%c",buff[k]);
				}
				j=0;
				printf("\n");
			}
			if(packet[vird+i]==0)
			{
				for(int k=0; k<i%16; k++){printf("%02X ",buff[k]);}
				for(int k=0; k<16-i%16; k++){printf("   ");}
				printf("\t");
				for(int k=0; k<i%16; k++)
				{
					if(((buff[k]>=0x00) && (buff[k]<=0x20))||buff[k]==0x7f)
					{
						printf("."); 
						continue;
					}
					printf("%c",buff[k]);
				}
				j=0;
				printf("\n\n\n");
				break;
			}
		}
	}
	pcap_close(handle);
	return 0;
}

