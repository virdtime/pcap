#include "stdio.h"
#include "pcap.h"

typedef struct Ethernet_
{
	u_char dst[6];
	u_char src[6];
	unsigned short type;
	u_char h_len;
}eth;

typedef struct IP_
{
	u_char version;
	u_char h_len;
	u_char SIP[4];
	u_char DIP[4];
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
	IP p;
	TCP t;

	dev=pcap_lookupdev(errbuf);
	if(dev==NULL) return(2);
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1) {net=0; mask=0;}
	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL) return(2);
	if(pcap_compile(handle, &fp, filter_exp, 0, net)==-1) return(2);
	if(pcap_setfilter(handle, &fp)==-1) return(2);
	pcap_next_ex(handle,&header,&packet);

	for(int i=0; i<6; i++){e.dst[i]=packet[i]; e.src[i]=packet[i+6];}
	e.type=packet[12]+packet[13]*16*16;
	e.h_len=14;

	printf("dst: ");
	for(int i=0; i<5; i++){printf("%02X:",e.dst[i]);}
	printf("%02X\nsrc: ",e.dst[5]);
	for(int i=0; i<5; i++){printf("%02X:",e.src[i]);}
	printf("%02X\n",e.src[5]);
	printf("type: %X\n",e.type);

	p.version=(packet[e.h_len]>>4);
	p.h_len=(packet[e.h_len] & 0x0F)*4;
	for(int i=0; i<4; i++){p.SIP[i]=packet[12+e.h_len+i]; p.DIP[i]=packet[16+e.h_len+i];}
	
	printf("src: ");
	for(int i=0; i<3; i++){printf("%d.",p.SIP[i]);}
	printf("%d\ndst: ",p.SIP[3]);
	for(int i=0; i<3; i++){printf("%d.",p.DIP[i]);}
	printf("%d\n",p.DIP[3]);
	
	t.s_port=0;
	t.d_port=0;
	t.s_port=packet[e.h_len+p.h_len]*256+packet[e.h_len+p.h_len+1];
	t.d_port=packet[e.h_len+p.h_len+2]*256+packet[e.h_len+p.h_len+3];
	t.h_len=packet[e.h_len+p.h_len+12];

	printf("src: ");
	printf("%d\ndst:",t.s_port);
	printf("%d\n",t.d_port);
	return(0);
}

