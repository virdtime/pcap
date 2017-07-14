#include "stdio.h"
#include "pcap.h"

typedef struct ethernet_
{
	u_char dst[6];
	u_char src[6];
	unsigned short type;
}eth;

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

	printf("src_mac: ");
	for(int i=0; i<5; i++){printf("%02X:",e.src[i]);}
	printf("%X\ndst_mac: ",e.dst[5]);
	for(int i=0; i<5; i++){printf("%02X:",e.dst[i]);}
	printf("%02X\n",e.src[5]);

	printf("type: %X\n",e.type);

	return(0);
}

