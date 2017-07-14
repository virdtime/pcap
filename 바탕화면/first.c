#include "stdio.h"
#include "pcap.h"

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

	dev=pcap_lookupdev(errbuf);
	if(dev==NULL) return(2);
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1) {net=0; mask=0;}
	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL) return(2);
	if(pcap_compile(handle, &fp, filter_exp, 0, net)==-1) return(2);
	if(pcap_setfilter(handle, &fp)==-1) return(2);
	pcap_next_ex(handle,&header,&packet);
	for(int i=0; i<100; i++){printf("%X ",packet[i]);}
	printf("\n");
	pcap_close(handle);
	return(0);
}
