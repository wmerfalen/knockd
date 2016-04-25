#include "TypeDefs.h"
#include "Service.h"
#include "TCPTypes.h"
#include "FileParser.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <pcap/pcap.h>

// GLOBALS
pcap_t * pcap_handle;		/* Session handle */
std::string dev;
std::string local_host;

void packet_capture(u_char* args,const struct pcap_pkthdr *header,const u_char* packet){
	std::string remote_ip;
    struct sniff_ethernet * ptr_eth;
    struct sniff_ip * ptr_ip;
    struct sniff_tcp * ptr_tcp;
    u_short src_port,dst_port;
    std::string src_ip,dst_ip;
    u_char* payload;
    u_int size_ip;
    u_int size_tcp;
	
    ptr_eth = (struct sniff_ethernet*)(packet);
    ptr_ip = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
    size_ip = IP_HL(ptr_ip)*4;
    if (size_ip < 20) {
        //printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    ptr_tcp = (struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet)+ size_ip);
    size_tcp = TH_OFF(ptr_tcp)*4;
    if (size_tcp < 20) {
        //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + sizeof(struct sniff_ethernet) + size_ip + size_tcp);

    src_ip = inet_ntoa(ptr_ip->ip_src);
    dst_ip = inet_ntoa(ptr_ip->ip_dst);

	return;
}

int usage(){
	//TODO: add option for listing active tcp connections
	std::cerr << "usage: knockd -i <device> -c <config_file>\n";
	return 0;
}

int main(int argc, char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	u_char* packet;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	std::string filter_exp = "tcp";
	std::string config_file = "knockd.conf";

	int c = -1;
	int ret;
	struct pcap_pkthdr pkt_hdr;

	while ((c = getopt (argc, argv, "i:c:I:")) != -1){
		switch(c){
			case 'i':
				dev = optarg;
				break;
			case 'c':
				config_file = optarg;
				break;
			case 'I':
				local_host = optarg;
				break;
			case '?':
				std::cerr << "Option: '" << (char)optopt << "' requires an argument\n";
				return 1;
				break;
			default: 
				std::cerr << "Unrecognized option: " << optopt << "\n";
				return 2;
				break;
		}
	}

	FileParser file_parser(config_file);
	if(!file_parser.isOpen()){
		std::cerr << "Unable to continue, file could not be parsed\n";
		return 1;
	}
	file_parser.parse();



	if(dev.length() == 0){
		usage();
		return 3;
	}

	if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
		std::cerr << "Can't get netmask for device: " << dev.c_str() << "\n";
		net = 0;
	 	mask = 0;
	}
	pcap_handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 10, errbuf);
	if (pcap_handle == NULL) {
		std::cerr << "Couldn't open device: "  << dev.c_str() << ": " << errbuf << "\n";
	 	return 4;
	}
	if (pcap_compile(pcap_handle, &fp, filter_exp.c_str(), 0, net) == -1) {
		std::cerr << "Couldn't parse filter " << filter_exp.c_str() << ": " << 
			pcap_geterr(pcap_handle) << "\n";
	 	return 5;
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
	 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(pcap_handle));
	 	return 6;
	}

	std::cout << "Using IP Address: " << local_host.c_str() << "\n";

	ret = pcap_set_immediate_mode(pcap_handle,11);
	if(ret != 0){
		std::cerr << "[warning] unable to set immediate mode\n";
	}
	/* Grab a packet */
	while(1){
		const u_char* packet = pcap_next(pcap_handle,&pkt_hdr);
		if(packet)
				packet_capture(nullptr,&pkt_hdr,packet);
	}
	cleanup:
	pcap_close(pcap_handle);
	return(0);
}

