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

//TODO: Fix bug in explode numerics that causes the last number in a port sequence to not be saved properly
//TODO: SOmeday support multiple services?

// GLOBALS
pcap_t * pcap_handle;		/* Session handle */
std::string dev;
std::string local_host;

typedef std::vector<Service*> ServiceList;
typedef std::vector<Service*>::const_iterator ServiceListConstIterator;
typedef std::vector<Service*>::iterator ServiceListIterator;

ServiceList services;

void trimNumeric(std::string &in);

bool getService(ServiceListIterator & sit,short port){
	//std::cout << "getService\n";
	ServiceListIterator it = services.begin();
	for(;it != services.end();++it){
		/*
		if(port == (*it)->getTargetPort()){
			std::cout << "Found service for port " << (*it)->getTargetPort() << "\n";
			sit = it;
			return true;
		}*/
	}
	return false;
}


void packet_capture(u_char* args,const struct pcap_pkthdr *header,const u_char* packet){
	std::string remote_ip;
    //struct snsff_ethernet * ptr_eth;
    struct sniff_ip * ptr_ip;
    struct sniff_tcp * ptr_tcp;
    //u_short src_port,dst_port;
    std::string src_ip,dst_ip;
    //u_char* payload;
    u_int size_ip;
    u_int size_tcp;
	
    //ptr_eth = (struct sniff_ethernet*)(packet);
    ptr_ip = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
    size_ip = IP_HL(ptr_ip)*4;
    if (size_ip < 20) {
		//std::cerr << "Invalid IP header length\n";
        return;
    }
    ptr_tcp = (struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet)+ size_ip);
    size_tcp = TH_OFF(ptr_tcp)*4;
    if (size_tcp < 20) {
		//std::cerr << "Invalid TCP header length\n";
        return;
    }

	ServiceListIterator sit;

    src_ip = inet_ntoa(ptr_ip->ip_src);
	if(src_ip != "10.0.0.21"){ return; }
    dst_ip = inet_ntoa(ptr_ip->ip_dst);
	if(dst_ip == local_host){
		unsigned short port = ntohs(ptr_tcp->th_dport);
		std::cout << "Port: " << port << "\n";
		sit = services.begin();
		for(;sit != services.end();++sit){
			int response = (*sit)->knock(src_ip,port);
			if(response == Service::sequence_success){
				std::cout << "[yay] Sequence success. Opening port\n";
				(*sit)->invalidateSequence(src_ip);
			}else if(response == Service::sequence_next){
				std::cout << ".";
			}else if(response == Service::time_exceeded){
				std::cout << "Time exceeded for ip: " << src_ip << "\n";
				std::cout << "Invalidating sequence\n";
				(*sit)->invalidateSequence(src_ip);
			}
		}
	}
	return;
}

bool extractValueMap(ValueMap &vmap,const char* key,std::string & output){
	ValueMapConstIterator it = vmap.find(static_cast<std::string>(key));
	if(it == vmap.end()){
		return false;
	}else{
		output = (*it).second;
		return true;
	}
}

template <typename T>
int explodeNumericCsv(std::string csv,std::vector<T> &output){
	size_t pos = csv.find_first_of(",",0);
	std::string temp;
	std::string copy = csv;
	int ctr =0;
	std::string numerics = "0123456789";
	while(pos != std::string::npos){
		temp = copy.substr(0,pos);
		trimNumeric(temp);
		try{
			T tempInt = std::stoi(temp);
			output.push_back(tempInt);
			ctr++;
		}catch(const std::invalid_argument& ia) {
			std::cerr << "Invalid argument: " << temp << "\n";
			return -1;
		}
		if(copy.length() < pos+1){ break; }
		copy = copy.substr(pos+1);
		pos = copy.find_first_of(',',0);
		if(pos == std::string::npos && copy.length() > 0){
			pos = copy.find_first_not_of(numerics);
			if(pos == std::string::npos){
				pos = copy.length();
			}
			continue;
		}
	}
	return output.size();
}

void trimNumeric(std::string &in){
	size_t pos = in.find_first_not_of("\t\n ",0);
	std::string numerics = "0123456789";
	if(pos == std::string::npos){
		return;
	}
	size_t endPos = in.find_first_not_of(numerics,pos);
	if(endPos == std::string::npos){
		in = in.substr(pos);
		return;
	}
	in = in.substr(pos,endPos-1);
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

	if(local_host.length() == 0){
		std::cerr << "Use -I to specify a target IP address\n";
		return 1;
	}

	FileParser file_parser(config_file);
	if(!file_parser.isOpen()){
		std::cerr << "Unable to continue, file could not be parsed\n";
		return 1;
	}
	file_parser.parse();

	HeaderList header_list;
	if(file_parser.getHeaders(header_list) == 0){
		std::cerr << "No headers specified in config file\n";
		return 2;
	}
	
	HeaderListConstIterator header_list_it = header_list.begin();
	std::string portList,targetPort;
	for(;header_list_it != header_list.end();++header_list_it){
		ValueMap vmap;
		if(file_parser.getValueMap(vmap,*header_list_it) == 0){
			std::cerr << "Header " << *header_list_it << " has no values set\n";
			return 3;
		}else{
			time_t time = 0;
			std::string timeout;
			if(!extractValueMap(vmap,"port",targetPort)){
				std::cerr << "Header " << *header_list_it << " has no 'port' variable set\n";
				return 4;
			}
			if(!extractValueMap(vmap,"sequence",portList)){
				std::cerr << "Header " << *header_list_it << " has no 'sequence' variable set\n";
				return 5;
			}
			if(!extractValueMap(vmap,"timeout",timeout)){
				std::cerr << "Header " << *header_list_it << " has no 'timeout' variable set\n";
				return 7;
			}else{
				try{
					time = std::stoi(timeout);
				}catch(const std::invalid_argument ia){
					std::cerr << "Timeout is invalid\n";
					return 8;
				}
			}

			std::vector<unsigned short> shortPortList;
			if(explodeNumericCsv<unsigned short>(portList,shortPortList) < 0){
				std::cerr << "Error parsing csv\n";
				return 6;
			}
			try{
				Service* serv = new Service(shortPortList,std::stoi(targetPort));
				serv->setTimeInterval(time);
				services.push_back(serv);
			}catch(const std::invalid_argument ia){
				std::cerr << "Port must be a valid number\n";
				return 6;
			}
		}
	}

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
	pcap_close(pcap_handle);
	return(0);
}

