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

//TODO: enable emailing of ports knocked
//TODO: enable hitting utils.slowip.net whenever a port knock is successful

// GLOBALS
pcap_t * pcap_handle;		/* Session handle */
std::string dev;
std::string local_host;
bool use_udp = false;
bool use_tcp = false;
bool exitProgram = false;

typedef std::vector<Service*> ServiceList;
typedef std::vector<Service*>::const_iterator ServiceListConstIterator;
typedef std::vector<Service*>::iterator ServiceListIterator;
typedef struct _command { std::string start; std::string end; std::string ip_address; time_t timeout; } RegisteredCommand;
typedef std::vector<RegisteredCommand> RegisteredCommandList;

ServiceList services;
RegisteredCommandList registeredCommands;

void trimNumeric(std::string &in);
void trimString(std::string &);
bool headerTypeRequired(int,const char*);
bool hasElement(std::vector<const char*>,const char*);

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
bool hasElement(std::vector<const char*>v,const char* entry){
	return (std::find(v.begin(),v.end(),entry) != v.end());
}

bool headerTypeRequired(int headerType,const char* entry){
	std::vector<const char*> cleanup = { "sequence","timeout","type" };
	std::vector<const char*> commandTrigger = {
		"sequence","timeout","port","command_start","command_timeout","command_end","type"
	};
	if(headerType == Service::header_type_cleanup){
		return hasElement(cleanup,entry);
	}
	if(headerType == Service::header_type_command_trigger){
		return hasElement(commandTrigger,entry);
	}
	return false;
}

void interpolateCommand(std::string &str,std::string ip){
	//LOL fix this
	char buffer[str.length() + ip.length()];
	sprintf(buffer,str.c_str(),ip.c_str());
	str = buffer;
}

void registerCommand(std::string start,std::string end,std::string ipAddress,time_t commandTimeout){
	RegisteredCommand m;
	m.start = start;
	m.end = end;
	m.ip_address = ipAddress;
	m.timeout = commandTimeout;
	//TODO: sanitize
	interpolateCommand(m.start,ipAddress);
	interpolateCommand(m.end,ipAddress);
	registeredCommands.push_back(m);
	int ret = system(m.start.c_str());
	std::cout << "Ran: " << m.start << "\n";
	std::cout << "return value: " << ret << "\n";
}

void processCommands(){
	RegisteredCommandList::iterator it = registeredCommands.begin();
	RegisteredCommandList::iterator end_it = registeredCommands.end();
	if(it == end_it) return; 
	RegisteredCommandList r;
	for(; it != registeredCommands.end();++it){
		if((*it).timeout <= time(NULL)){
			int ret = system((*it).end.c_str());
			std::cout << "[" << ret << "]: " << it->end << "\n";
		}else{
			r.push_back((*it));
		}
	}
	registeredCommands = std::move(r);

}


void packet_capture(u_char* args,const struct pcap_pkthdr *header,const u_char* packet){
	std::string remote_ip;
    //struct snsff_ethernet * ptr_eth;
    struct sniff_ip * ptr_ip;
    struct sniff_tcp * ptr_tcp;
	struct sniff_udp * ptr_udp;
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
	unsigned short port = ntohs(ptr_tcp->th_dport);
	if(use_tcp){
		ptr_tcp = (struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet)+ size_ip);
		size_tcp = TH_OFF(ptr_tcp)*4;
		if (size_tcp < 20) {
			//std::cerr << "Invalid TCP header length\n";
			return;
		}
		port = ntohs(ptr_tcp->th_dport);
	}else{
		ptr_udp = (struct sniff_udp*)(packet + sizeof(struct sniff_ethernet)+ size_ip);
		port = ntohs(ptr_udp->uh_dport);
	}
	ServiceListIterator sit;

    src_ip = inet_ntoa(ptr_ip->ip_src);
    dst_ip = inet_ntoa(ptr_ip->ip_dst);
	if(dst_ip == local_host){
		sit = services.begin();
		for(;sit != services.end();++sit){
			int response = (*sit)->knock(src_ip,port);
			if(response == Service::sequence_success){
				std::cout << "[yay] Sequence success. Opening port for " << src_ip << "\n";
				if((*sit)->getType() == Service::header_type_command_trigger){
				time_t timeout;
				std::string start,end;
				(*sit)->getOpenCommand(start);
				(*sit)->getCloseCommand(end);
				timeout = (*sit)->getCommandTimeout() + time(NULL);
				registerCommand(start,end,src_ip,timeout);
				(*sit)->invalidateSequence(src_ip);
				}else if((*sit)->getType() == Service::header_type_cleanup){
					std::cout << "[goodbye]\n";
					exitProgram = true;
					return;
				}
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

void trimString(std::string &in){
	size_t pos = in.find_first_not_of("\t\n ",0);
	std::string whitespace = "\t\n ";
	if(pos == std::string::npos){
		return;
	}
	size_t endPos = in.find_first_of(whitespace,pos);
	if(endPos == std::string::npos){
		in = in.substr(pos);
		return;
	}
	in = in.substr(pos,endPos-1);
	return;
}

int usage(){
	std::cerr << "usage: knockd -i <device> -I local_ip [-t|-u] [-c <config_file>]\n";
	std::cerr << "\nOptions:\n";
	std::cerr << "-i <dev>\t\t Device to listen on\n";
	std::cerr << "-I <ip>\t\t Ip address of dev\n";
	std::cerr << "-t\t\t Use TCP\n";
	std::cerr << "-u\t\t Use UDP\n";
	std::cerr << "-c <conf>\t\t Use conf as config file\n";
	std::cerr << "\n";
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

	while ((c = getopt (argc, argv, "i:c:I:ut")) != -1){
		switch(c){
			case 'i':
				dev = optarg;
				break;
			case 'u':
				if(use_tcp){
					std::cerr << "Cannot use options 'u' and 't' at the same time\n";
					return 1;
				}
				use_udp = true;
				use_tcp = false;
				break;
			case 't':
				if(use_udp){
					std::cerr << "Cannot use options 'u' and 't' at the same time\n";
					return 1;
				}
				use_tcp = true;
				use_udp = false;
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

	if(!use_udp && !use_tcp){
		std::cerr << "Use -u or -t to specify UDP or TCP respectively\n";
		return 1;
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
			time_t commandTimeout = 0;
			int hType = Service::header_type_command_trigger;
			std::string timeout;
			std::string strCommandTimeout;
			std::string commandStart;
			std::string commandEnd;
			std::string headerType;
			Service* serv = new Service();

			if(!extractValueMap(vmap,"type",headerType)){
				std::cout << "Header " << *header_list_it << " type is defaulting to 'command-trigger'\n";
				hType = Service::header_type_command_trigger;
			}else{
				trimString(headerType);
				if(headerType == "cleanup"){
					std::cout << "Header cleanup detected\n";
					hType = Service::header_type_cleanup;
				}else if(headerType == "command-trigger"){
					std::cout << "Header command-trigger detected\n";
					hType = Service::header_type_command_trigger;
				}else{
					std::cerr << "Invalid header type '" << headerType << "'\n";
					return 4;
				}
			}
			serv->setType(hType);
			
			if(headerTypeRequired(hType,"port")){
				if(!extractValueMap(vmap,"port",targetPort)){
					std::cerr << "Header " << *header_list_it << " has no 'port' variable set\n";
					return 4;
				}else{
					//TODO: catch this
					serv->setTargetPort(std::stoi(targetPort));
				}
			}

			if(headerTypeRequired(hType,"sequence")){
				if(!extractValueMap(vmap,"sequence",portList) && headerTypeRequired(hType,"sequence")){
					std::cerr << "Header " << *header_list_it << " has no 'sequence' variable set\n";
					return 5;
				}else{
					std::vector<unsigned short> shortPortList;
					if(explodeNumericCsv<unsigned short>(portList,shortPortList) < 0){
						std::cerr << "Error parsing csv\n";
						return 6;
					}
					serv->setPortSequence(shortPortList);
				}
			}

			if(headerTypeRequired(hType,"command_start")){
				if(!extractValueMap(vmap,"command_start",commandStart) && headerTypeRequired(hType,"command_start")){
					std::cerr << "Header " << *header_list_it << " has no 'command_start' variable set\n";
					return 5;
				}else{
					serv->setOpenCommand(commandStart);
				}
			}

			if(headerTypeRequired(hType,"command_end")){
				if(!extractValueMap(vmap,"command_end",commandEnd) && headerTypeRequired(hType,"command_end")){
					std::cerr << "Header " << *header_list_it << " has no 'command_end' variable set\n";
					return 5;
				}else{
					serv->setCloseCommand(commandEnd);
				}
			}

			if(headerTypeRequired(hType,"timeout")){
				if(!extractValueMap(vmap,"timeout",timeout) && headerTypeRequired(hType,"timeout")){
					std::cerr << "Header " << *header_list_it << " has no 'timeout' variable set\n";
					return 7;
				}else{
					try{
						time = std::stoi(timeout);
					}catch(const std::invalid_argument ia){
						std::cerr << "Timeout is invalid\n";
						return 8;
					}
					serv->setTimeInterval(time);
				}
			}

			if(headerTypeRequired(hType,"command_timeout")){
				if(!extractValueMap(vmap,"command_timeout",strCommandTimeout) && headerTypeRequired(hType,"command_timeout")){
					std::cerr << "Header " << *header_list_it << " has no 'command_timeout' variable set\n";
					return 7;
				}else{
					try{
						commandTimeout = std::stoi(strCommandTimeout);
					}catch(const std::invalid_argument ia){
						std::cerr << "Command timeout is invalid\n";
						return 8;
					}
					serv->setCommandTimeout(commandTimeout);
				}
			}
			serv->setType(hType);
			services.push_back(serv);
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
	if(use_udp){
		filter_exp = "udp";
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
	while(!exitProgram){
		processCommands();
		const u_char* packet = pcap_next(pcap_handle,&pkt_hdr);
		if(packet)
				packet_capture(nullptr,&pkt_hdr,packet);
	}
	pcap_close(pcap_handle);
	return(0);
}

