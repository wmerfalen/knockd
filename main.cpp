#include <iostream>
#include <vector>
#include <forward_list>
#include <string>
#include <pcap.h>
#include <array>
#include <string.h>
#include <optional>
#include <functional>
#include "TCPTypes.h"

#define m_debug(A) std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n";

void usage(std::string_view bin) {
	std::cerr << "Usage: " << bin << " <device> <tcp|udp> <port>...<port-N>\n";
}

pcap_t *handle = nullptr;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;		/* The compiled filter expression */
std::string filter_exp = "port 22";	/* The filter expression */
bpf_u_int32 mask = 0;		/* The netmask of our sniffing device */
bpf_u_int32 net = 0;		/* The IP of our sniffing device */
struct pcap_pkthdr header;	/* The header that pcap gives us */
const u_char *packet;		/* The actual packet */
std::string dev;
std::vector<uint16_t> ports;
enum listen_protocol : uint8_t {
	LISTEN_TCP,
	LISTEN_UDP,
};

listen_protocol protocol;

bool lower_case_compare(const std::string& a,const std::string& b) {
	char tmp_a, tmp_b;
	for(std::size_t i = 0; i < std::min(a.length(),b.length()); ++i) {
		tmp_a = tolower(a[i]);
		tmp_b = tolower(b[i]);
		if(tmp_a != tmp_b) {
			return false;
		}
	}
	return true;
}

struct state_management_t {
	in_addr src_ip;
	std::size_t index;
	std::array<time_t,10> timestamps;
	state_management_t() : index(0) {
		std::fill(timestamps.begin(),timestamps.end(),0);
		memset(&src_ip,0,sizeof(src_ip));
	}
	state_management_t(const in_addr* __src_ip) : state_management_t() {
		src_ip = *__src_ip;
	}
	state_management_t(const state_management_t& copy) {
		src_ip = copy.src_ip;
		index = copy.index;
		std::copy(copy.timestamps.cbegin(),copy.timestamps.cend(),timestamps.begin());
	}
};
std::forward_list<state_management_t> client_slots;

state_management_t* get_by_ip(const in_addr src) {
	for(auto& client : client_slots) {
		if(client.src_ip.s_addr == src.s_addr) {
			return &client;
		}
	}
	return nullptr;
}
void allow_client(state_management_t* client) {
	std::string host = inet_ntoa(client->src_ip);
	std::cout << "Allow: " << host << "\n";
	client_slots.remove_if([&](const state_management_t& cl) {
		return cl.src_ip.s_addr == client->src_ip.s_addr;
	});
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	m_debug("got_packet");
	if(ports.size() == 0) {
		std::cerr << "[info]: got packet, but ports.size is zero!\n";
		return;
	}
	/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const struct sniff_udp *udp; /* The UDP header */
	const u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
	u_int size_udp;
	//ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	state_management_t* client = get_by_ip(ip->ip_src);
	if(client == nullptr) {
		client_slots.emplace_front((const in_addr*)&(ip->ip_src));
		client = &client_slots.front();
	}


	if(protocol == LISTEN_TCP) {
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if(size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	} else {
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	}
	if(client->index >= ports.size()) {
		allow_client(client);
	}
}

/**
	* ./knockd <device> <tcp|udp> <port>...<port-N>
	*
	*/
int main(int argc, char *argv[]) {
	if(argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	dev = argv[1];
	std::string proto = argv[2];
	if(lower_case_compare(proto,"tcp")) {
		protocol = LISTEN_TCP;
	} else if(lower_case_compare(proto,"udp")) {
		protocol = LISTEN_UDP;
	} else {
		std::cerr << "[error]: specify tcp or udp for protocol\n";
		exit(2);
	}
	for(int i =3; i < argc; ++i) {
		int p = 0;
		p = atoi(argv[i]);
		if(p == 0) {
			std::cerr << "[error]: '" << argv[i] << "' is not a valid port.\n";
			exit(3);
		}
		ports.emplace_back(static_cast<uint16_t>(p));
	}
	if(pcap_lookupnet((char*)dev.c_str(), &net, &mask, errbuf) == -1) {
		std::cerr << "Can't get netmask for device " << dev << "\n";
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live((char*)dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		std::cerr <<  "[error]: couldn't open device " << dev << ": " << errbuf << "\n";
		exit(4);
	}
	if(pcap_compile(handle, &fp, (char*)filter_exp.c_str(), 0, net) == -1) {
		std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(5);
	}
	if(pcap_setfilter(handle, &fp) == -1) {
		std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(6);
	}

	pcap_loop(handle, 0, got_packet, nullptr);
	//int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);

	exit(0);
}
