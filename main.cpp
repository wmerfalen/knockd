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
#include <boost/pool/object_pool.hpp>

#define MAX_PORTS 64

#define m_debug(A) std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n";

void usage(std::string_view bin) {
	std::cerr << "Usage: " << bin << " <device> <tcp|udp> <port>...<port-N>\n";
}

pcap_t *handle = nullptr;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;		/* The compiled filter expression */
std::string filter_exp;	/* The filter expression */
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
	state_management_t() : index(0) {
		memset(&src_ip,0,sizeof(src_ip));
	}
	state_management_t(const in_addr* __src_ip) : state_management_t() {
		src_ip = *__src_ip;
	}
	state_management_t(const state_management_t& copy) {
		src_ip = copy.src_ip;
		index = copy.index;
	}
	void import_host(const in_addr* __src_ip) {
		index = 0;
		src_ip = *__src_ip;
	}
	enum knock_result : uint8_t {
		ALLOW_CLIENT = 0,
		INCREMENT_INDEX,
		KNOCK_FAILED,
	};
	void increment_index() {
		++index;
	}
	knock_result knock(const uint16_t& port) {
		if(index >= ports.size()) {
			return ALLOW_CLIENT;
		}
		if(port == ports[index]) {
			if(index + 1 == ports.size()) {
				return ALLOW_CLIENT;
			}
			return INCREMENT_INDEX;
		}
		return KNOCK_FAILED;
	}
	const std::string& to_string() {
		ip_string = inet_ntoa(src_ip);
		return ip_string;
	}
	std::string ip_string;
	in_addr src_ip;
	std::size_t index;
};

boost::object_pool<state_management_t> client_slots;
std::vector<state_management_t*> pointers;

void remove_client(state_management_t* c) {
	client_slots.free(c);
	pointers.erase(
	std::remove_if(pointers.begin(),pointers.end(),[&](const state_management_t* ptr) {
		return ptr == c;
	}),
	pointers.end());
}

state_management_t* get_by_ip(const in_addr src) {
	for(auto& client : pointers) {
		if(client->src_ip.s_addr == src.s_addr) {
			return client;
		}
	}
	return nullptr;
}
void allow_client(state_management_t* client) {
	std::string host = inet_ntoa(client->src_ip);
	std::cout << "Allow: " << host << "\n";
	remove_client(client);
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

	u_int size_ip;
	u_int size_tcp;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	state_management_t* client = get_by_ip(ip->ip_src);
	if(client == nullptr) {
		client = client_slots.malloc();
		client->import_host(&(ip->ip_src));
		pointers.emplace_back(client);
		m_debug("creating client for " << inet_ntoa(ip->ip_src));
	}

	uint16_t port = 0;

	if(protocol == LISTEN_TCP) {
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if(size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		port = ntohs(tcp->th_dport);
	} else {
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		port = ntohs(udp->uh_dport);
	}
	m_debug("IN:" << client->to_string() << ":" << port);
	switch(client->knock(port)) {
		case state_management_t::knock_result::ALLOW_CLIENT:
			m_debug("Allowing client: " << client->to_string());
			allow_client(client);
			break;
		case state_management_t::knock_result::INCREMENT_INDEX:
			m_debug("increment_index for client: " << client->to_string());
			client->increment_index();
			break;
		case state_management_t::knock_result::KNOCK_FAILED:
			m_debug("remove_client: " << client->to_string());
			remove_client(client);
			break;
		default:
			std::cerr << "[warning]: unknown value returned from client->knock(" << port << ")\n";
			break;
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
		if(ports.size() > MAX_PORTS) {
			std::cerr << "[error]: maximum allowed ports specified is " << MAX_PORTS << "\n";
			exit(4);
		}
	}
	std::string template_filter = protocol == LISTEN_TCP ? "tcp dst port " : "udp dst port ";

	bool first = true;
	for(const auto& p : ports) {
		if(!first) {
			filter_exp += " or ";
		}
		first = false;
		filter_exp += template_filter + std::to_string(p);
	}
	m_debug("filter_exp: '" << filter_exp << "'");
	if(pcap_lookupnet((char*)dev.c_str(), &net, &mask, errbuf) == -1) {
		std::cerr << "Can't get netmask for device " << dev << "\n";
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live((char*)dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		std::cerr <<  "[error]: couldn't open device " << dev << ": " << errbuf << "\n";
		exit(5);
	}
	if(pcap_compile(handle, &fp, (char*)filter_exp.c_str(), 0, net) == -1) {
		std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(7);
	}
	if(pcap_setfilter(handle, &fp) == -1) {
		std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(7);
	}

	pcap_loop(handle, 0, got_packet, nullptr);
	pcap_close(handle);

	exit(0);
}
