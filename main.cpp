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
#include <arpa/inet.h>
#include "xoroshiro.hpp"

#define DEFAULT_TIMEOUT 10

#define MAX_PORTS 64

#define ALLOW_COMMAND "/root/knockd-allow"

#define m_debug(A) std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n";

#define m_alert(A) std::cout << "***ALERT***\n***ALERT***: " << A << "\n***ALERT***\n";

void usage(std::string_view bin) {
	std::cerr <<
	    "Usage: " << bin << " <DEVICE> <PROTO> < ports\n"
	    << "  -> listen on DEVICE for PROTO (udp or tcp) traffic. Read sequence from stdin\n"
	    << "  Example: " << bin << " eth0 tcp < ports\n"
	    << "  Example: " << bin << " wlan0 udp < ports\n"
	    << "\n"
	    << "Usage: " << bin << " <DEVICE> <PROTO> generate\n"
	    << "  -> listen on DEVICE for PROTO (udp or tcp) traffic. Will generate a random\n"
	    << " sequence of ports. The sequence will be printed once to stdout.\n"
	    << "\n"
	    << "Keep in mind: this program will run /root/knockd-allow IP when knocking is successful\n"
	    ;
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
time_t TIMEOUT_SECONDS = DEFAULT_TIMEOUT;

struct state_management_t {
	state_management_t() : index(0) {
		m_debug("state_management_t()");
		memset(&src_ip,0,sizeof(src_ip));
		last_hit = time(nullptr);
	}
	state_management_t(in_addr __src_ip) : state_management_t() {
		m_debug("state_management_t(in_addr)");
		src_ip = __src_ip;
		last_hit = time(nullptr);
	}
	state_management_t(const state_management_t& copy) {
		m_debug("state_management_t copy constructor");
		src_ip = copy.src_ip;
		index = copy.index;
		last_hit = copy.last_hit;
		ip_string = copy.ip_string;
	}
	~state_management_t() {
		m_debug("~state_management_t");
		ip_string.clear();
	}
	void import_host(in_addr __src_ip) {
		m_debug("import_host(in_addr)");
		m_debug("this: " << (uint64_t)this);
		index = 0;
		src_ip = __src_ip;
		last_hit = time(nullptr);
	}
	enum knock_result : uint8_t {
		ALLOW_CLIENT = 0,
		INCREMENT_INDEX,
		KNOCK_FAILED,
		TIMEOUT,
	};
	void increment_index() {
		++index;
	}
	knock_result knock(uint16_t port) {
		time_t now = time(nullptr);
		if(now - last_hit > TIMEOUT_SECONDS) {
			return TIMEOUT;
		}
		last_hit = time(nullptr);
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
	std::string to_string() {
		m_debug("to_string");
		char* tmp = inet_ntoa(src_ip);
		if(!tmp) {
			m_alert("invalid inet_ntoa return! returning blank string...");
			ip_string.clear();
			return ip_string;
		}
		ip_string = tmp;
		return ip_string;
	}
	std::string timeout() const {
		m_debug("timeout");
		return std::to_string(time(nullptr) - last_hit);
	}
	std::string ip_string;
	in_addr src_ip;
	std::size_t index;
	time_t last_hit;
};

static boost::object_pool<state_management_t> client_slots;
static std::vector<state_management_t*> pointers;

void remove_client(state_management_t* c) {
	pointers.erase(
	std::remove_if(pointers.begin(),pointers.end(),[&](const state_management_t* ptr) {
		return ptr == c;
	}),
	pointers.end());
	m_debug("client_slots.free");
	client_slots.destroy(c);
}

state_management_t* get_by_ip(const in_addr src) {
	m_debug("get_by_ip");
	for(auto& client : pointers) {
		m_debug("checking");
		if(client->src_ip.s_addr == src.s_addr) {
			return client;
		}
	}
	return nullptr;
}
void allow_client(state_management_t* client) {
	if(!client) {
		m_alert("allowing client that has nullptr!");
		return;
	}
	std::string host = inet_ntoa(client->src_ip);
	std::cout << "Allow: " << host << "\n";
	std::string command = ALLOW_COMMAND;
	command += " ";
	command += host;
	system(command.c_str());
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
	m_debug("getting client ptr");
	state_management_t* client = get_by_ip(ip->ip_src);
	if(client == nullptr) {
		m_debug("creating client for " << inet_ntoa(ip->ip_src));
		client = client_slots.construct(ip->ip_src);
		if(!client) {
			m_alert("Invalid malloc!");
			return;
		}
		client->import_host(ip->ip_src);
		pointers.push_back(client);
	}

	uint16_t port = 0;

	if(protocol == LISTEN_TCP) {
		m_debug("is tcp");
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if(size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		port = ntohs(tcp->th_dport);
	} else {
		m_debug("is udp");
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		m_debug("getting port");
		port = ntohs(udp->uh_dport);
		m_debug("port :" << port);
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
		case state_management_t::knock_result::TIMEOUT:
			m_debug("timeout " << client->timeout() << " remove_client: " << client->to_string());
			remove_client(client);
			break;
		default:
			std::cerr << "[warning]: unknown value returned from client->knock(" << port << ")\n";
			break;
	}
}

/**
	* ./knockd <device> <tcp|udp> < ports.csv
	*
	* ./knockd <device> <tcp|udp> generate
	*
	*/
int main(int argc, char *argv[]) {
	if(argc < 2) {
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
	std::size_t ctr = MAX_PORTS;

	uint16_t min = 1, max = 1;
	if(argc > 3 && lower_case_compare(argv[3],"generate")) {
		xoroshiro::init();
		m_debug("Generating " << MAX_PORTS << " random ports...");
		std::cout << "seq:";
		for(std::size_t i = 0; i < 64; i++) {
			ports.emplace_back(xoroshiro::next());
			if(ports.back() < min) {
				min = ports.back();
			}
			if(ports.back() > max) {
				max = ports.back();
			}
			std::cout << ports.back() << "/";
		}
		std::cout << "\n";
	} else {
		m_debug("Reading ports from stdin...");
		uint16_t n = 0;
		while(1) {
			n = 0;
			std::cin >> n;
			if(n == 0) {
				break;
			}
			if(n < min) {
				min = n;
			}
			if(n > max) {
				max = n;
			}
			ports.emplace_back(n);
			--ctr;
			if(ctr == 0) {
				break;
			}
		}
	}

	if(protocol == LISTEN_TCP) {
		filter_exp = "tcp";
	} else {
		filter_exp = "udp";
	}
	filter_exp += " portrange " + std::to_string(min);
	filter_exp += "-";
	filter_exp += std::to_string(max);
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
