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
#include <arpa/inet.h>
#include "xoroshiro.hpp"

#define DEFAULT_TIMEOUT 10

#define CLEANUP_EVERY_N_SECONDS 20
#define LAST_SEEN_TIMEOUT_IN_SECONDS 40
#define DUMP_USAGE_STATS_EVERY_N_SECONDS 120

#define MAX_PORTS 64

#define ALLOW_COMMAND "/root/knockd-allow"
#ifdef KNOCKD_DEBUG_OUTPUT
	bool debug = false;
	#define m_debug(A) if(debug){ std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n"; }
#else
	#define m_debug(A)
#endif

#define m_alert(A) std::cerr << "***ALERT***\n***ALERT***: " << A << "\n***ALERT***\n";

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
time_t last_cleanup_time;
time_t last_stats_usage_time;

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
struct knock {
	in_addr ip;
	std::size_t index;
	time_t last_hit;
};

std::vector<knock> clients;

void remove_client(knock client) {
	clients.erase(
	std::remove_if(clients.begin(),clients.end(),[&](const auto & param_client) {
		return param_client.ip.s_addr == client.ip.s_addr;
	}),
	clients.end());
}

knock& get_by_ip(const in_addr& src) {
	m_debug("get_by_ip");
	for(auto& client : clients) {
		m_debug("checking");
		if(client.ip.s_addr == src.s_addr) {
			client.last_hit = time(nullptr);
			return client;
		}
	}
	clients.emplace_back();
	auto& ref = clients.back();
	ref.ip = src;
	ref.index = 0;
	ref.last_hit = time(nullptr);
	return ref;
}
void allow_client(knock& client) {
	char* tmp = inet_ntoa(client.ip);
	if(!tmp) {
		remove_client(client);
		return;
	}
	std::string host = tmp;
	std::cout << "Allow: " << host << "\n";
	std::string command = ALLOW_COMMAND;
	command += " ";
	command += host;
	system(command.c_str());
	remove_client(client);
}

void cleanup_old_clients() {
	m_debug("running");
	clients.erase(
	std::remove_if(clients.begin(),clients.end(),[&](const auto& param_client) {
		bool is_old = time(nullptr) - param_client.last_hit > LAST_SEEN_TIMEOUT_IN_SECONDS;
		if(is_old) {
			m_debug("removing old client");
		}
		return is_old;
	}),
	clients.end()
	);
	last_cleanup_time = time(nullptr);
}

void dump_usage_stats() {
	std::cout << "------ [ USAGE STATS ] -------\n" <<
	    "[ clients.size(): " << clients.size() << " (bytes: " << clients.size() * sizeof(knock) << ")]\n" <<
	    "[--------------------------------------]\n";
	last_stats_usage_time = time(nullptr);
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
	knock& client = get_by_ip(ip->ip_src);

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
	char* tmp_host = inet_ntoa(ip->ip_src);
	std::string host;
	if(!tmp_host) {
		host = "<unknown>";
	} else {
		host = tmp_host;
	}
	m_debug("IN:" << host << ":" << port);
	if(client.index < ports.size()) {
		if(port == ports[client.index]) {
			m_debug("incrementing client.index for: " << host);
			client.index++;
		} else {
			m_debug("Resetting for: " << host);
			client.index = 0;
		}
	}
	if(client.index >= ports.size()) {
		m_debug("allowing client " << host);
		allow_client(client);
		remove_client(client);
	}
	if(time(nullptr) - last_cleanup_time > CLEANUP_EVERY_N_SECONDS) {
		cleanup_old_clients();
	}

	if(time(nullptr) - last_stats_usage_time > DUMP_USAGE_STATS_EVERY_N_SECONDS) {
		dump_usage_stats();
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
	last_cleanup_time = time(nullptr);
	last_stats_usage_time = time(nullptr);

	pcap_loop(handle, 0, got_packet, nullptr);
	pcap_close(handle);

	exit(0);
}
