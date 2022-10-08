#include <fstream>
#include <vector>
#include <string>
#include <functional>
#include "lib/knockd.hpp"

/* ethernet headers are always exactly 14 bytes */
#define DEFAULT_TIMEOUT 10

#define CLEANUP_EVERY_N_SECONDS 20
#define LAST_SEEN_TIMEOUT_IN_SECONDS 40
#define DUMP_USAGE_STATS_EVERY_N_SECONDS 120

#define MAX_PORTS 64

#define ALLOW_COMMAND "/root/knockd-allow"

#ifdef KNOCKD_DEBUG_OUTPUT
	bool debug = true;
	#define m_debug(A) if(debug){ std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n"; }
#else
	#define m_debug(A)
#endif

#define m_alert(A) std::cerr << "***ALERT***\n***ALERT***: " << A << "\n***ALERT***\n";

std::string ip2str(const in_addr& ia) {
	char* tmp = inet_ntoa(ia);
	if(!tmp) {
		return "";
	}
	return tmp;
}

void usage(std::string_view bin) {
	std::cerr <<
	    "Usage: " << bin << " -i <DEVICE> -p <PROTO> [-s] [-f INPUTFILE] [-g OUTPUT]\n"
	    << "  -> listen on DEVICE for PROTO (udp or tcp) traffic. Read sequence from stdin\n"
	    << "  Example: " << bin << " -i eth0 -p tcp -s < ports\n"
	    << "\n"
	    << "  -> Read sequence from file named 'ports'\n"
	    << "  Example: " << bin << " -i eth0 -p tcp -f ports\n"
	    << "\n"
	    << "  -> Randomly generate a " << MAX_PORTS << " port sequence and save to file 'generated'\n"
	    << "  Example: " << bin << " -i eth0 -p tcp -g generated\n"
	    << "\n"
	    << "Keep in mind: this program will run /root/knockd-allow IP when knocking is successful\n"
	    ;
}

pcap_t *handle = nullptr;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program bpf_filter_program;		/* The compiled filter expression */
std::string filter_exp;	/* The filter expression */
bpf_u_int32 mask = 0;		/* The netmask of our sniffing device */
bpf_u_int32 net = 0;		/* The IP of our sniffing device */
std::string dev;
std::vector<uint16_t> ports;
enum listen_protocol : uint8_t {
	LISTEN_TCP,
	LISTEN_UDP,
};
listen_protocol protocol;
time_t last_cleanup_time;
time_t last_stats_usage_time;
uint32_t snaplen;
struct knock {
	in_addr ip;
	std::size_t index;
	time_t last_hit;
};
enum port_mode_t : uint16_t {
	NONE,
	READ_FROM_STDIN,
	READ_FROM_INPUT_FILE,
	GENERATE_SEQUENCE,
};
port_mode_t port_mode;

std::vector<knock> clients;


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
			return client;
		}
	}
	clients.emplace_back();
	auto& ref = clients.back();
	ref.ip = src;
	ref.index = 0;
	return ref;
}
void allow_client(knock& client) {
	std::string host = ip2str(client.ip);
	if(host.length()) {
		std::cout << "Allow: " << host << "\n";
		std::string command = ALLOW_COMMAND;
		command += " ";
		command += host;
		system(command.c_str());
	}
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

	m_debug("-[ packet metadata ]-----------------------------------");
	m_debug("packet stats: ");
	m_debug("packet.ts      : " << header->ts.tv_sec);
	m_debug("packet.caplen  : " << header->caplen);
	m_debug("packet.len     : " << header->len);
	m_debug("-------------------------------------------------------");

	if(header->caplen < snaplen) {
		std::cerr << "[info]: packet doesnt meet required minimum length of " << snaplen << "\n";
		return;
	}

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
	client.last_hit = header->ts.tv_sec;

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
	std::string host = ip2str(ip->ip_src);
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

std::string to_string_limit(std::string_view str,std::size_t limit) {
	return str.substr(0,std::min(limit,str.length())).data();
}

/**
 *  # listen on <device> for <protocol> packets. read sequence of packets from
 *  # file (-f) named 'ports'
	* ./knockd -i <device> -p <protocol> -f ports
	*
	*  # listen on <device> for <protocol> packets. generate (-g) a random sequence of packets
	*  # write sequence of packets to file (-g) 'ports'
	* ./knockd -i <device> -p <protocol> -g ports
	*
	* # listen on <device> for <protocol> packets. read sequence of packets from
	* # stdin (-s)
	* ./knockd -i <device> -p <protocol> -s
	*
	*/
int main(int argc, char *argv[]) {
	if(argc < 6) {
		usage(argv[0]);
		exit(1);
	}
	std::string file;
	std::string proto;
	bool capture_device = false;
	bool capture_protocol = false;
	bool capture_file = false;
	std::size_t ctr = MAX_PORTS;
	port_mode = NONE;
	uint16_t min = 1, max = 1;
	for(int i = 1; i < argc; i++) {
		if(capture_device) {
			capture_device = false;
			dev = to_string_limit(argv[i],16);
			continue;
		}
		if(capture_protocol) {
			capture_protocol = false;
			proto = to_string_limit(argv[i],3);
			if(lower_case_compare(proto,"tcp")) {
				protocol = LISTEN_TCP;
			} else if(lower_case_compare(proto,"udp")) {
				protocol = LISTEN_UDP;
			} else {
				std::cerr << "[error]: specify tcp or udp for protocol\n";
				exit(2);
			}
			continue;
		}
		if(capture_file) {
			capture_file = false;
			file = to_string_limit(argv[i],1024);
			continue;
		}

		std::string str_i = to_string_limit(argv[i],3);
		if(lower_case_compare(str_i,"-i")) {
			capture_device = true;
			continue;
		}
		if(lower_case_compare(str_i,"-p")) {
			capture_protocol = true;
			continue;
		}
		if(lower_case_compare(str_i,"-f")) {
			port_mode = READ_FROM_INPUT_FILE;
			capture_file = true;
			continue;
		}
		if(lower_case_compare(str_i,"-g")) {
			port_mode = GENERATE_SEQUENCE;
			capture_file = true;
			continue;
		}
		if(lower_case_compare(str_i,"-s")) {
			port_mode = READ_FROM_STDIN;
			continue;
		}
	}
	if(port_mode == NONE) {
		std::cerr << "[error]: specify either -f, -g, or -s\n";
		exit(3);
	}


	if(file.length() == 0 && port_mode != READ_FROM_STDIN) {
		if(port_mode == GENERATE_SEQUENCE) {
			std::cerr << "[error]: the -g option requires a filename to write the ports to\n";
			exit(4);
		}
		if(port_mode == READ_FROM_INPUT_FILE) {
			std::cerr << "[error]: the -f option requires a filename to read ports from\n";
			exit(4);
		}
		std::cerr << "[error]: either -f or -g need to be specified\n";
		exit(4);
	}
	if(port_mode == GENERATE_SEQUENCE) {
		std::ofstream fp(file.c_str(),std::ios::out | std::ios::trunc);
		if(!fp.good()) {
			std::cerr << "[error]: failed to open '" << file << "' for writing.\n";
			exit(5);
		}
		xoroshiro::init();
		xoroshiro::next();
		m_debug("Generating " << MAX_PORTS << " random ports...");
		for(std::size_t i = 0; i < 64; i++) {
			ports.emplace_back(xoroshiro::next());
			if(ports.back() < min) {
				min = ports.back();
			}
			if(ports.back() > max) {
				max = ports.back();
			}
			fp << std::to_string(ports.back()) << "\n";
		}
		fp.close();
		std::cout << "[status]: wrote " << ports.size() << " ports to '" << file << "'\n";
	}
	if(port_mode == READ_FROM_STDIN) {
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
		std::cout << "[status]: read " << ports.size() << " ports from stdin\n";
	}
	if(port_mode == READ_FROM_INPUT_FILE) {
		m_debug("Reading ports from '" << file << "'");
		std::ifstream fp(file.c_str(),std::ios::in);
		if(!fp.good() || fp.is_open() == false) {
			std::cerr << "[error]: couldn't open input file\n";
			exit(6);
		}
		uint16_t n = 0;
		while(fp.good() && !fp.eof()) {
			n = 0;
			fp >> n;
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
		fp.close();
		std::cout << "[status]: read " << ports.size() << " ports from file: '" << file << "'\n";
	}

	if(protocol == LISTEN_TCP) {
		filter_exp = "tcp";
		snaplen = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_tcp);
	} else {
		filter_exp = "udp";
		snaplen = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_udp);
	}
	m_debug("snaplen set to: " << snaplen);
	filter_exp += " portrange " + std::to_string(min);
	filter_exp += "-";
	filter_exp += std::to_string(max);
	if(pcap_lookupnet((char*)dev.c_str(), &net, &mask, errbuf) == -1) {
		std::cerr << "Can't get netmask for device " << dev << "\n";
		net = 0;
		mask = 0;
	}
	/*
	 *
	 * pcap_t *pcap_open_live(
	 * 	const char *device,
	 * 	int snaplen,
	 * 	int promisc,
	 * 	int to_ms,
	 * 	char *errbuf
	 * 	);
	 */
	handle = pcap_open_live((char*)dev.c_str(), snaplen, 1, 1000, errbuf);
	if(handle == NULL) {
		std::cerr <<  "[error]: couldn't open device " << dev << ": " << errbuf << "\n";
		exit(7);
	}
	if(pcap_compile(handle, &bpf_filter_program, (char*)filter_exp.c_str(), 0, net) == -1) {
		std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(8);
	}
	if(pcap_setfilter(handle, &bpf_filter_program) == -1) {
		std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << "\n";
		exit(9);
	}
	last_cleanup_time = time(nullptr);
	last_stats_usage_time = time(nullptr);

	pcap_loop(handle, 0, got_packet, nullptr);
	pcap_close(handle);

	exit(0);
}
