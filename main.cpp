#include <fstream>
#include <vector>
#include <string>
#include <functional>
#include "lib/knockd.hpp"

/* ethernet headers are always exactly 14 bytes */
#define DEFAULT_TIMEOUT 10

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

enum port_mode_t : uint16_t {
	NONE,
	READ_FROM_STDIN,
	READ_FROM_INPUT_FILE,
	GENERATE_SEQUENCE,
};
port_mode_t port_mode;
std::string dev;
std::vector<uint16_t> ports;

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
	bool capture_device = false;
	bool capture_protocol = false;
	bool capture_file = false;
	std::size_t ctr = MAX_PORTS;
	port_mode = NONE;
	libknockd::protocol_t listen_protocol = libknockd::protocol_t::NONE;
	for(int i = 1; i < argc; i++) {
		if(capture_device) {
			capture_device = false;
			dev = to_string_limit(argv[i],16);
			continue;
		}
		if(capture_protocol) {
			capture_protocol = false;
			std::string proto = to_string_limit(argv[i],3);
			if(lower_case_compare(proto,"tcp")) {
				listen_protocol = libknockd::protocol_t::PROTO_TCP;
			} else if(lower_case_compare(proto,"udp")) {
				listen_protocol = libknockd::protocol_t::PROTO_UDP;
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
			ports.emplace_back(n);
			--ctr;
			if(ctr == 0) {
				break;
			}
		}
		fp.close();
		std::cout << "[status]: read " << ports.size() << " ports from file: '" << file << "'\n";
	}

	libknockd::Listener listener(dev,listen_protocol,ports,0,"/root/knockd-allow");
	if(listener.start_capture() < 0) {
		std::cerr << "[error]: failed to start capture\n";
	} else {
		std::cout << "[status]: completed capture successfully\n";
	}

	return 0;
}
