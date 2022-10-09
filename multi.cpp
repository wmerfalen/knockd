#include <fstream>
#include <vector>
#include <string>
#include <functional>
#include "lib/knockd.hpp"

/* ethernet headers are always exactly 14 bytes */
#define DEFAULT_TIMEOUT 10

#define MAX_PORTS 64

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
std::string dev = "eth0";
using port_t = libknockd::port_t;
std::vector<port_t> ports;

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

using namespace libknockd;

protocol_t random_proto() {
	if(xoroshiro::next() % 2 == 0) {
		return TCP;
	}
	return UDP;
}
std::string port_to_string(const port_t& p) {
	std::string s;
	switch(p.first) {
		case TCP:
			s = "TCP:";
			break;
		case UDP:
			s = "UDP:";
			break;
		default:
			s = "?";
			break;
	}
	return s + std::to_string(p.second);
}

/**
	*  # listen on <device> for <protocol> packets. generate (-g) a random sequence of packets
	*  # write sequence of packets to file (-g) 'ports'
	* ./knockd -i <device> -p <protocol> -g ports
	*
	*/
int main(int argc, char *argv[]) {
	std::string file = "generated-multi";
	port_mode = port_mode_t::GENERATE_SEQUENCE;

	std::ofstream fp(file.c_str(),std::ios::out | std::ios::trunc);
	if(!fp.good()) {
		std::cerr << "[error]: failed to open '" << file << "' for writing.\n";
		exit(5);
	}
	xoroshiro::init();
	xoroshiro::next();
	m_debug("Generating " << MAX_PORTS << " random ports...");
	for(std::size_t i = 0; i < 64; i++) {
		ports.emplace_back(std::make_pair<>(random_proto(),xoroshiro::next()));
		fp << port_to_string(ports.back()) << "\n";
	}
	fp.close();
	std::cout << "[status]: wrote " << ports.size() << " ports to '" << file << "'\n";

	libknockd::MultiListener listener(dev,ports,0,"/root/knockd-allow");
	int ret = listener.prepare_device(dev);
	if(ret < 0) {
		std::cerr << "[error]: failed to prepare device: '" << listener.get_error() << "'\n";
		listener.close();
		exit(1);
	}
	/**
	 * passing in zero as max packet count means we will won't be returning from
	 * this next call.
	 */
	ret = listener.start_capture(0);
	if(listener.run() < 0) {
		std::cerr << "[error]: failed to start capture\n";
	} else {
		std::cout << "[status]: completed capture successfully\n";
	}
	listener.close();

	return 0;
}
