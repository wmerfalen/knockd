#ifndef __LIBKNOCKD_HEADER_INCLUDE__
#define __LIBKNOCKD_HEADER_INCLUDE__
#include <array>
#include <set>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <pcap.h>
#include "TCPTypes.h"
#include "xoroshiro.hpp"
#include <cstring>

#include <unistd.h> // TODO: FIXME remove me

#define ALLOW_COMMAND "/root/knockd-allow"
#define m_debug(A) std::cerr << "[debug " << __FILE__ << "@" << __FUNCTION__ << ":" << __LINE__ << "]->" << A << "\n";

namespace libknockd {
	struct knock {
		in_addr ip;
		std::size_t index;
		time_t last_hit;
	};
	enum protocol_t : u_char {
		NONE = 0,
		ICMP = 1,
		IGMP = 2,
		GGP = 3,
		IPV4 = 4,
		ST = 5,
		TCP = 6,
		CBT = 7,
		EGP = 8,
		IGP = 9,
		BBN = 10,
		NVP = 11,
		PUP = 12,
		ARGUS = 13,
		EMCON = 14,
		XNET = 15,
		CHAOS = 16,
		UDP = 17,
	};
	enum capture_result_t : int {
		KNOCKDCAP_ERROR_DEVICE = -1,
		KNOCKDCAP_ERROR_COMPILE = -2,
		KNOCKDCAP_ERROR_SET_FILTER = -3,
		SUCCESS = 0,
	};
	using port_t = std::pair<protocol_t,uint16_t>;

	namespace util {
		std::string ip2str(in_addr ia) {
			char* tmp = inet_ntoa(ia);
			if(!tmp) {
				return "";
			}
			return tmp;
		}
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
		template <typename T,typename TStringType>
		static inline TStringType generate_bpf_program(
		    T* in_ports,
		    uint8_t in_protocol
		) {
			TStringType local_bpf_program;
			uint16_t local_min =  0, local_max = 0;
			for(const auto& port : *in_ports) {
				if(port < local_min) {
					local_min = port;
				}
				if(port > local_max) {
					local_max = port;
				}
			}
			if(in_protocol == protocol_t::TCP) {
				local_bpf_program = "tcp";
			} else {
				local_bpf_program = "udp";
			}
			local_bpf_program += " portrange " + std::to_string(local_min);
			local_bpf_program += "-";
			local_bpf_program += std::to_string(local_max);
			return local_bpf_program;
		}
		template <typename T,typename TStringType>
		static inline TStringType generate_multi_protocol_bpf_program(
		    T* in_ports
		) {
			TStringType local_bpf_program;
			uint16_t local_min =  0, local_max = 0;
			std::set<protocol_t> protocols;
			for(auto& pair : *in_ports) {
				protocols.insert(pair.first);
				if(pair.second < local_min) {
					local_min = pair.second;
				}
				if(pair.second > local_max) {
					local_max = pair.second;
				}
			}
			for(const auto& proto : protocols) {
				switch(proto) {
					case protocol_t::TCP:
						if(local_bpf_program.length()) {
							local_bpf_program += " or ";
						}
						local_bpf_program += "tcp ";
						break;
					case protocol_t::UDP:
						if(local_bpf_program.length()) {
							local_bpf_program += " or ";
						}
						local_bpf_program += "udp ";
						break;
					default:
						break;
				}
			}

			local_bpf_program += " portrange " + std::to_string(local_min);
			local_bpf_program += "-";
			local_bpf_program += std::to_string(local_max);
			return local_bpf_program;
		}
		template <typename T, typename TFunctor>
		static inline T& remove_from_vector(T& container, TFunctor logic) {
			container.erase(
			    std::remove_if(container.begin(),container.end(),logic),
			    container.end());
			return container;
		}
	};

	namespace config {
		static constexpr uint32_t SNAPLEN_TCP = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_tcp);
		static constexpr uint32_t SNAPLEN_UDP = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_udp);
	};
	namespace callback {
		void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
		void multi_listener_got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	};
	struct Listener {
			Listener() : handle(nullptr),
				mask(0), net(0),
				protocol(NONE),
				snaplen(0),
				m_allow_command(ALLOW_COMMAND),
				ip(nullptr),
				tcp(nullptr),
				udp(nullptr),
				size_ip(0),
				size_tcp(0),
				min_port(0),
				max_port(0),
				max_cap(0) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
			}
			Listener(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<uint16_t>& in_ports,
			    const int& in_max_cap,
			    std::string_view in_allow_command) :
				handle(nullptr), mask(0), net(0),
				dev(libknockd::util::to_string_limit(in_device,16)),
				ports(in_ports),
				protocol(in_protocol),
				snaplen(in_protocol == protocol_t::TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP),
				m_allow_command(in_allow_command),
				ip(nullptr),
				tcp(nullptr),
				udp(nullptr),
				size_ip(0),
				size_tcp(0),
				min_port(0),
				max_port(0),
				max_cap(in_max_cap) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
			}
			~Listener() {
				if(handle) {
					pcap_close(handle);
				}
				ports.clear();
				handle = nullptr;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				filter_exp.clear();
				dev.clear();
				m_clients.clear();
				m_allow_command.clear();
				ip = nullptr;
				tcp = nullptr;
				udp = nullptr;
				size_ip = size_tcp = 0;
				min_port = max_port = 0;
				max_cap = 0;
			}
			std::string get_error() {
				return pcap_geterr(handle);
			}
			std::string_view get_allow_command() {
				return m_allow_command;
			}
			void set_allow_command(std::string_view file) {
				m_allow_command = util::to_string_limit(file,1024);
			}
			const std::vector<knock>& clients() const {
				return m_clients;
			}
			knock& get_by_ip(const in_addr& src) {
				for(auto& client : m_clients) {
					if(client.ip.s_addr == src.s_addr) {
						return client;
					}
				}
				m_clients.emplace_back();
				auto& ref = m_clients.back();
				ref.ip = src;
				ref.index = 0;
				return ref;
			}
			void remove_client(in_addr ip) {
				util::remove_from_vector<std::vector<knock>,std::function<bool(const knock&)>>(
				m_clients,[&](const knock& client) {
					return client.ip.s_addr == ip.s_addr;
				}
				    );
			}
			void allow_client(in_addr ip) {
				std::string host = util::ip2str(ip);
				if(host.length()) {
					std::string command = m_allow_command;
					command += " ";
					command += host;
					system(command.c_str());
				}
			}
			void cleanup_clients_older_than(time_t last_seen) {
				time_t now = time(nullptr);
				util::remove_from_vector<std::vector<knock>,std::function<bool(const knock&)>>(
				m_clients,[&](const auto& param_client) {
					return now - param_client.last_hit < last_seen;
				});
			}

			void process_packet(const struct pcap_pkthdr *header, const u_char* packet) {
				if(header->caplen < snaplen) {
					return;
				}

				ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
				size_ip = IP_HL(ip)*4;
				if(size_ip < 20) {
					return;
				}
				knock& client = get_by_ip(ip->ip_src);
				client.last_hit = header->ts.tv_sec;

				uint16_t port = 0;

				if(protocol == protocol_t::TCP) {
					tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
					size_tcp = TH_OFF(tcp)*4;
					if(size_tcp < 20) {
						return;
					}
					port = ntohs(tcp->th_dport);
				} else {
					udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
					port = ntohs(udp->uh_dport);
				}
				std::string host = util::ip2str(ip->ip_src);
				if(client.index < ports.size()) {
					if(port == ports[client.index]) {
						client.index++;
					} else {
						client.index = 0;
					}
				}
				if(client.index >= ports.size()) {
					allow_client(client.ip);
					remove_client(client.ip);
				}
			}
			void set_max_count(const int& m) {
				max_cap = m;
			}
			const int& get_max_count() const {
				return max_cap;
			}
			int run(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<uint16_t>& in_ports,
			    const int& in_max_cap,
			    std::string_view in_allow_command) {
				dev = libknockd::util::to_string_limit(in_device,16);
				ports = in_ports;
				protocol = in_protocol;
				snaplen = in_protocol == protocol_t::TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				max_cap = in_max_cap;
				m_allow_command = in_allow_command;
				return run();
			}
			std::pair<uint16_t,uint16_t> fetch_device_netmask() {
				return fetch_device_netmask(dev);
			}
			std::pair<uint16_t,uint16_t> fetch_device_netmask(std::string_view dev) {
				uint32_t local_net = 0,local_mask = 0;
				std::fill(errbuf.begin(),errbuf.end(),0);
				if(pcap_lookupnet((char*)dev.data(), &local_net, &local_mask, (char*)&errbuf[0]) == -1) {
					local_net = 0;
					local_mask = 0;
				}
				return {local_net,local_mask};
			}
			int prepare_device(std::string_view in_device) {
				dev = in_device;
				snaplen = protocol == protocol_t::TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				handle = pcap_open_live((char*)dev.c_str(), snaplen, 1, 1000, (char*)&errbuf[0]);
				if(handle == NULL) {
					return capture_result_t::KNOCKDCAP_ERROR_DEVICE;
				}
				std::pair<uint16_t,uint16_t> pair = fetch_device_netmask(dev);
				net = pair.first;
				mask = pair.second;
				filter_exp = util::generate_bpf_program<std::vector<uint16_t>,std::string>(&ports,protocol);
				if(pcap_compile(handle, &bpf_filter_program, (char*)filter_exp.c_str(), 0, net) == -1) {
					return capture_result_t::KNOCKDCAP_ERROR_COMPILE;
				}
				if(pcap_setfilter(handle, &bpf_filter_program) == -1) {
					return capture_result_t::KNOCKDCAP_ERROR_SET_FILTER;
				}
				return 0;
			}
			int start_capture(const int& max_packets) {
				max_cap = max_packets;
				return pcap_loop(handle, max_cap, callback::got_packet, reinterpret_cast<u_char*>(this));
			}
			void close() {
				pcap_close(handle);
			}
			int run() {
				int ret = prepare_device(dev);
				if(ret < 0) {
					return ret;
				}
				ret = start_capture(max_cap);
				if(ret < 0) {
					close();
					return ret;
				}
				close();
				return 0;
			}

		private:
			pcap_t *handle;
			std::array<char,PCAP_ERRBUF_SIZE> errbuf;
			struct bpf_program bpf_filter_program;		/* The compiled filter expression */
			std::string filter_exp;	/* The filter expression */
			bpf_u_int32 mask = 0;		/* The netmask of our sniffing device */
			bpf_u_int32 net = 0;		/* The IP of our sniffing device */
			std::string dev;
			std::vector<uint16_t> ports;
			protocol_t protocol;
			uint32_t snaplen;
			std::vector<knock> m_clients;
			std::string m_allow_command;
			const struct sniff_ip *ip; /* The IP header */
			const struct sniff_tcp *tcp; /* The TCP header */
			const struct sniff_udp *udp; /* The UDP header */
			u_int size_ip;
			u_int size_tcp;
			uint16_t min_port;
			uint16_t max_port;
			int max_cap;
	};

	struct MultiListener {
			MultiListener() : handle(nullptr),
				mask(0), net(0),
				m_allow_command(ALLOW_COMMAND),
				ip(nullptr),
				tcp(nullptr),
				udp(nullptr),
				size_ip(0),
				size_tcp(0),
				min_port(0),
				max_port(0),
				max_cap(0) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				snaplen = 0;
			}
			MultiListener(
			    std::string_view in_device,
			    const std::vector<port_t>& in_ports,
			    const int& in_max_cap,
			    std::string_view in_allow_command) :
				handle(nullptr), mask(0), net(0),
				dev(libknockd::util::to_string_limit(in_device,16)),
				ports(in_ports),
				m_allow_command(in_allow_command),
				ip(nullptr),
				tcp(nullptr),
				udp(nullptr),
				size_ip(0),
				size_tcp(0),
				min_port(0),
				max_port(0),
				max_cap(in_max_cap) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				snaplen = 0;
			}
			~MultiListener() {
				if(handle) {
					pcap_close(handle);
				}
				ports.clear();
				handle = nullptr;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				filter_exp.clear();
				dev.clear();
				m_clients.clear();
				m_allow_command.clear();
				ip = nullptr;
				tcp = nullptr;
				udp = nullptr;
				size_ip = size_tcp = 0;
				min_port = max_port = 0;
				max_cap = 0;
			}
			std::string get_error() {
				return pcap_geterr(handle);
			}
			std::string_view get_allow_command() {
				return m_allow_command;
			}
			void set_allow_command(std::string_view file) {
				m_allow_command = util::to_string_limit(file,1024);
			}
			const std::vector<knock>& clients() const {
				return m_clients;
			}
			knock& get_by_ip(const in_addr& src) {
				for(auto& client : m_clients) {
					if(client.ip.s_addr == src.s_addr) {
						return client;
					}
				}
				m_clients.emplace_back();
				auto& ref = m_clients.back();
				ref.ip = src;
				ref.index = 0;
				return ref;
			}
			void remove_client(in_addr ip) {
				util::remove_from_vector<std::vector<knock>,std::function<bool(const knock&)>>(
				m_clients,[&](const knock& client) {
					return client.ip.s_addr == ip.s_addr;
				}
				    );
			}
			void allow_client(in_addr ip) {
				std::string host = util::ip2str(ip);
				if(host.length()) {
					std::string command = m_allow_command;
					command += " ";
					command += host;
					system(command.c_str());
				}
			}
			void cleanup_clients_older_than(time_t last_seen) {
				time_t now = time(nullptr);
				util::remove_from_vector<std::vector<knock>,std::function<bool(const knock&)>>(
				m_clients,[&](const auto& param_client) {
					return now - param_client.last_hit < last_seen;
				});
			}

			void process_packet(const struct pcap_pkthdr *header, const u_char* packet) {
				if(header->caplen < snaplen) {
					return;
				}

				ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
				size_ip = IP_HL(ip)*4;
				if(size_ip < 20) {
					return;
				}
				knock& client = get_by_ip(ip->ip_src);
				client.last_hit = header->ts.tv_sec;

				uint16_t port = 0;
				u_char ip_protocol = IP_PROTO(ip);
				std::cerr << "[info]: caught packet of protocol #:" << std::to_string(ip_protocol) << "\n";

				protocol_t our_protocol = NONE;
				if(IP_PROTO(ip) == protocol_t::TCP) {
					our_protocol = TCP;
					m_debug("TCP packet caught");
					tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
					size_tcp = TH_OFF(tcp)*4;
					if(size_tcp < 20) {
						return;
					}
					port = ntohs(tcp->th_dport);
				} else if(IP_PROTO(ip) == protocol_t::UDP) {
					m_debug("UDP packet caught");
					our_protocol = UDP;
					udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
					port = ntohs(udp->uh_dport);
				} else {
					std::cerr << "[info]: unknown protocol type: " << std::to_string(IP_PROTO(ip)) << "\n";
					return;
				}
				std::string host = util::ip2str(ip->ip_src);
				if(client.index < ports.size()) {
					if(ports[client.index].first == our_protocol && port == ports[client.index].second) {
						m_debug("client index incrementing: " << host);
						client.index++;
					} else {
						m_debug("client failed index: " << host);
						client.index = 0;
					}
				}
				if(client.index >= ports.size()) {
					allow_client(client.ip);
					remove_client(client.ip);
				}
			}
			void set_max_count(const int& m) {
				max_cap = m;
			}
			const int& get_max_count() const {
				return max_cap;
			}
			int run(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<port_t>& in_ports,
			    const int& in_max_cap,
			    std::string_view in_allow_command) {
				dev = libknockd::util::to_string_limit(in_device,16);
				ports = in_ports;
				protocol = in_protocol;
				snaplen = in_protocol == protocol_t::TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				max_cap = in_max_cap;
				m_allow_command = in_allow_command;
				return run();
			}
			std::pair<uint16_t,uint16_t> fetch_device_netmask() {
				return fetch_device_netmask(dev);
			}
			std::pair<uint16_t,uint16_t> fetch_device_netmask(std::string_view dev) {
				uint32_t local_net = 0,local_mask = 0;
				std::fill(errbuf.begin(),errbuf.end(),0);
				if(pcap_lookupnet((char*)dev.data(), &local_net, &local_mask, (char*)&errbuf[0]) == -1) {
					local_net = 0;
					local_mask = 0;
				}
				return {local_net,local_mask};
			}
			int prepare_device(std::string_view in_device) {
				dev = in_device;
				snaplen = protocol == protocol_t::TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				handle = pcap_open_live((char*)dev.c_str(), snaplen, 1, 1000, (char*)&errbuf[0]);
				if(handle == NULL) {
					return capture_result_t::KNOCKDCAP_ERROR_DEVICE;
				}
				std::pair<uint16_t,uint16_t> pair = fetch_device_netmask(dev);
				net = pair.first;
				mask = pair.second;
				filter_exp = util::generate_multi_protocol_bpf_program<std::vector<port_t>,std::string>(&ports);
				m_debug("filter_exp: '" << filter_exp << "'");
				sleep(1);
				if(pcap_compile(handle, &bpf_filter_program, (char*)filter_exp.c_str(), 0, net) == -1) {
					return capture_result_t::KNOCKDCAP_ERROR_COMPILE;
				}
				if(pcap_setfilter(handle, &bpf_filter_program) == -1) {
					return capture_result_t::KNOCKDCAP_ERROR_SET_FILTER;
				}
				return 0;
			}
			int start_capture(const int& max_packets) {
				max_cap = max_packets;
				return pcap_loop(handle, max_cap, callback::multi_listener_got_packet, reinterpret_cast<u_char*>(this));
			}
			void close() {
				pcap_close(handle);
			}
			int run() {
				int ret = prepare_device(dev);
				if(ret < 0) {
					return ret;
				}
				ret = start_capture(max_cap);
				if(ret < 0) {
					close();
					return ret;
				}
				close();
				return 0;
			}

		private:
			pcap_t *handle;
			std::array<char,PCAP_ERRBUF_SIZE> errbuf;
			struct bpf_program bpf_filter_program;		/* The compiled filter expression */
			std::string filter_exp;	/* The filter expression */
			bpf_u_int32 mask = 0;		/* The netmask of our sniffing device */
			bpf_u_int32 net = 0;		/* The IP of our sniffing device */
			std::string dev;
			std::vector<port_t> ports;
			protocol_t protocol;
			uint32_t snaplen;
			std::vector<knock> m_clients;
			std::string m_allow_command;
			const struct sniff_ip *ip; /* The IP header */
			const struct sniff_tcp *tcp; /* The TCP header */
			const struct sniff_udp *udp; /* The UDP header */
			u_int size_ip;
			u_int size_tcp;
			uint16_t min_port;
			uint16_t max_port;
			int max_cap;


	};
};// end namespace libknockd

namespace libknockd {
	namespace callback {
		void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
			Listener* listener = reinterpret_cast<Listener*>(args);
			listener->process_packet(header,packet);
		}
		void multi_listener_got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
			MultiListener* listener = reinterpret_cast<MultiListener*>(args);
			listener->process_packet(header,packet);
		}
	};
};

#undef m_debug
#endif
