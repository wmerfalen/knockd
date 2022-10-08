#ifndef __LIBKNOCKD_HEADER_INCLUDE__
#define __LIBKNOCKD_HEADER_INCLUDE__
#include <array>
#include <vector>
#include <string>
#include <functional>
#include <pcap.h>
#include "TCPTypes.h"
#include "xoroshiro.hpp"
#include <cstring>

#ifndef DEFAULT_TIMEOUT
	#define DEFAULT_TIMEOUT 10
#endif
#ifndef CLEANUP_EVERY_N_SECONDS
	#define CLEANUP_EVERY_N_SECONDS 20
#endif
#ifndef LAST_SEEN_TIMEOUT_IN_SECONDS
	#define LAST_SEEN_TIMEOUT_IN_SECONDS 40
#endif
#ifndef MAX_PORTS
	#define MAX_PORTS 64
#endif
#define ALLOW_COMMAND "/root/knockd-allow"
namespace libknockd {
#ifdef KNOCKD_DEBUG_OUTPUT
	static bool debug = true;
	#define m_debug(A) if(debug){ std::cout << "[debug]: " << __FUNCTION__ << ":" << __LINE__ << ":->" << A << "\n"; }
#else
	#define m_debug(A)
#endif
#ifdef NO_ALERTS
	#define m_alert(A)
#else
	#define m_alert(A) std::cerr << "***ALERT***\n***ALERT***: " << A << "\n***ALERT***\n";
#endif
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
	};

	namespace config {
		uint16_t TIMEOUT = DEFAULT_TIMEOUT;
		uint16_t CLEANUP_SECONDS = CLEANUP_EVERY_N_SECONDS;
		uint16_t LAST_SEEN_TIMEOUT = LAST_SEEN_TIMEOUT_IN_SECONDS;
		uint16_t PORT_COUNT = MAX_PORTS;
		static constexpr uint32_t SNAPLEN_TCP = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_tcp);
		static constexpr uint32_t SNAPLEN_UDP = SIZE_ETHERNET + sizeof(sniff_ip) + sizeof(sniff_udp);
	};
	namespace callback {
		void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	};
	struct knock {
		in_addr ip;
		std::size_t index;
		time_t last_hit;
	};
	struct Listener {
			enum protocol_t : uint8_t {
				NONE,
				PROTO_TCP,
				PROTO_UDP,
			};
			Listener() : handle(nullptr),
				mask(0), net(0),
				protocol(NONE),
				snaplen(0) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
				m_aggregate_strings = true;
#endif
			}
			Listener(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<uint16_t>& in_ports) :
				handle(nullptr), mask(0), net(0),
				dev(libknockd::util::to_string_limit(in_device,16)),
				ports(in_ports),
				protocol(in_protocol),
				snaplen(in_protocol == PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP) {
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));

				if(protocol == PROTO_TCP) {
					filter_exp = "tcp";
				} else {
					filter_exp = "udp";
				}

			}
			std::string_view allow_command() {
				return m_allow_command;
			}
			void set_allow_command(std::string_view file) {
				m_allow_command = util::to_string_limit(file,1024);
			}
			const std::vector<knock>& clients() const {
				return m_clients;
			}
			knock& get_by_ip(const in_addr& src) {
				m_debug("get_by_ip");
				for(auto& client : m_clients) {
					m_debug("checking");
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
				m_clients.erase(
				std::remove_if(m_clients.begin(),m_clients.end(),[&](const auto & param_client) {
					return param_client.ip.s_addr == ip.s_addr;
				}),
				m_clients.end());
			}
			void allow_client(in_addr ip) {
				std::string host = util::ip2str(ip);
				if(host.length()) {
					std::cout << "Allow: " << host << "\n";
					std::string command = m_allow_command;
					command += " ";
					command += host;
					system(command.c_str());
				}
			}
			void cleanup_clients_older_than(time_t last_seen) {
				m_debug("running");
				time_t now = time(nullptr);
				m_clients.erase(
				std::remove_if(m_clients.begin(),m_clients.end(),[&](const auto& param_client) {
					return now - param_client.last_hit < last_seen;
				}),
				m_clients.end()
				);
			}
#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
			const std::vector<std::string>& get_errors_list() const {
				return m_errors;
			}
			void clear_errors_list() {
				m_errors.clear();
			}
			void disable_error_string_aggregation() {
				m_aggregate_strings = false;
			}
			void enable_error_string_aggregation() {
				m_aggregate_strings = true;
			}
#endif

			void dump_usage_stats() {
				std::cout << "------ [ USAGE STATS ] -------\n" <<
				    "[ clients.size(): " << m_clients.size() << " (bytes: " << m_clients.size() * sizeof(knock) << ")]\n" <<
				    "[--------------------------------------]\n";
			}

			void process_packet(const struct pcap_pkthdr *header, const u_char* packet) {
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

				if(protocol == PROTO_TCP) {
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
				std::string host = util::ip2str(ip->ip_src);
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
					allow_client(client.ip);
					remove_client(client.ip);
				}
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
#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
			std::vector<std::string> m_errors;
			bool  m_aggregate_strings;
#endif
			std::string m_allow_command;



#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
			void add_error() {
				m_errors.emplace_back(pcap_geterr(handle));
			}
#endif

			int setup_interface() {
				m_debug("snaplen set to: " << snaplen);
				uint16_t min = 0, max = 0;
				for(const auto& port : ports) {
					if(port < min) {
						min = port;
					}
					if(port > max) {
						max = port;
					}
				}
				filter_exp += " portrange " + std::to_string(min);
				filter_exp += "-";
				filter_exp += std::to_string(max);
				if(pcap_lookupnet((char*)dev.c_str(), &net, &mask, (char*)&errbuf[0]) == -1) {
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
				handle = pcap_open_live((char*)dev.c_str(), snaplen, 1, 1000, (char*)&errbuf[0]);
				if(handle == NULL) {
					return -1;
				}
				if(pcap_compile(handle, &bpf_filter_program, (char*)filter_exp.c_str(), 0, net) == -1) {
#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
					add_error();
#endif
					return -2;
				}
				if(pcap_setfilter(handle, &bpf_filter_program) == -1) {
#ifdef KNOCKD_AGGREGATE_ERROR_STRINGS
					add_error();
#endif
					return -3;
				}
				pcap_loop(handle, 0, callback::got_packet, reinterpret_cast<u_char*>(this));
				pcap_close(handle);
				return 0;
			}
	};
};// end namespace libknockd

namespace libknockd {
	namespace callback {
		void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
			Listener* listener = reinterpret_cast<Listener*>(args);
			listener->process_packet(header,packet);
		}
	};
};

#endif
