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

#define ALLOW_COMMAND "/root/knockd-allow"

namespace libknockd {
	struct knock {
		in_addr ip;
		std::size_t index;
		time_t last_hit;
	};
	enum capture_result_t : int {
		KNOCKDCAP_ERROR_DEVICE = -1,
		KNOCKDCAP_ERROR_COMPILE = -2,
		KNOCKDCAP_ERROR_SET_FILTER = -3,
		SUCCESS = 0,
	};
	enum protocol_t : uint8_t {
		NONE,
		PROTO_TCP,
		PROTO_UDP,
	};
	enum setup_result_t : int {

	};
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
			if(in_protocol == protocol_t::PROTO_TCP) {
				local_bpf_program = "tcp";
			} else {
				local_bpf_program = "udp";
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
				snaplen(in_protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP),
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
			    const int& in_max_cap) :
				handle(nullptr), mask(0), net(0),
				dev(libknockd::util::to_string_limit(in_device,16)),
				ports(in_ports),
				protocol(in_protocol),
				snaplen(in_protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP),
				m_allow_command(ALLOW_COMMAND),
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
			Listener(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<uint16_t>& in_ports,
			    const int& in_max_cap,
			    std::string_view allow_command) :
				handle(nullptr), mask(0), net(0),
				dev(libknockd::util::to_string_limit(in_device,16)),
				ports(in_ports),
				protocol(in_protocol),
				snaplen(in_protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP),
				m_allow_command(allow_command),
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

				if(protocol == protocol_t::PROTO_TCP) {
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
			    const int& in_max_cap) {
				dev = libknockd::util::to_string_limit(in_device,16);
				ports = in_ports;
				protocol = in_protocol;
				snaplen = in_protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
				max_cap = in_max_cap;
				return run();
			}
			int run(
			    std::string_view in_device,
			    const protocol_t& in_protocol,
			    const std::vector<uint16_t>& in_ports) {
				dev = libknockd::util::to_string_limit(in_device,16);
				ports = in_ports;
				protocol = in_protocol;
				snaplen = in_protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				memset(&bpf_filter_program,0,sizeof(bpf_filter_program));
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
			int open_device() {
				snaplen = protocol == protocol_t::PROTO_TCP ? config::SNAPLEN_TCP : config::SNAPLEN_UDP;
				std::fill(errbuf.begin(),errbuf.end(),0);
				handle = pcap_open_live((char*)dev.c_str(), snaplen, 1, 1000, (char*)&errbuf[0]);
				if(handle == NULL) {
					return capture_result_t::KNOCKDCAP_ERROR_DEVICE;
				}
				return 0;
			}
			int compile_filter() {
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
				return start_capture();
			}
			int start_capture() {
				return pcap_loop(handle, max_cap, callback::got_packet, reinterpret_cast<u_char*>(this));
			}
			void close() {
				pcap_close(handle);
			}
			int run() {
				int ret = open_device();
				if(ret < 0) {
					return ret;
				}
				ret = compile_filter();
				if(ret < 0) {
					return ret;
				}
				return start_capture();
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
