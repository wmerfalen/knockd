#ifndef __SERVICE_HEADER__
#define __SERVICE_HEADER__ 1

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>

#include "TypeDefs.h"
#include "TCPTypes.h"



#define KNOCKD_TIMEOUT_EXCEEDED 1
#define KNOCKD_STEP_OKAY 2
#define KNOCKD_SEQUENCE_FULFILLED 3

class Service { 
	public:
		Service(const std::vector<short>,const short);
		Service();
		~Service();
		void setTargetPort(const short p){ m_target_port = p; }
		short getTargetPort(){ return m_target_port; }
		void knock(const u_char*);
	private:
		int m_openPort(const std::string);
		bool m_isValidPort(const short);
		PortList m_ports;
		short m_target_port;
		IPList m_ips;
		IPTimeList m_port_times;
};

#endif
