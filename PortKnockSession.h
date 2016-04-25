#ifndef __PORT_KNOCK_SESSION_HEADER__
#define __PORT_KNOCK_SESSION_HEADER__ 1

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <map>
#include <time.h>

#include "TypeDefs.h"

#define KNOCKD_TIMEOUT_EXCEEDED 1
#define KNOCKD_STEP_OKAY 2
#define KNOCKD_SEQUENCE_FULFILLED 3

class PortKnockSession { 
	public:
		PortKnockSession(const std::string,const PortList,const int);
		PortKnockSession();
		~PortKnockSession();
		int handlePacket(const u_char*);
	private:
		bool m_portInList(const short);
		std::string m_ip;
		PortList m_port_list;
		PortTimeList m_port_times;
		int m_timeout;
};

#endif
