#ifndef __SERVICE_HEADER__
#define __SERVICE_HEADER__ 1

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <map>

#include "TypeDefs.h"
#include "TCPTypes.h"



#define KNOCKD_TIMEOUT_EXCEEDED 1
#define KNOCKD_STEP_OKAY 2
#define KNOCKD_SEQUENCE_FULFILLED 3


class Service { 
	public:
		const static KnockStatus invalid_port = 1;
		const static KnockStatus time_error = 2;
		const static KnockStatus time_exceeded = 3;
		const static KnockStatus sequence_next = 4;
		const static KnockStatus ip_not_found = 5;
		const static KnockStatus sequence_success = 0;
		const static KnockStatus general_fuckery_ensued = 0xdeadb33f;
		Service(const std::vector<unsigned short>,const unsigned short);
		Service();
		~Service();
		void setTargetPort(const unsigned short p){ m_target_port = p; }
		short getTargetPort(){ return m_target_port; }
		void setTimeInterval(time_t);
		time_t getTimeInterval();
		void invalidateSequence(const std::string);
		KnockStatus knock(const std::string,unsigned short);
	private:
		int m_openPort(const std::string);
		bool m_isValidPort(const unsigned short);
		bool m_isNextSequence(const unsigned short,std::string);
		int m_sequenceComplete(const std::string);
		bool m_withinTimeout(const std::string);
		void m_updateTime(const std::string,const unsigned short);
		void m_invalidateSequence(std::string);
		void m_dumpData();
		time_t m_time_interval_seconds;
		PortList m_ports;
		unsigned short m_target_port;
		IPList m_ips;
		IPTimeList m_port_times;
};

#endif
