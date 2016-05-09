#ifndef __SERVICE_SOURCE__ 
#define __SERVICE_SOURCE__ 1

#include "Service.h"

Service::Service(const std::vector<unsigned short> portList,const unsigned short targetPort){
	m_ports = portList;
	m_target_port = targetPort;
}

Service::Service(){
	m_time_interval_seconds = 0;
	m_target_port = 0;
}

Service::~Service(){
	
}

void Service::setPortSequence(std::vector<unsigned short> portList){
	m_ports = portList;
}

time_t Service::getTimeInterval(){
	return m_time_interval_seconds;
}

void Service::setTimeInterval(time_t t){
	m_time_interval_seconds = t;
}

int Service::setOpenCommand(const std::string s){
	m_open_command = s;
	return 0;
}

void Service::getOpenCommand(std::string &s){
	s = m_open_command;
}

int Service::setCloseCommand(const std::string s){
	m_close_command = s;
	return 0;
}

void Service::getCloseCommand(std::string& s){
	s = m_close_command;
}

void Service::setCommandTimeout(time_t t){
	m_command_timeout = t;
}

void Service::m_dumpData(){
	std::cout << "Dump data\n";
	std::cout << "Registered port sequence: ";
	PortList::const_iterator pit = m_ports.begin();
	for(;pit != m_ports.end();++pit){
		std::cout << " " << (*pit);
	}
	std::cout << "\n";
	IPTimeListIterator it = m_port_times.begin();
	for(;it != m_port_times.end();++it){
		std::cout << "IP Address: " << (*it).first << "\n";
		PortTimeList ptime = (*it).second;
		PortTimeList::const_iterator pit = ptime.begin();
		for(;pit != ptime.end();++pit){
			std::cout << "Port: " << (*pit).port << ": " << (*pit).time << "\n";
		}
	}
}

void Service::invalidateSequence(const std::string ip){
	m_invalidateSequence(ip);
}

void Service::m_invalidateSequence(std::string ip){
	m_port_times.erase(ip);
}

bool Service::m_isValidPort(unsigned short port){
	PortList::const_iterator it = std::find(m_ports.begin(),m_ports.end(),port);
	if(it == m_ports.end()){
		return false;
	}else{
		return true;
	}
}

bool Service::m_isNextSequence(const unsigned short port,std::string ip){
	m_dumpData();
	IPTimeList::iterator it = m_port_times.find(ip);
	if(it == m_port_times.end()){
		return false;
	}

	PortList::const_iterator portListIt = m_ports.begin();
	PortTimeList::iterator timesIt = it->second.begin();
	for(;timesIt != it->second.end();++timesIt,++portListIt){
		if((*portListIt) != (*timesIt).port){
			return false;
		}
	}
	if((*portListIt) == port){
		return true;
	}
	return false;
}

KnockStatus Service::knock(const std::string ip,unsigned short port){
	if(!m_isValidPort(port)){
		return Service::invalid_port;
	}

	IPTimeList::iterator it = m_port_times.find(ip);
	PortList::const_iterator portListIt = m_ports.begin();
	PortTimes pt;
	pt.port = port;
	time_t timeReturn = time(NULL);
	if(timeReturn == -1){
		std::cerr << "time() returned -1: " << errno << "\n";
		return Service::time_error;
	}
	pt.time = timeReturn;
	PortTimeList ptl{pt};
	if(it != m_port_times.end()){
		if(m_isNextSequence(port,ip)){
			(*it).second.push_back(pt);
		}
	}else if((*portListIt) == port){
		//This is the first entry and needs to be added to the m_port_times structure
		//TODO: fill pt.time
		m_port_times.insert(std::pair<std::string,PortTimeList>(ip,ptl));
	}else{
		m_dumpData();
	}

	switch(m_sequenceComplete(ip)){
		case -1:
			return Service::ip_not_found;
			break;
		case -2:
			return Service::time_exceeded;
			break;
		case -3:
			return Service::invalid_port;
			break;
		case 0:
			return Service::sequence_success;
			break;
		case 1:
			return Service::sequence_next;
			break;
		default:
			std::cerr << "Unknown return value from m_sequenceComplete\n";
			break;
	}
	return Service::general_fuckery_ensued;
}

int Service::m_sequenceComplete(const std::string ip){
	IPTimeList::iterator it = m_port_times.find(ip);
	if(it == m_port_times.end()){
		return -1;
	}
	PortList::const_iterator portListIt = m_ports.begin();
	PortTimeList::iterator timesIt = it->second.begin();
	PortTimeList::iterator previousIt = it->second.begin();
	for(;timesIt != it->second.end();++timesIt,++portListIt){
		if((*portListIt) == (*timesIt).port){
			if(!((*timesIt).time - (*previousIt).time < m_time_interval_seconds)){
				std::cout << "Time out detected!\n";
				return -2;
			}
		}else{
			return -3;
		}
		previousIt = timesIt;
	}
	if((*it).second.size() == m_ports.size()){
		return 0;
	}else{
		return 1;
	}
}

#endif
