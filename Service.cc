#ifndef __SERVICE_SOURCE__ 
#define __SERVICE_SOURCE__ 1

#include "Service.h"

Service::Service(const std::vector<short> portList,const short targetPort){
	m_ports = portList;
	m_target_port = targetPort;
}

Service::Service(){

}

Service::~Service(){
	
}

void Service::knock(const u_char* packet){
	
}

#endif
