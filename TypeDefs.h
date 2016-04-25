#ifndef __TYPEDEFS_HEADER__
#define __TYPEDEFS_HEADER__ 1

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <forward_list>
#include <time.h>

typedef std::vector<short> PortList;
typedef std::vector<short>::const_iterator PortListConstIterator;
typedef std::vector<std::string> IPList;

typedef struct _port_times { 	\
	short port;					\
	time_t time;				\
} PortTimes;

typedef std::forward_list<PortTimes> PortTimeList;
typedef std::map<std::string,PortTimeList> IPTimeList;
#endif
