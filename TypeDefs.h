#ifndef __TYPEDEFS_HEADER__
#define __TYPEDEFS_HEADER__ 1

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <forward_list>
#include <time.h>


typedef std::map<std::string,std::map<std::string,std::string>> KVMap;
typedef std::map<std::string,std::map<std::string,std::string>>::const_iterator KVMapConstIterator;
typedef std::map<std::string,std::map<std::string,std::string>>::iterator KVMapIterator;
typedef std::map<std::string,std::string> ValueMap;
typedef std::map<std::string,std::string>::iterator ValueMapIterator;
typedef std::map<std::string,std::string>::const_iterator ValueMapConstIterator;
typedef std::vector<std::string> HeaderList;
typedef std::vector<std::string>::const_iterator HeaderListConstIterator;
typedef std::vector<std::string>::iterator HeaderListIterator;

typedef std::vector<unsigned short> PortList;
typedef std::vector<unsigned short>::const_iterator PortListConstIterator;
typedef std::vector<std::string> IPList;

typedef struct _port_times { 	\
	unsigned short port;		\
	time_t time;				\
} PortTimes;

typedef std::vector<PortTimes> PortTimeList;
typedef std::map<std::string,PortTimeList> IPTimeList;
typedef std::map<std::string,PortTimeList>::const_iterator IPTimeListConstIterator;
typedef std::map<std::string,PortTimeList>::iterator IPTimeListIterator;

typedef int KnockStatus;

#endif
