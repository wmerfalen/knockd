#ifndef __FILE_PARSER_HEADER__
#define __FILE_PARSER_HEADER__ 1

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <map>

typedef std::map<std::string,std::map<std::string,std::string>> KVMap;
typedef std::map<std::string,std::map<std::string,std::string>>::const_iterator KVMapConstIterator;
typedef std::map<std::string,std::map<std::string,std::string>>::iterator KVMapIterator;
typedef std::map<std::string,std::string> ValueMap;
typedef std::map<std::string,std::string>::iterator ValueMapIterator;
typedef std::map<std::string,std::string>::const_iterator ValueMapConstIterator;
typedef std::vector<std::string> HeaderList;
typedef std::vector<std::string>::const_iterator HeaderListConstIterator;
typedef std::vector<std::string>::iterator HeaderListIterator;

class FileParser { 
	public:
		FileParser(std::string);
		FileParser();
		~FileParser();
		bool openFile(const std::string&);
		bool isOpen();
		void parse();
		int getHeaders(HeaderList&);
		int getValueMap(ValueMap&,const std::string);
		std::string getValue(const std::string&);
	private:
		void m_dump_headers();
		KVMap m_kvmap;
		std::fstream m_fstream;
		std::string m_file;
};

#endif
