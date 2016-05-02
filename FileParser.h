#ifndef __FILE_PARSER_HEADER__
#define __FILE_PARSER_HEADER__ 1

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <map>

#include "TypeDefs.h"

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
