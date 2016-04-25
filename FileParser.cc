#ifndef __FILE_PARSER_SOURCE__
#define __FILE_PARSER_SOURCE__ 1
#include "FileParser.h"
#include <vector>

#define PARSE_LINE_SIZE 1024

FileParser::FileParser(std::string file){
	m_file = file;
	if(!openFile(m_file)){
		std::cerr << "Unable to open file: " << file << "\n";
	}
}

FileParser::FileParser(){
}

FileParser::~FileParser(){
	if(m_fstream.is_open()){
		m_fstream.close();
	}
}

bool FileParser::isOpen(){ return m_fstream.is_open(); }

bool FileParser::openFile(const std::string& file){
	m_fstream.open(file.c_str(),std::fstream::in);
	return m_fstream.is_open();
}

void FileParser::parse(){

	int depth = 0;
	int line_number = 0;
	std::string alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::string current_header;
	ValueMap map;

	while(!m_fstream.eof()){
		char buf[PARSE_LINE_SIZE];
		memset(buf,0,PARSE_LINE_SIZE);
		m_fstream.getline(buf,PARSE_LINE_SIZE,'\n');
		std::string line = buf;
		++line_number;

		//Is line a comment?
		size_t pos = line.find("#",0);
		if(pos == 1){
			continue;
		}

		//Is the line just whitespace?
		pos = line.find_first_not_of("\n\t ",0);
		if(pos == std::string::npos){
			continue;
		}

		//Is the line a section name?
		if(depth == 0){
			//Get the last alpha char position from the line
			size_t last_char = line.find_first_not_of(alpha,pos);
			if(last_char == pos){
				continue;
			}
			current_header = line.substr(pos,last_char);

			//Find the opening bracket
			pos = line.find("{",last_char);
			if(pos == std::string::npos){
				//opening bracket is not on this line, throw an error
				std::cerr << "Missing opening bracket on line: " << line_number << "\n";
				return;
			}else{
				depth++;
			}
		}else{
			//Check if it's the end of a block
			pos = line.find("}",0);
			if(pos != std::string::npos){
				m_kvmap.insert(std::pair<std::string,ValueMap>(current_header,map));
				current_header.clear();
				map.clear();
				depth = 0;
				line_number++;
				continue;
			}

			//Find first character of the key
			pos = line.find_first_not_of("\t",0);
			
			//Is this a comment?
			if(pos != std::string::npos && line[pos] == '#'){
				line_number++;
				continue;
			}

			std::string key;
			std::string value;
			size_t colon_pos = 0;

			//Find colon
			colon_pos = line.find(":",pos);
			if(colon_pos == std::string::npos){
				std::cerr << "Missing expected ':' on line number:" << line_number << "\n";
				return;
			}

			key = line.substr(pos,colon_pos -1);
			
			//Find a semi-colon
			pos = line.find(";",colon_pos);
			if(pos == std::string::npos){
				std::cerr << "Missing expected ';' on line number:" << line_number << "\n";
				return;
			}

			value = line.substr(colon_pos +1,pos - colon_pos -1);

			map[key] = value;
		}
	}
}

int FileParser::getHeaders(HeaderList& hl){
	KVMapConstIterator it = m_kvmap.begin();
	int ctr = 0;
	for(;it != m_kvmap.end();++it){
		hl.push_back((*it).first);
		ctr++;
	}
	return ctr;
}

int FileParser::getValueMap(ValueMap& vm,const std::string header){
	KVMapConstIterator it = m_kvmap.find(header);
	if(it != m_kvmap.end()){
		vm = m_kvmap[header];
		return vm.size();
	}else{
		return 0;
	}
}

void FileParser::m_dump_headers(){
	KVMapIterator it = m_kvmap.begin();
	for(; it != m_kvmap.end();++it){
		std::cout << "Header: '" << (*it).first << "'\n";
		ValueMap temp_map = (*it).second;
		ValueMapConstIterator mit = temp_map.begin();
		for(; mit != temp_map.end();++mit){
			std::cout << (*mit).first << ":" << (*mit).second << "\n";
		}
	}
}

#endif
