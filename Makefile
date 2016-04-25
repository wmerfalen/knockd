DEBUG=-ggdb
FLAGS=-fno-exceptions -O3
GPP=g++ -std=c++11
all: file_parser service
	$(GPP) $(DEBUG) $(FLAGS) main.cc file_parser.o service.o -lpcap -o knockd
file_parser:
	$(GPP) $(DEBUG) $(FLAGS) -c FileParser.cc -o file_parser.o
service:
	$(GPP) $(DEBUG) $(FLAGS) -c Service.cc -o service.o
