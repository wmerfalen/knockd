FILE_INCLUDES=$(CPP_INCLUDES)
LINK_INCLUDES=$(LINKER_INCLUDES)
DEBUG=-ggdb -g
FLAGS=-O3 -Wall $(FILE_INCLUDES) $(LINK_INCLUDES)
GPP=g++-10 -std=c++17
all: main.cpp
	$(GPP) $(DBEUG) $(FLAGS) main.cpp -lpcap -o knockd
