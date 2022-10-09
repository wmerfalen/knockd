FILE_INCLUDES=$(CPP_INCLUDES)
LINK_INCLUDES=$(LINKER_INCLUDES)
DEBUG=$(DEBUG_FLAGS)
FLAGS=-O3 -Wall $(FILE_INCLUDES) $(LINK_INCLUDES)
GPP=$(CPP) -std=c++17
all: main.cpp
	$(GPP) -DKNOCKD_DEBUG_OUTPUT=1 $(DEBUG) $(FLAGS) main.cpp -lpcap -o knockd && \
		$(GPP) -DKNOCKD_DEBUG_OUTPUT=1 $(DEBUG) $(FLAGS) multi.cpp -lpcap -o multi-knockd

release: main.cpp
	$(GPP) $(FLAGS) main.cpp -lpcap -o knockd && strip knockd

multi: multi.cpp
	$(GPP) -DKNOCKD_DEBUG_OUTPUT=1 $(DEBUG) $(FLAGS) multi.cpp -lpcap -o multi-knockd
