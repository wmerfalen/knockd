GS=-O3 -Wall
GPP=g++ -std=c++11
%.o: %.cc; $(GPP) $(DEBUG) $(FLAGS) -o $@ -c $^
	all: knockd
	OBJS = FileParser.o Service.o
knockd: main.cc $(OBJS)
		$(GPP) $(DEBUG) $(FLAGS) $^ -lpcap -o $@
-include $(OBJS:=.d)
