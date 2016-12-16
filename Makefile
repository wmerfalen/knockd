DEBUG=-ggdb
FLAGS=-O3 -Wall
GPP=g++ -std=c++11
%.o: %.cc; $(GPP) $(DEBUG) $(FLAGS) -MMD -MP -o $@ -c $^
all: knockd
OBJS = FileParser.o Service.o main.o
knockd: $(OBJS)
	$(GPP) $(DEBUG) $(FLAGS) $^ -lpcap -o $@
-include $(OBJS:.o=.d)
