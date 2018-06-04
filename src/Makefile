CXX=g++

CXXFLAGS+=-Wall
CPPFLAGS+=-I../include
LDFLAGS+=-pthread

OBJS=main.o aux.o logger.o class.o niceshaper.o config.o filter.o ifaces.o iptables.o libnetlink.o supervisor.o sys.o talk.o tests.o trigger.o worker.o 
TARGET=niceshaper

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $<

all: $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET)
