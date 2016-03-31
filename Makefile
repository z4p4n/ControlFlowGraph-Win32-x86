CPP=g++
CC=gcc
CFLAGS=-c
LDFLAGS=
SOURCES=$(wildcard *.cpp pe/pelib/*.cpp pe/pelib_extend/*.cpp cfg/*.cpp graph/*.cpp hde28c/*.cpp)
SOURCES_2=$(wildcard libdisasm/*.c)
OBJECTS=$(SOURCES:.cpp=.o) $(SOURCES_2:.c=.o)
EXECUTABLE=CFGBuilder.exe
DBGDIR=dbg
OBJ=$(wildcard *.o libdisasm/*.o pe/pelib/*.o pe/pelib_extend/*.o cfg/*.o graph/*.o hde28c/*.o)

all: $(SOURCES) $(SOURCES_2) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	mkdir -p $(DBGDIR)
	$(CPP) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CPP) $(CFLAGS) $< -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm $(OBJ)
	rm $(EXECUTABLE)

