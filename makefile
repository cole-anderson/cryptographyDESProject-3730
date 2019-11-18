INCLUDE = -I/usr/include/
LIBDIR = -L/usr/lib/

COMPILERFLAGS = -Wall
CC = g++ -std=c++11
CFLAGS = $(COMPILERFLAGS) $(INCLUDE) $(INC)
LIBRARIES = -lX11 -lXi -lXmu -lm

all: run cole3730
# 	$(CC) $(CFLAGS) -o $@ $(LIBDIR) $< $(LIBRARIES)

run: cole3730
	./cole3730

.PHONY: all run

cole3730: cole3730.o
	g++ -c cole3730.cpp


	$(CC) $(CFLAGS)  cole3730.o -o cole3730 $(LIBDIR) $(LIBRARIES)

clean:
	rm -f *.o *~ cole3730
