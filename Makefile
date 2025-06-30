##########################################################################################################################################################
# Copyright (c) 2013-2024 A Balaguera
##################################################################################
# Makefile to compile COSMICATLASS
##################################################################################
CXX = g++
CXXFLAGS = -O3 -march=native -fopenmp --std=gnu++20 -fPIC -g3 -pg -funroll-loops -fpermissive
# Use CFLAGS to point out warnings
CXXFLAGS += #-Wall -Wextra -pedantic -Wno-deprecated -Wno-write-strings -Wunused-variable -Wsign-compare -Wmisleading-indentation
##################################################################################
# math and gsl libraries
LIBS_GSL = -lgsl -lgslcblas -lutil -lm -lboost_iostreams -lboost_system -lboost_filesystem 
LIB_SSL  = -I/opt/openssl-3.4.0/include -L/opt/openssl-3.4.0/lib64 -lssl -lcrypto 
LIB_ISA  = -I/usr/include/ -L/usr/local/lib -lisal 
#########################################################################
.PHONY: all clean
all: chall powt nchall
#########################################################################
OBJSa = challenge.o 
SRCSa = $(OBJSa:.o=.cpp)
TARGETa = challenge.exe
chall: $(TARGETa)

#########################################################################
OBJSp = powtest.o 
SRCSp = $(OBJSp:.o=.cpp)
TARGETp = powtest.exe
powt: $(TARGETp)

#########################################################################
OBJSn = nchallenge.o 
SRCSn = $(OBJSn:.o=.cpp)
TARGETn = nchallenge.exe
nchall: $(TARGETn)

#########################################################################
$(TARGETa): $(OBJSa) 
	$(CXX) $(CXXFLAGS) $(SRCSa) -o $(TARGETa) $(LIBS_GSL) $(LTLS) 

$(TARGETn): $(OBJSn) 
	$(CXX) $(CXXFLAGS) $(SRCSn)  $(LIBS_GSL) $(LIB_SSL) $(LIB_ISA) -o $(TARGETn)

$(TARGETp): $(OBJSp) 
	$(CXX) $(CXXFLAGS) $(SRCSp) -o $(TARGETp) $(LIBS_GSL) $(LTLS) 

clean:                                                                                                                                                    
	@echo "Cleaning build artifacts..."                                                                                                                    
	rm -f *.o *.exe
