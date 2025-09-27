CXX := g++
CXXSTD   := c++11
CXXFLAGS := -std=$(CXXSTD) -Wall -Wextra -O2 -Isrc/include
LDFLAGS  := -lpcap
SRCS := src/main.cpp src/escaneo.cpp src/sniffer.cpp
OUT  := main

.PHONY: all clean run

all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(OUT) $(LDFLAGS)

clean:
	@echo "Cleaning..."
	-rm -f $(OUT)

run:
	sudo ./main
