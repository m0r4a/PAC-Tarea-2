CXX := g++

CXXSTD   := c++11
CXXFLAGS := -std=$(CXXSTD) -Wall -Wextra -O2
LDFLAGS  := -lpcap

SRCS := main.cpp
OUT  := main

.PHONY: all clean run

all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(OUT) $(LDFLAGS)

clean:
	@echo "Cleaning..."
	-rm -f $(OUT)

run:
	sudo ./main
