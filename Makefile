CXX := g++
CXXSTD   := c++23
CXXFLAGS := -std=$(CXXSTD) -Wall -Wextra -O2 -Isrc/include
LDFLAGS  := -lpcap -pthread
SRCS := src/main.cpp src/escaneo.cpp src/sniffer.cpp src/args.cpp src/JSONGen.cpp
OUT  := escaner

.PHONY: all clean run

all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(OUT) $(LDFLAGS)

clean:
	@echo "Cleaning..."
	-rm -f $(OUT)

test:
	sudo ./$(OUT) 127.0.0.1 -p 1-500 -i lo -o test.json
