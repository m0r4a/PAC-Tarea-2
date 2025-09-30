#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <pcap.h>
#include <future>
#include "common.h"

struct SnifferResult {
    bool packet_found = false;
    PortStatus status = PortStatus::UNKNOWN;
    std::vector<unsigned char> header_bytes;
};

class Sniffer {
public:
    Sniffer(const std::string& interface, const std::string& ip, int port);
    ~Sniffer();
    
    void start(Protocol protocol, std::promise<SnifferResult> result_promise);
    void stop();
    
    std::string interface;
    std::string target_ip;
    int target_port;

private:
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    pcap_t* handle;
};

#endif
