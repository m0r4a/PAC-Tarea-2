#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <pcap.h>
#include <atomic>
#include "common.h"

class Sniffer {
public:
    Sniffer(const std::string& interface, const std::string& ip, int port);
    
    void start(Protocol protocol, std::atomic<bool>& stop_signal);

private:
    void print_header_bytes(const u_char* data, int size);
    
    // esto aparentemente es para procesar los paquetes en modo no bloqueante
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    std::string interface;
    std::string target_ip;
    int target_port;
    Protocol scan_protocol;
    bool packet_found = false; // para saber si ya se capturó algo
};

#endif
