#include "include/sniffer.h"
#include <iostream>

Sniffer::Sniffer(const std::string& iface, const std::string& ip, int port)
    : interface(iface), target_ip(ip), target_port(port) {}

void Sniffer::print_header_bytes(const u_char* data, int size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void Sniffer::startTCP() {
    std::cout << "\nStarting the sniffing on " << interface << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open the interface: " << interface << ": " << errbuf << std::endl;
        return;
    }

    std::string filter_exp = "src host " + target_ip + " and src port " + std::to_string(target_port);
    std::cout << "Applying BPF filter: \"" << filter_exp << "\"" << std::endl;

    bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't compile the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't apply the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res > 0) {
        std::cout << "Response trace captured, with a lenght of " << header->caplen << " bytes" << std::endl;
        std::cout << "First 16 bytes of the header: ";
        print_header_bytes(packet, 16);
    } else if (res == 0) {
        std::cout << "Couldn't capture a reply" << std::endl;
    } else {
        std::cerr << "Error capturing the packet: " << pcap_geterr(handle) << std::endl;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
}
