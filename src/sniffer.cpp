#include "include/sniffer.h"
#include "include/common.h"
#include <iostream>
#include <netinet/ip.h>

Sniffer::Sniffer(const std::string& iface, const std::string& ip, int port)
    : interface(iface), target_ip(ip), target_port(port) {}

void Sniffer::print_header_bytes(const u_char* data, int size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void Sniffer::start(Protocol protocol) {
    std::string filter_exp;
    int timeout_ms;

    if (protocol == Protocol::TCP) {
        std::cout << "\nStarting the sniffing on " << interface << std::endl;

        timeout_ms = 1000;
        // Aquí se aplica el filtro BPF para TCP
        filter_exp = "src host " + target_ip + " and src port " + std::to_string(target_port);

    } else {
        std::cout << "\nStarting the UDP sniffing on " << interface << std::endl;

        timeout_ms = 2000;
        // Aquí se aplica el filtro BPF para UDP, se captura una respuesta de UDP o un error ICMP
        filter_exp = "(udp and src host " + target_ip + " and src port " + std::to_string(target_port) + ") or (icmp and src host " + target_ip + ")";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, timeout_ms, errbuf);

    if (handle == nullptr) {
        std::cerr << "Couldn't open the interface: " << interface << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "Applying BPF filter: \"" << filter_exp << "\"" << std::endl;
    
    // Mucho texto copiado de un foro
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

        if (protocol == Protocol::TCP) {
            std::cout << "First 16 bytes of the header: ";
            print_header_bytes(packet, 16);
        } else {
            // Analizamos la cabecera IP para ver si es ICMP (cerrado) o UDP (abierto)
            // Ahora hay que revisar la cabecera, si es ICMP significa que el puerto está cerrado y si es UDP está abierto

            // Aparentemente las cabeceras son de longitudes diferentes dependiendo si es ethernet o no, como no le quiero
            // agregar muchísima complejidad sólo asumiré que es por ethernet estableciendo una longitud de 14 bytes
            const struct ip* ip_header = (const struct ip*)(packet + 14);

            if (ip_header->ip_p == IPPROTO_ICMP) {
                std::cout << "Received an ICMP packet -> the port " << target_port << " it's closed" << std::endl;
            } else if (ip_header->ip_p == IPPROTO_UDP) {
                std::cout << "Received a UDP packet -> the port " << target_port << " it's open" << std::endl;
            }
            
            std::cout << "First 16 bytes of the header: ";
            print_header_bytes(packet, 16);
        }

    } else if (res == 0) {
        if (protocol == Protocol::TCP) {
            std::cout << "Couldn't capture a reply" << std::endl;
        } else {
             // Aparentemente si tienes un timeout de UDP significa que el puerto está abierto o filtrado
            std::cout << "Couldn't capture a reply (timeout) -> The port " << target_port << " it's open or filtered" << std::endl;
        }
    } else {
        std::cerr << "Error capturing the packet: " << pcap_geterr(handle) << std::endl;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
}
