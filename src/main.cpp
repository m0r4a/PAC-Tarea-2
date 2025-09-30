#include "./include/escaneo.h"
#include "./include/sniffer.h"
#include "./include/common.h"
#include <iostream>
#include <thread>
#include <chrono>


// TCP example
// const Protocol SCAN_PROTOCOL = Protocol::TCP;
// const char* TARGET_IP = "127.0.0.1";
// const int TARGET_PORT = 80;
// const char* INTERFACE = "lo";

// UDP
const Protocol SCAN_PROTOCOL = Protocol::UDP;
const char* TARGET_IP = "127.0.0.1";
const int TARGET_PORT = 1234;
const char* INTERFACE = "lo";

int main() {
    Scanner scanner(TARGET_IP, TARGET_PORT);
    Sniffer sniffer(INTERFACE, TARGET_IP, TARGET_PORT);

    std::atomic<bool> stop_sniffer(false);

    std::cout << "Starting sniffer in the background..." << std::endl;
    std::thread sniffer_thread(&Sniffer::start, &sniffer, SCAN_PROTOCOL, std::ref(stop_sniffer));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (SCAN_PROTOCOL == Protocol::TCP) {
        scanner.scanTCP();
    } else {
        scanner.scanUDP();
    }

    // El hilo principal espera 2 segundos, el tiempo máximo para recibir una respuesta UDP
    // porque si no cuando el puerto está abierto se queda esperando infinitamente
    std::this_thread::sleep_for(std::chrono::seconds(2));

    stop_sniffer.store(true);
    
    // esperar a que el hilo termine de forma limpia
    sniffer_thread.join();

    std::cout << "\nScan and capture finished" << std::endl;

    return 0;
}
