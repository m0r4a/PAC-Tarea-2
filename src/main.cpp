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
    // 1. Se crean las instancias de los objetos primero.
    Scanner scanner(TARGET_IP, TARGET_PORT);
    Sniffer sniffer(INTERFACE, TARGET_IP, TARGET_PORT);

    // 2. Se lanza el sniffer en un hilo de fondo.
    //    Este hilo empieza a ejecutar sniffer.start() inmediatamente.
    std::cout << "Iniciando sniffer en segundo plano..." << std::endl;
    std::thread sniffer_thread(&Sniffer::start, &sniffer, SCAN_PROTOCOL);

    // 3. Se hace una pequeña pausa para asegurar que el hilo del sniffer
    //    ya esté activo y escuchando en la red.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 4. Con el sniffer ya escuchando, se ejecuta el scanner en el hilo principal.
    //    La llamada a scanTCP/scanUDP enviará el paquete que el sniffer está esperando.
    if (SCAN_PROTOCOL == Protocol::TCP) {
        scanner.scanTCP();
    } else {
        scanner.scanUDP();
    }

    // 5. El hilo principal espera a que el hilo del sniffer termine.
    //    'join()' detiene el programa aquí hasta que sniffer.start() finalice
    //    (ya sea porque capturó un paquete o por timeout).
    sniffer_thread.join();

    std::cout << "\nEscaneo y captura finalizados." << std::endl;

    return 0;
}
