// src/main.cpp
#include "./include/escaneo.h"
#include "./include/sniffer.h"

// --- simple config ---
const char* TARGET_IP = "127.0.0.1";
const int TARGET_PORT = 80;
const char* INTERFACE = "lo";

int main() {
    Scanner scanner(TARGET_IP, TARGET_PORT);

    // Si el escaneo TCP determina que el puerto está abierto...
    if (scanner.scanTCP()) {
        // ...entonces inicia el sniffer para capturar la respuesta.
        Sniffer sniffer(INTERFACE, TARGET_IP, TARGET_PORT);
        sniffer.start();
    }

    return 0;
}
