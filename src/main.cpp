#include "./include/escaneo.h"
#include "./include/sniffer.h"

// --- simple config ---
const char* TARGET_IP = "127.0.0.1";
const int TARGET_PORT = 80;
const char* INTERFACE = "lo";

int main() {
    Scanner scanner(TARGET_IP, TARGET_PORT);

    if (scanner.scanTCP()) {
        Sniffer sniffer(INTERFACE, TARGET_IP, TARGET_PORT);
        sniffer.startTCP();
    }

    return 0;
}
