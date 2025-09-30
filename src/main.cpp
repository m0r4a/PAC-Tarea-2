#include "./include/escaneo.h"
#include "./include/sniffer.h"
#include "./include/common.h"

// TCP example
// const Protocol SCAN_PROTOCOL = Protocol::TCP
// const char* TARGET_IP = "127.0.0.1";
// const int TARGET_PORT = 80;
// const char* INTERFACE = "lo";

// UDP
const Protocol SCAN_PROTOCOL = Protocol::UDP;
const char* TARGET_IP = "8.8.8.8";
const int TARGET_PORT = 53;
const char* INTERFACE = "enp109s0";

int main() {
    Scanner scanner(TARGET_IP, TARGET_PORT);
    bool scan_successful = false;

    if (SCAN_PROTOCOL == Protocol::TCP) {
        scan_successful = scanner.scanTCP();
    } else {
        scan_successful = scanner.scanUDP();
    }

    if (scan_successful) {
        Sniffer sniffer(INTERFACE, TARGET_IP, TARGET_PORT);
        sniffer.start(SCAN_PROTOCOL);
    }

    return 0;
}
