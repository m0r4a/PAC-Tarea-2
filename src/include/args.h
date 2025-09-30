#ifndef ARGS_H
#define ARGS_H

#include <string>
#include <vector>
#include "common.h"

struct AppConfig {
    std::string target_ip;
    std::vector<int> ports;
    std::vector<Protocol> protocols_to_scan;
    int timeout_ms = 2000;
    std::string interface = "enp109s0";
    std::string output_file;
    size_t num_threads = 0;
    bool show_help = false;
    bool args_validos = true;
};

namespace ArgsParser {
    AppConfig parse(int argc, char* argv[]);
    void imprimirUso(const char* prog);
}

#endif
