#include "include/args.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <string>

static std::vector<int> parsearPuertos(const std::string& input) {
    std::vector<int> puertos;
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (token.empty()) continue;

        size_t guion = token.find('-');
        try {
            if (guion != std::string::npos) {
                int inicio = std::stoi(token.substr(0, guion));
                int fin = std::stoi(token.substr(guion + 1));
                if (inicio >= 1 && fin <= 65535 && inicio <= fin) {
                    for (int p = inicio; p <= fin; ++p) puertos.push_back(p);
                }
            } else {
                int puerto = std::stoi(token);
                if (puerto >= 1 && puerto <= 65535) puertos.push_back(puerto);
            }
        } catch (...) { /* Si algo está mal se ignora */ }
    }
    std::sort(puertos.begin(), puertos.end());
    puertos.erase(std::unique(puertos.begin(), puertos.end()), puertos.end());
    return puertos;
}

void ArgsParser::imprimirUso(const char* prog) {
    std::cout << "Uso: " << prog << " <objetivo> [opciones]\n\n";
    std::cout << "Argumentos:\n";
    std::cout << "  objetivo                      Dirección IP o nombre del host a escanear\n\n";
    std::cout << "Opciones de Escaneo:\n";
    std::cout << "  -u, --udp                     Realizar un escaneo UDP (el predeterminado es TCP)\n";
    std::cout << "  -tu, -ut                      Realizar escaneo TCP y UDP\n";
    std::cout << "  -p PUERTOS                    Puertos a escanear (ej. 1-100, 22,80,443)\n";
    std::cout << "  -i, --interface INTERFAZ      Interfaz de red a usar (predeterminado: enp109s0)\n\n";
    std::cout << "Opciones de Salida y Rendimiento:\n";
    std::cout << "  -t, --threads N               Número de hilos a usar (predeterminado: máximo posible)\n";
    std::cout << "  --timeout MS            Timeout en milisegundos (predeterminado: 2000)\n";
    std::cout << "  -o, --output ARCHIVO    Archivo de salida para el reporte JSON\n";
    std::cout << "  -h, --help              Muestra esta ayuda\n";
}

AppConfig ArgsParser::parse(int argc, char* argv[]) {
    AppConfig config;
    if (argc < 2 || std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
        imprimirUso(argv[0]);
        config.show_help = true;
        return config;
    }

    config.target_ip = argv[1];
    std::string puertoInput = "1-1024";
    bool protocol_explicitly_set = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-u" || arg == "--udp") {
            config.protocols_to_scan.push_back(Protocol::UDP);
            protocol_explicitly_set = true;
        } else if (arg == "-tu" || arg == "-ut") {
            config.protocols_to_scan.push_back(Protocol::TCP);
            config.protocols_to_scan.push_back(Protocol::UDP);
            protocol_explicitly_set = true;
        }
        else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            try { config.num_threads = std::max(1, std::stoi(argv[++i])); } catch (...) {}
        }
        else if ((arg == "-p") && i + 1 < argc) {
            puertoInput = argv[++i];
        }
        else if (arg.rfind("--timeout=", 0) == 0) {
            try { config.timeout_ms = std::stoi(arg.substr(10)); } catch (...) {}
        } 
        else if ((arg == "--timeout") && i + 1 < argc) {
            try { config.timeout_ms = std::stoi(argv[++i]); } catch (...) {}
        } 
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            config.interface = argv[++i];
        }
    }

    if (!protocol_explicitly_set) {
        config.protocols_to_scan.push_back(Protocol::TCP);
    }

    std::sort(config.protocols_to_scan.begin(), config.protocols_to_scan.end());
    config.protocols_to_scan.erase(std::unique(config.protocols_to_scan.begin(), config.protocols_to_scan.end()), config.protocols_to_scan.end());

    config.ports = parsearPuertos(puertoInput);
    if (config.ports.empty()) {
        std::cerr << "error, no se especificaron puertos válidos." << std::endl;
        config.args_validos = false;
    }

    return config;
}
