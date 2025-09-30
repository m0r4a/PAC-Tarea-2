#include "./include/args.h"
#include "./include/escaneo.h"
#include "./include/sniffer.h"
#include "./include/common.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <queue>
#include <mutex>
#include <functional>

std::queue<int> g_port_queue;
std::mutex g_queue_mutex;
std::mutex g_cout_mutex;

void scan_worker(const AppConfig& config, Protocol protocol) {
    while (true) {
        int puerto;

        {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            if (g_port_queue.empty()) {
                return;
            }
            puerto = g_port_queue.front();
            g_port_queue.pop();
        }

        Scanner scanner(config.target_ip, puerto);
        Sniffer sniffer(config.interface, config.target_ip, puerto);

        std::atomic<bool> stop_sniffer(false);
        std::thread sniffer_thread(&Sniffer::start, &sniffer, protocol, std::ref(stop_sniffer));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        if (protocol == Protocol::TCP) {
            scanner.scanTCP();
        } else {
            scanner.scanUDP();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(config.timeout_ms));
        stop_sniffer.store(true);
        sniffer_thread.join();
    }
}

int main(int argc, char* argv[]) {
    AppConfig config = ArgsParser::parse(argc, argv);
    if (config.show_help || !config.args_validos) {
        return config.args_validos ? 0 : 1;
    }

    size_t num_threads = config.num_threads;
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }

    std::cout << "Iniciando escaneo en " << config.target_ip << " sobre " << config.ports.size() << " puertos..." << std::endl;
    std::cout << "Usando " << num_threads << " hilos" << std::endl;

    for (Protocol protocol : config.protocols_to_scan) {
        const char* protocol_str = (protocol == Protocol::TCP) ? "TCP" : "UDP";
        std::cout << "\nEscaneando puertos " << protocol_str << std::endl;

        {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            for (int puerto : config.ports) {
                g_port_queue.push(puerto);
            }
        }

        std::vector<std::thread> workers;
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back(scan_worker, std::cref(config), protocol);
        }

        for (auto& worker : workers) {
            worker.join();
        }
    }

    if (!config.output_file.empty()) {
        std::cout << "\nGenerando reporte en: " << config.output_file << "..." << std::endl;
        // aqui va la lógica para generar el JSON
    }

    std::cout << "\nEscaneo completo" << std::endl;
    return 0;
}
