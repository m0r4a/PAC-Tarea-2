#include "./include/args.h"
#include "./include/escaneo.h"
#include "./include/sniffer.h"
#include "./include/utils.h"
#include "./include/JSONGen.h"
#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <future>
#include <algorithm>
#include <map>

// Esto es "una unidad de trabajo"
struct ScanTask {
    int port;
    Protocol protocol;
};

// Esto no sé si va a estar 100% bien con un patrón de producción y bla bla pero
// esto es para evitar las famosas "race conditions", es decir, que los hilos hagan cosas
// extrañas por no saber el estado de los demás hilos

//  Esto funciona como una queue global que todos los hilos comparten, (productor - consumidor)
std::queue<ScanTask> g_task_queue;

// Esto garantiza el acceso atómico a g_task_queue, esto es lo que previene las race conditions
std::mutex g_queue_mutex;

// Aquí es donde se almacenan los resultados de cada tarea de escaneo
std::vector<ScanResult> g_results;

// Esto protege el acceso a g_results durante las inserciones
std::mutex g_results_mutex;

// Esta es la función que se ejecuta por cada "worker" (cada hilo)
void scan_worker(const AppConfig& config) {

    // Esto es el bucle principal, se ejecuta hasta que la cola de tareas termine
    while (true) {
        ScanTask task;
        {
            // lock_guard se asegura de que el mutex se libere automáticamente
            std::lock_guard<std::mutex> lock(g_queue_mutex);

            // Esta es la salida del hilo, si ya no hay nada que hacer el trabajo terminó
            if (g_task_queue.empty()) return;
            task = g_task_queue.front();
            g_task_queue.pop();
        }

        Scanner scanner(config.target_ip, config.timeout_ms);
        ScanResult final_result{};
        final_result.port = task.port;
        final_result.protocol = task.protocol;
        final_result.service = get_service_name(task.port, task.protocol);

        if (task.protocol == Protocol::TCP) {
            // Esta es la lógica del escaneo TCP, conexión activa y captura pasiva
            Sniffer sniffer(config.interface, config.target_ip, task.port);

            // Se usa un patrón "promise/future" para la comunicación asíncrona entre
            // este hilo y el hilo del sniffer que se crea después
            std::promise<SnifferResult> sniffer_promise;
            std::future<SnifferResult> sniffer_future = sniffer_promise.get_future();
            
            // Se crea un hilo específico para el sniffer para capturar los paquetes
            std::thread sniffer_thread(&Sniffer::start, &sniffer, task.protocol, std::move(sniffer_promise));
            // Se le da una pausita para darle tiempo al sniffer a iniciar la captura antes de enviar paquetes
            // la idea es mitigar una race condition, una condition variable sería mejor pero esto me sirve
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            // Se inicia el escaneo
            PortStatus connect_status = scanner.scanTCP(task.port);
            
            SnifferResult sniffer_result;
            // Se espera el resultado del sniffer pero con timeout para no estar esperando infinitamente
            if (sniffer_future.wait_for(std::chrono::milliseconds(config.timeout_ms)) == std::future_status::ready) {
                sniffer_result = sniffer_future.get(); // Si estuvo listo a tiempo se toma el resultado
            } else {
                sniffer.stop(); // IMPORTANTE: si el "futuro" expiró se detiene la captura
            }
            sniffer_thread.join(); // Esto sincroniza y espera a que el hilo del sniffer termine
            
            final_result.header_bytes = sniffer_result.header_bytes;
            // Esto prioriza el resultado del sniffer basado en una respuesta real sobre el escaneo que se hace con connect()
            final_result.status = (sniffer_result.packet_found && sniffer_result.status != PortStatus::UNKNOWN)
                                   ? sniffer_result.status
                                   : connect_status;
                                   
        } else {
            
            Sniffer sniffer(config.interface, config.target_ip, task.port);
            std::promise<SnifferResult> sniffer_promise;
            std::future<SnifferResult> sniffer_future = sniffer_promise.get_future();
            
            std::thread sniffer_thread(&Sniffer::start, &sniffer, task.protocol, std::move(sniffer_promise));
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Más tiempo para UDP
            
            // se envia el paquete de sondeo UDP DESPUÉS de asegurarse que el sniffer está escuchando
            if (!scanner.sendUDPProbe(task.port)) {
                sniffer.stop();
                sniffer_thread.join();
                continue;  // Si el envío falla solo se continúa
            }
            
            SnifferResult sniffer_result;
            if (sniffer_future.wait_for(std::chrono::milliseconds(config.timeout_ms)) == std::future_status::ready) {
                // Si el sniffer capturó un paquete ICMP es que está cerrado
                // si capturó algo en UDP está abierto, esta lógica se maneja en sniffer.cpp
                sniffer_result = sniffer_future.get();
                final_result.header_bytes = sniffer_result.header_bytes;
                final_result.status = sniffer_result.status;
            } else {
                sniffer.stop();
                sniffer_thread.join();
                // Como estamos mandando un payload vacío puede ser que el puerto SÍ
                // esté abierto pero no sepa que responder así que se maneja ese caso
                final_result.status = PortStatus::OPEN_FILTERED;
            }
            
            // Esto se asegura que el hilo del sniffer siempre esté unido anque el futuro expire
            if (sniffer_thread.joinable()) {
                sniffer_thread.join();
            }
        }

        {
            // Aquí almacenas los resultados
            std::lock_guard<std::mutex> lock(g_results_mutex);
            g_results.push_back(final_result);
        }
    }
}


// Imprime los resultados de forma ordenada, no supe hacer que lo haga en orden a pesar de que sea por hilos,
// demasiada complejidad comparada con el proyecto anterior
void print_results(const std::vector<ScanResult>& results) {
    std::map<PortStatus, std::string> status_map = {
        {PortStatus::OPEN, "Abierto"},
        {PortStatus::CLOSED, "Cerrado"},
        {PortStatus::FILTERED, "Filtrado"},
        {PortStatus::OPEN_FILTERED, "Abierto|Filtrado"},
        {PortStatus::UNKNOWN, "Desconocido"}
    };
    
    std::vector<ScanResult> sorted_results = results;

    // Ordena los resultados por puerto y luego por protocolo
    std::sort(sorted_results.begin(), sorted_results.end(), [](const ScanResult& a, const ScanResult& b) {
        if (a.port != b.port) return a.port < b.port;
        return static_cast<int>(a.protocol) < static_cast<int>(b.protocol);
    });

    std::cout << "\nPUERTO\t\tESTADO\t\tSERVICIO" << std::endl;
    std::cout << "------\t\t------\t\t--------" << std::endl;

    for (const auto& result : sorted_results) {
        // IMPORTANTE: Esto hace que no se muestren los puertos cerrados
        if (result.status == PortStatus::CLOSED) continue;
        
        const char* protocol_str = (result.protocol == Protocol::TCP) ? "TCP" : "UDP";
        std::cout << result.port << "/" << protocol_str
                  << "\t\t" << status_map[result.status]
                  << "\t\t" << result.service
                  << std::endl;
    }
}

int main(int argc, char* argv[]) {
    AppConfig config = ArgsParser::parse(argc, argv);
    if (config.show_help || !config.args_validos) return config.args_validos ? 0 : 1;

    // Se determina el número de hilos
    size_t num_threads = config.num_threads > 0 ? config.num_threads : std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    std::cout << "Iniciando escaneo en " << config.target_ip << " con " << num_threads << " hilos..." << std::endl;

    // Se llena la queue de tareas con los puertos y protocolos a escanear
    for (Protocol protocol : config.protocols_to_scan) {
        for (int port : config.ports) {
            g_task_queue.push({port, protocol});
        }
    }

    // Se crea y lanza la pool de hilos
    std::vector<std::thread> workers;
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back(scan_worker, std::cref(config));
    }

    // El hilo main espera a que todos los trabajadores completen su ejecución
    for (auto& worker : workers) {
        worker.join();
    }
    
    print_results(g_results);

    if (!config.output_file.empty()) {
        std::cout << "\nGenerando reporte en: " << config.output_file << "..." << std::endl;
        JSONGenerator::generate_report(config, g_results);
    }

    std::cout << "\nEscaneo completo." << std::endl;
    return 0;
}
