#include "include/JSONGen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include "../include/nlohmann/json.hpp"

using json = nlohmann::json;

namespace JSONGenerator {

    std::string bytes_to_hex_string(const std::vector<unsigned char>& bytes) {
        if (bytes.empty()) {
            return "";
        }
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
            if (i < bytes.size() - 1) {
                ss << " ";
            }
        }
        return ss.str();
    }

    void generate_report(const AppConfig& config, const std::vector<ScanResult>& results) {
        json report_array = json::array();

        for (const auto& result : results) {
            if (result.status == PortStatus::CLOSED) {
                continue;
            }

            std::string status_str;
            switch(result.status) {
                case PortStatus::OPEN:          status_str = "open"; break;
                case PortStatus::FILTERED:      status_str = "filtered"; break;
                default:                        status_str = "unknown"; break;
            }

            json entry;
            entry["ip"] = config.target_ip;
            entry["port"] = result.port;
            entry["status"] = status_str;
            entry["protocol"] = (result.protocol == Protocol::TCP) ? "TCP" : "UDP";
            entry["service"] = result.service;
            entry["header_bytes"] = bytes_to_hex_string(result.header_bytes);

            report_array.push_back(entry);
        }

        std::ofstream o(config.output_file);
        o << std::setw(4) << report_array << std::endl;
    }

}
