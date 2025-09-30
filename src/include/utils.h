#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <map>
#include "common.h"

static std::map<int, std::string> TCP_SERVICE_MAP = {
    {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
    {25, "smtp"}, {53, "domain"}, {80, "http"}, {110, "pop3"}, 
    {143, "imap"}, {389, "ldap"}, {443, "https"}, {445, "microsoft-ds"}, 
    {993, "imaps"}, {995, "pop3s"}, {1433, "ms-sql-s"}, {1521, "oracle"}, 
    {3306, "mysql"}, {3389, "ms-wbt-server"}, {5432, "postgresql"}, 
    {5900, "vnc"}, {6379, "redis"}, {8080, "http-proxy"}, {8443, "https-alt"}
};

static std::map<int, std::string> UDP_SERVICE_MAP = {
    {53, "domain"}, {67, "bootps"}, {68, "bootpc"}, {69, "tftp"}, 
    {123, "ntp"}, {135, "msrpc"}, {137, "netbios-ns"}, {138, "netbios-dgm"},
    {139, "netbios-ssn"}, {161, "snmp"}, {514, "syslog"}, {1900, "ssdp"}, 
    {5353, "mdns"}
};

inline std::string get_service_name(int port, Protocol protocol) {
    if (protocol == Protocol::TCP) {
        auto it = TCP_SERVICE_MAP.find(port);
        if (it != TCP_SERVICE_MAP.end()) {
            return it->second;
        }
    } else {
        auto it = UDP_SERVICE_MAP.find(port);
        if (it != UDP_SERVICE_MAP.end()) {
            return it->second;
        }
    }
    return "unknown";
}

#endif
