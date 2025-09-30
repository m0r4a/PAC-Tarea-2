#ifndef JSONGEN_H
#define JSONGEN_H

#include <vector>
#include "common.h"
#include "args.h"

namespace JSONGenerator {

    void generate_report(const AppConfig& config, const std::vector<ScanResult>& results);

}

#endif
