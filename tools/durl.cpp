// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#include <opendht/http.h>
#include <opendht/log.h>

#include <asio/io_context.hpp>
#ifndef _MSC_VER
#include <getopt.h>
#else
#include "wingetopt.h"
#endif

using namespace dht;

void
print_info()
{
    std::cout << "durl, a simple http(s) client." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

void
print_version()
{
    std::cout << "OpenDHT version " << dht::version() << std::endl;
    print_info();
}

void
print_usage()
{
    std::cout << "Usage: durl url" << std::endl << std::endl;
    print_info();
}

static const constexpr struct option long_options[] = {
    {"help",    no_argument, nullptr, 'h'},
    {"headers", no_argument, nullptr, 'H'},
    {"verbose", no_argument, nullptr, 'v'},
    {"version", no_argument, nullptr, 'V'},
    {nullptr,   0,           nullptr, 0  }
};

struct durl_params
{
    std::string url;
    bool help {false};
    bool log {false};
    bool headers {false};
    bool version {false};
};

durl_params
parseArgs(int argc, char** argv)
{
    durl_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvVH", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'V':
            params.version = true;
            break;
        case 'h':
            params.help = true;
            break;
        case 'H':
            params.headers = true;
            break;
        case 'v':
            params.log = true;
            break;
        default:
            break;
        }
    }

    if (optind < argc) {
        params.url = argv[optind++];
    }

    return params;
}

int
main(int argc, char** argv)
{
    auto params = parseArgs(argc, argv);
    if (params.help) {
        print_usage();
        return 0;
    }
    if (params.version) {
        print_version();
        return 0;
    }

    std::shared_ptr<dht::Logger> logger;
    if (params.log) {
        logger = dht::log::getStdLogger();
    }

    asio::io_context ctx;
    auto request = std::make_shared<dht::http::Request>(
        ctx,
        params.url,
        [&](const dht::http::Response& response) {
            if (params.headers) {
                for (const auto& header : response.headers)
                    std::cout << header.first << ": " << header.second << std::endl;
                std::cout << std::endl;
            }
            std::cout << response.body << std::endl;
            ctx.stop();
        },
        logger);
    request->send();
    auto work = asio::make_work_guard(ctx);
    ctx.run();
    return 0;
}
