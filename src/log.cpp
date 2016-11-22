//
// Created by istvan on 11/22/16.
//

#include "log.h"

namespace dht {
    namespace log {

        /**
         * Print va_list to std::ostream (used for logging).
         */
        void
        printLog(std::ostream &s, char const *m, va_list args) {
            // print log to buffer
            std::array<char, 8192> buffer;
            int ret = vsnprintf(buffer.data(), buffer.size(), m, args);
            if (ret < 0)
                return;

            // write timestamp
            using namespace std::chrono;
            using log_precision = microseconds;
            constexpr auto den = log_precision::period::den;
            auto micro = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
            s << "[" << std::setfill('0') << std::setw(6) << micro / den << "."
              << std::setfill('0') << std::setw(6) << micro % den << "]" << " ";

            // write log
            s.write(buffer.data(), std::min((size_t) ret, buffer.size()));
            if ((size_t) ret >= buffer.size())
                s << "[[TRUNCATED]]";
            s << std::endl;
        }

        void
        enableLogging(dht::DhtRunner &dht) {
            dht.setLoggers(
                    [](char const *m, va_list args) {
                        std::cerr << red;
                        printLog(std::cerr, m, args);
                        std::cerr << def;
                    },
                    [](char const *m, va_list args) {
                        std::cout << yellow;
                        printLog(std::cout, m, args);
                        std::cout << def;
                    },
                    [](char const *m, va_list args) { printLog(std::cout, m, args); }
            );
        }

        void
        enableFileLogging(dht::DhtRunner &dht, const std::string &path) {
            auto logfile = std::make_shared<std::fstream>();
            logfile->open(path, std::ios::out);

            dht.setLoggers(
                    [=](char const *m, va_list args) { printLog(*logfile, m, args); },
                    [=](char const *m, va_list args) { printLog(*logfile, m, args); },
                    [=](char const *m, va_list args) { printLog(*logfile, m, args); }
            );
        }

        void
        disableLogging(dht::DhtRunner &dht) {
            dht.setLoggers(dht::NOLOG, dht::NOLOG, dht::NOLOG);
        }
    }
}