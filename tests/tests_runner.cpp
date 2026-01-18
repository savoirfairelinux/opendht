// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/CompilerOutputter.h>
#include <iostream>

extern "C" {
#include <gnutls/gnutls.h>
}

int
main(int /*argc*/, char** /*argv*/)
{
#ifdef _MSC_VER
    if (auto err = gnutls_global_init()) {
        std::cerr << "Failed to initialize GnuTLS: " << gnutls_strerror(err) << std::endl;
        return EXIT_FAILURE;
    }
#endif

    CppUnit::TestFactoryRegistry& registry = CppUnit::TestFactoryRegistry::getRegistry();
    CppUnit::Test* suite = registry.makeTest();
    if (suite->countTestCases() == 0) {
        std::cout << "No test cases specified for suite" << std::endl;
        return 1;
    }
    CppUnit::TextUi::TestRunner runner;
    runner.addTest(suite);
    auto result = runner.run() ? 0 : 1;
    return result;
}
