// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/CompilerOutputter.h>
#include <iostream>

namespace {

void
listTests(CppUnit::Test* test, const std::string& prefix = {})
{
    const auto name = test->getName();
    const auto fullName = prefix.empty() ? name : prefix + "/" + name;
    if (test->getChildTestCount() == 0) {
        std::cout << fullName << std::endl;
        return;
    }
    for (int index = 0; index < test->getChildTestCount(); ++index)
        listTests(test->getChildTestAt(index), fullName);
}

} // namespace

extern "C" {
#include <gnutls/gnutls.h>
}

int
main(int argc, char** argv)
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
    if (argc > 1 && std::string(argv[1]) == "--list") {
        listTests(suite);
        return 0;
    }
    CppUnit::TextUi::TestRunner runner;
    if (argc > 1)
        runner.addTest(suite->findTest(argv[1]));
    else
        runner.addTest(suite);
    auto result = runner.run() ? 0 : 1;
    return result;
}
