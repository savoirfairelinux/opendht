from conans import ConanFile, CMake, tools
import os


class SobjectizerConan(ConanFile):
    name = "restinio"
    version = "0.5.1"

    license = "BSD-3-Clause"
    url = "https://github.com/Stiffstream/restinio-conan"

    description = (
            "RESTinio is a header-only C++14 library that gives you "
            "an embedded HTTP/Websocket server."
    )

    settings = "os", "compiler", "build_type", "arch"
    options = {'boost_libs': ['none', 'static', 'shared']}
    default_options = {'boost_libs': 'none'}
    generators = "cmake"
    source_subfolder = "restinio"
    build_policy = "missing"

    def requirements(self):
        self.requires.add("http-parser/2.8.1@bincrafters/stable")
        self.requires.add("fmt/5.3.0@bincrafters/stable")

        if self.options.boost_libs == "none":
            self.requires.add("asio/1.12.2@bincrafters/stable")
        else:
            self.requires.add("boost/1.69.0@conan/stable")
            if self.options.boost_libs == "shared":
                self.options["boost"].shared = True
            else:
                self.options["boost"].shared = False

    def source(self):
        source_url = "https://bitbucket.org/sobjectizerteam/restinio/downloads"
        tools.get("{0}/restinio-{1}.zip".format(source_url, self.version))
        extracted_dir = "restinio-" + self.version
        os.rename(extracted_dir, self.source_subfolder)

    def _configure_cmake(self):
        cmake = CMake(self)
        cmake.definitions['RESTINIO_INSTALL'] = True
        cmake.definitions['RESTINIO_FIND_DEPS'] = False
        cmake.definitions['RESTINIO_USE_BOOST_ASIO'] = self.options.boost_libs
        cmake.configure(source_folder = self.source_subfolder + "/dev/restinio")
        return cmake

    def package(self):
        cmake = self._configure_cmake()
        self.output.info(cmake.definitions)
        cmake.install()

    def package_info(self):
        self.info.header_only()
        if self.options.boost_libs != "none":
            self.cpp_info.defines.append("RESTINIO_USE_BOOST_ASIO")
