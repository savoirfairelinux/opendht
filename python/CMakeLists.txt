set(CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CURRENT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

configure_file(setup.py.in setup.py)
configure_file(pyproject.toml pyproject.toml COPYONLY)
configure_file(README.md README.md COPYONLY)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_target(python ALL
    COMMAND ${Python3_EXECUTABLE} -m build .
    DEPENDS opendht opendht_cpp.pxd opendht.pyx pyproject.toml)

install(CODE [[
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -m pip install --no-deps --break-system-packages .
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        RESULT_VARIABLE _pip_result)
    if(NOT _pip_result EQUAL 0)
        message(FATAL_ERROR "pip install failed with code ${_pip_result}")
    endif()
]])
if (OPENDHT_TOOLS)
	install(PROGRAMS tools/dhtcluster.py DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME dhtcluster)
endif()
