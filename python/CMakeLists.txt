set(CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CURRENT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

configure_file(setup.py.in setup.py)
configure_file(pyproject.toml pyproject.toml COPYONLY)
configure_file(README.md README.md COPYONLY)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_target(python
    COMMAND ${Python3_EXECUTABLE} -m build "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS opendht opendht_cpp.pxd opendht.pyx pyproject.toml
            ${CURRENT_SOURCE_DIR}/opendht/__init__.py
            ${CURRENT_SOURCE_DIR}/opendht/aio.py)

install(CODE [[
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -m pip install --no-deps --break-system-packages "${CMAKE_CURRENT_BINARY_DIR}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        OUTPUT_VARIABLE _pip_output
        ERROR_VARIABLE _pip_output
        RESULT_VARIABLE _pip_result)
    message(STATUS ${_pip_output})
    if(NOT _pip_result EQUAL 0)
        message(FATAL_ERROR "pip install failed with code ${_pip_result}")
    endif()
]])
if (OPENDHT_TOOLS)
	install(PROGRAMS tools/dhtcluster.py DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME dhtcluster)
endif()
