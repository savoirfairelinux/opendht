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
set(_pip_commands 
    "${Python3_EXECUTABLE};-m;pip;install;--no-deps;--break-system-packages;${CMAKE_CURRENT_BINARY_DIR}"
    "${Python3_EXECUTABLE};-m;pip;install;--no-deps;${CMAKE_CURRENT_BINARY_DIR}"
    "pip3;install;--no-deps;--break-system-packages;${CMAKE_CURRENT_BINARY_DIR}"
    "pip;install;--no-deps;--break-system-packages;${CMAKE_CURRENT_BINARY_DIR}")

install(CODE [[
    # Try different pip installation methods
    
    set(_success FALSE)
    foreach(_cmd_list ${_pip_commands})
        string(REPLACE ";" " " _cmd_str "${_cmd_list}")
        message(STATUS "Attempting: ${_cmd_str}")
        
        execute_process(
            COMMAND ${_cmd_list}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            OUTPUT_VARIABLE _pip_output
            ERROR_VARIABLE _pip_error
            RESULT_VARIABLE _pip_result)
            
        if(_pip_result EQUAL 0)
            message(STATUS "Successfully installed Python package")
            message(STATUS "Output: ${_pip_output}")
            set(_success TRUE)
            break()
        else()
            message(WARNING "Command failed with code ${_pip_result}")
            message(WARNING "Output: ${_pip_output}")
            message(WARNING "Error: ${_pip_error}")
        endif()
    endforeach()
    
    if(NOT _success)
        message(FATAL_ERROR "All pip install attempts failed. Check that pip is available and the wheel was built correctly.")
    endif()
]])
if (OPENDHT_TOOLS)
	install(PROGRAMS tools/dhtcluster.py DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME dhtcluster)
endif()
