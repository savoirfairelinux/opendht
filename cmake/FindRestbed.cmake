find_path (RESTBED_INCLUDE restbed
           HINTS
           "/usr/include"
           "/usr/local/include"
           "/opt/local/include"
)

if (RESTBED_INCLUDE)
    message(STATUS "${green}Found Restbed: ${RESTBED_INCLUDE}")
else()
    message(FATAL_ERROR "${red}Failed to locate Restbed.}")
endif()

if (RESTBED_INCLUDE)
    set(RESTBED_FOUND TRUE)
    set(Restbed_LIBRARIES restbed)
endif()
