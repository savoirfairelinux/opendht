find_path (JSONCPP_INCLUDE jsoncpp
           HINTS
           "/usr/include"
           "/usr/local/include"
           "/opt/local/include"
)

if (JSONCPP_INCLUDE)
    message(STATUS "${green}Found Jsoncpp: ${JSONCPP_INCLUDE}")
else()
    message(FATAL_ERROR "${red}Failed to locate Jsoncpp.}")
endif()

if (JSONCPP_INCLUDE)
    set(JSONCPP_FOUND TRUE)
    set(Jsoncpp_LIBRARIES jsoncpp)
    set(Jsoncpp_INCLUDE_DIRS ${JSONCPP_INCLUDE}/jsoncpp)
endif()
