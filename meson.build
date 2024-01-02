project('opendht', 'c', 'cpp',
    version: '3.1.7',
    default_options: [
        'cpp_std=c++17',
        'warning_level=3'
    ])

gnutls = dependency('gnutls')
nettle = dependency('nettle')
msgpack = dependency('msgpack-cxx', required : false)
argon2 = dependency('libargon2')
openssl = dependency('openssl', required: get_option('proxy_client'))
jsoncpp = dependency('jsoncpp', required: get_option('proxy_client'))
fmt = dependency('fmt')

dirs=[]
if host_machine.system() == 'freebsd'
    dirs+='/usr/local/lib'
elif host_machine.system() == 'darwin'
    dirs+='/opt/homebrew/lib'
endif
http_parser = meson.get_compiler('c').find_library('http_parser', dirs: dirs, required: get_option('proxy_client'))
deps = [fmt, gnutls, nettle, msgpack, argon2, openssl, jsoncpp, http_parser]

add_project_arguments('-DMSGPACK_NO_BOOST', language : 'cpp')
add_project_arguments(['-Wno-return-type','-Wno-deprecated','-Wnon-virtual-dtor','-pedantic-errors','-fvisibility=hidden'], language : 'cpp')

opendht_inc = include_directories('include/opendht')
opendht_interface_inc = include_directories('include', is_system: true)
opendht_src = [
    'src/utils.cpp',
    'src/crypto.cpp',
    'src/default_types.cpp',
    'src/node.cpp',
    'src/value.cpp',
    'src/dht.cpp',
    'src/callbacks.cpp',
    'src/routing_table.cpp',
    'src/node_cache.cpp',
    'src/network_engine.cpp',
    'src/securedht.cpp',
    'src/dhtrunner.cpp',
    'src/log.cpp',
    'src/op_cache.cpp',
    'src/network_utils.cpp'
]
if jsoncpp.found()
    opendht_src += ['src/base64.cpp']
    add_project_arguments('-DOPENDHT_JSONCPP', language : 'cpp')
endif
if http_parser.found()
    opendht_src += ['src/http.cpp', 'src/compat/os_cert.cpp']
    if host_machine.system() == 'darwin'
        deps+=dependency('appleframeworks', modules : ['CoreFoundation', 'Security'])
    endif
endif
if get_option('proxy_client').enabled()
    opendht_src += ['src/dht_proxy_client.cpp']
    add_project_arguments('-DOPENDHT_PROXY_CLIENT', language : 'cpp')
endif
if get_option('proxy_server').enabled()
    opendht_src += 'src/dht_proxy_server.cpp'
    add_project_arguments('-DOPENDHT_PROXY_SERVER', language : 'cpp')
endif
if get_option('peer_discovery').enabled()
    opendht_src += 'src/peer_discovery.cpp'
    add_project_arguments('-DOPENDHT_PEER_DISCOVERY', language : 'cpp')
endif
opendht = shared_library('opendht',
    opendht_src,
    include_directories : opendht_inc,
    dependencies : deps,
    cpp_args : ['-DOPENHT_BUILD', '-Dopendht_EXPORTS'],
    install : true)

readline = meson.get_compiler('c').find_library('readline', required: get_option('tools'))

if get_option('c').enabled()
    opendht_c = shared_library('opendht-c',
        ['c/opendht.cpp',  'c/opendht_c.h'],
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [msgpack, fmt],
        cpp_args : ['-DOPENDHT_C_BUILD', '-Dopendht_c_EXPORTS'],
        install : true)

    if get_option('tools').enabled()
        dhtcnode = executable('dhtcnode', 'tools/dhtcnode.c',
            include_directories : ['c', opendht_interface_inc],
            link_with : opendht_c,
            dependencies : [readline],
            install : true)
    endif
endif

if get_option('tools').enabled()
    dhtnode = executable('dhtnode', 'tools/dhtnode.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, msgpack, fmt, openssl],
        install : true)
    dhtchat = executable('dhtchat', 'tools/dhtchat.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, msgpack, fmt, openssl],
        install : true)
    dhtscanner = executable('dhtscanner', 'tools/dhtscanner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, msgpack, fmt, openssl],
        install : true)
    if http_parser.found()
        durl = executable('durl', 'tools/durl.cpp',
            include_directories : opendht_interface_inc,
            link_with : opendht,
            dependencies : [msgpack, openssl])
    endif
endif
