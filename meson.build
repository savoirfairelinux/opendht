project('opendht', 'c', 'cpp', 'cython',
    version: '3.3.0',
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
llhttp = dependency('llhttp', 'libllhttp', required: get_option('proxy_client'))
io_uring = dependency('liburing', required: false)

deps = [fmt, gnutls, nettle, msgpack, argon2, openssl, jsoncpp, llhttp, io_uring]
conf_data = configuration_data()

add_project_arguments('-DMSGPACK_NO_BOOST', '-DASIO_STANDALONE', language : 'cpp')
if io_uring.found()
    add_project_arguments('-DASIO_HAS_IO_URING', '-DASIO_DISABLE_EPOLL', language : 'cpp')
    conf_data.set('iouring_lib', ', liburing')
endif
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
    'src/network_utils.cpp',
    'src/thread_pool.cpp',
]

if get_option('indexation').enabled()
    opendht_src += 'src/indexation/pht.cpp'
    add_project_arguments('-DOPENDHT_INDEXATION', language : 'cpp')
endif
if jsoncpp.found()
    opendht_src += ['src/base64.cpp']
    add_project_arguments('-DOPENDHT_JSONCPP', language : 'cpp')
    conf_data.set('jsoncpp_lib', ', jsoncpp')
endif
if llhttp.found()
    opendht_src += ['src/http.cpp', 'src/compat/os_cert.cpp']
    if host_machine.system() == 'darwin'
        deps+=dependency('appleframeworks', modules : ['CoreFoundation', 'Security'])
    endif
    conf_data.set('http_lib', '-lllhttp')
endif
if openssl.found()
    conf_data.set('openssl_lib', ', openssl')
endif
if get_option('proxy_client').enabled()
    opendht_src += ['src/dht_proxy_client.cpp']
    add_project_arguments('-DOPENDHT_PROXY_CLIENT', language : 'cpp')
endif
if get_option('proxy_server').enabled()
    opendht_src += 'src/dht_proxy_server.cpp'
    add_project_arguments('-DOPENDHT_PROXY_SERVER', language : 'cpp')
endif
if get_option('push_notifications').enabled()
    add_project_arguments('-DOPENDHT_PUSH_NOTIFICATIONS', language : 'cpp')
endif
if get_option('peer_discovery').enabled()
    opendht_src += 'src/peer_discovery.cpp'
    add_project_arguments('-DOPENDHT_PEER_DISCOVERY', language : 'cpp')
endif
opendht = library('opendht',
    opendht_src,
    include_directories : opendht_inc,
    dependencies : deps,
    cpp_args : ['-DOPENHT_BUILD', '-Dopendht_EXPORTS'],
    install : true)

conf_data.set('VERSION', meson.project_version())
conf_data.set('prefix', get_option('prefix'))
conf_data.set('exec_prefix', get_option('prefix'))
conf_data.set('libdir', join_paths(get_option('prefix'), get_option('libdir')))
conf_data.set('includedir', join_paths(get_option('prefix'), get_option('includedir')))
conf_data.set('argon2_lib', ', libargon2')

configure_file(input : 'opendht.pc.in',
               output : 'opendht.pc',
               configuration : conf_data,
               install: true,
               install_dir: join_paths(get_option('prefix'), get_option('libdir'), 'pkgconfig'))

readline = meson.get_compiler('c').find_library('readline', required: get_option('tools'))

if get_option('c').enabled()
    opendht_c = library('opendht-c',
        ['c/opendht.cpp',  'c/opendht_c.h'],
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [msgpack, jsoncpp, fmt],
        cpp_args : ['-DOPENDHT_C_BUILD', '-Dopendht_c_EXPORTS'],
        install : true)
    
    configure_file(input : 'opendht-c.pc.in',
                   output : 'opendht-c.pc',
                   configuration : conf_data,
                   install: true,
                   install_dir: join_paths(get_option('prefix'), get_option('libdir'), 'pkgconfig'))

    if get_option('tools').enabled()
        dhtcnode = executable('dhtcnode', 'tools/dhtcnode.c',
            include_directories : ['c', opendht_interface_inc],
            link_with : opendht_c,
            dependencies : [readline],
            install : true)
    endif
endif

if get_option('python').require(get_option('indexation').enabled(), error_message: 'python requires indexation').allowed()
    py = import('python').find_installation()
    dep_py = py.dependency()
    py.extension_module(
        'opendht',
        'python/opendht.pyx',
        include_directories : opendht_interface_inc,
        override_options : ['cython_language=cpp'],
        link_with : [opendht],
        dependencies : [msgpack, jsoncpp, fmt, dep_py],
        install : true
    )
endif

if get_option('tools').enabled()
    dhtnode = executable('dhtnode', 'tools/dhtnode.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, jsoncpp, msgpack, fmt, openssl],
        install : true)
    dhtchat = executable('dhtchat', 'tools/dhtchat.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, jsoncpp, msgpack, fmt, openssl],
        install : true)
    dhtscanner = executable('dhtscanner', 'tools/dhtscanner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [readline, jsoncpp, msgpack, fmt, openssl],
        install : true)
    if llhttp.found()
        durl = executable('durl', 'tools/durl.cpp',
            include_directories : opendht_interface_inc,
            link_with : opendht,
            dependencies : [msgpack, openssl])
    endif
endif

# Unit tests
if get_option('tests').enabled()
    cppunit = dependency('cppunit')

    test_infohash = executable('test_infohash',
        'tests/infohashtester.cpp', 'tests/tests_runner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
    test('Infohash', test_infohash)

    test_value = executable('test_value',
        'tests/valuetester.cpp', 'tests/tests_runner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
    test('Value', test_value)

    test_crypto = executable('test_crypto',
        'tests/cryptotester.cpp', 'tests/tests_runner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
    test('Crypto', test_crypto)

    test_dhtrunner = executable('test_dhtrunner',
        'tests/dhtrunnertester.cpp', 'tests/tests_runner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
    test('DhtRunner', test_dhtrunner)

    test_threadpool = executable('test_threadpool',
        'tests/threadpooltester.cpp', 'tests/tests_runner.cpp',
        include_directories : opendht_interface_inc,
        link_with : opendht,
        dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
    test('ThreadPool', test_threadpool)

    if get_option('proxy_client').enabled() or get_option('proxy_server').enabled()
        test_http = executable('test_http',
            'tests/httptester.cpp', 'tests/tests_runner.cpp',
            include_directories : opendht_interface_inc,
            link_with : opendht,
            dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
        test('Http', test_http)
    endif

    if get_option('peer_discovery').enabled()
        test_peerdiscovery = executable('test_peerdiscovery',
            'tests/peerdiscoverytester.cpp', 'tests/tests_runner.cpp',
            include_directories : opendht_interface_inc,
            link_with : opendht,
            dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
        test('PeerDiscovery', test_peerdiscovery)
    endif

    if get_option('proxy_server').enabled()
        test_proxy = executable('test_dhtproxy',
            'tests/dhtproxytester.cpp', 'tests/tests_runner.cpp',
            include_directories : opendht_interface_inc,
            link_with : opendht,
            dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
        test('DhtProxy', test_proxy)

        if get_option('long_tests').enabled()
            test_proxystress = executable('test_dhtproxystress',
                'tests/dhtproxy_stress_tester.cpp', 'tests/tests_runner.cpp',
                include_directories : opendht_interface_inc,
                link_with : opendht,
                dependencies : [cppunit, jsoncpp, fmt, openssl, msgpack])
            test('DhtProxy Stress', test_proxystress)
        endif
    endif
endif
