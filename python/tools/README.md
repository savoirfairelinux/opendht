# Benchmark

The `benchmark.py` script is used for testing OpenDHT in various cases. If you
run `benchmark.py --help`, you should find the following text:

    optional arguments:
      -h, --help            show this help message and exit
      --performance         Launches performance benchmark test. Available args
                            for "-t" are: gets.
      --data-persistence    Launches data persistence benchmark test. Available
                            args for "-t" are: delete, replace, mult_time.
                            Available args for "-o" are : dump_str_log,
                            keep_alive, trigger, traffic_plot, op_plot. Use "-m"
                            to specify the number of producers on the DHT.Use "-e"
                            to specify the number of values to put on the DHT.

These options specify the feature to be tested. Each feature has its own tests.
You specify the test by using `-t` flag (see `benchmark.py --help` for full
help).

## Python dependencies

- pyroute2 >=0.3.14
- matplotlib
- GeoIP (used by `scanner.py` for drawing map of the world)
- ipaddress
- netifaces
- networkx
- numpy

## Usage

Before running the script, you have to build and install OpenDHT and its cython
wrapper (`cython3` has to be installed) on the system so that it can be found by
the benchmark script.

    $ cd $OPENDHT_SRC_DIR
    $ ./autogen.sh
    $ ./configure
    $ make && sudo make install

Then, you can use the script like so:

    $ cd $OPENDHT_SRC_DIR/python/tools/
    $ python3 benchmark.py --performance -t gets -n 2048
