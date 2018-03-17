FROM ubuntu:16.04
MAINTAINER Adrien Béraud <adrien.beraud@savoirfairelinux.com>
RUN apt-get update \
	&& apt-get install -y llvm llvm-dev clang make cmake git wget libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev libuv1-dev libmsgpack-dev libjsoncpp-dev libasio-dev cython3 python3-dev python3-setuptools libcppunit-dev \
	&& apt-get remove -y gcc g++ && apt-get autoremove -y && apt-get clean

ENV CC cc
ENV CXX c++

# build restbed from sources
RUN git clone --recursive https://github.com/corvusoft/restbed.git \
	&& cd restbed && mkdir build && cd build \
	&& cmake -DBUILD_TESTS=NO -DBUILD_EXAMPLES=NO -DBUILD_SSL=NO -DBUILD_SHARED=YES -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib .. \
	&& make -j8 install \
	&& cd .. && rm -rf restbed

#build msgpack from source
RUN wget https://github.com/msgpack/msgpack-c/releases/download/cpp-2.1.5/msgpack-2.1.5.tar.gz \
	&& tar -xzf msgpack-2.1.5.tar.gz \
	&& cd msgpack-2.1.5 && mkdir build && cd build \
	&& cmake -DMSGPACK_CXX11=ON -DMSGPACK_BUILD_EXAMPLES=OFF -DCMAKE_INSTALL_PREFIX=/usr .. \
	&& make -j8 && make install \
	&& cd ../.. && rm -rf msgpack-2.1.5 msgpack-2.1.5.tar.gz
