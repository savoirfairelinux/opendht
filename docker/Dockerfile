FROM aberaud/opendht-deps
LABEL maintainer="Adrien Béraud <adrien.beraud@savoirfairelinux.com>"

RUN git clone https://github.com/savoirfairelinux/opendht.git \
	&& cd opendht && mkdir build && cd build \
	&& cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
				-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=On \
				-DOPENDHT_C=On \
				-DOPENDHT_PYTHON=On \
				-DOPENDHT_PROXY_SERVER=On \
				-DOPENDHT_PROXY_CLIENT=On \
	&& make -j8 && make install \
	&& cd ../.. && rm -rf opendht
