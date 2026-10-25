FROM ghcr.io/savoirfairelinux/opendht/opendht-deps:latest
LABEL maintainer="Adrien Béraud <adrien.beraud@savoirfairelinux.com>"
LABEL org.opencontainers.image.source=https://github.com/savoirfairelinux/opendht

RUN apt-get update && apt-get install -y --no-install-recommends \
	libmsgpack-cxx-dev libllhttp-dev libsimdutf-dev \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY . opendht

RUN cd opendht && mkdir build && cd build \
	&& cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
				-DBUILD_TESTING=Off \
				-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=On \
				-DOPENDHT_C=On \
				-DOPENDHT_PEER_DISCOVERY=On \
				-DOPENDHT_PYTHON=On \
				-DOPENDHT_TOOLS=On \
				-DOPENDHT_PROXY_SERVER=On \
				-DOPENDHT_PROXY_CLIENT=On \
				-DOPENDHT_SYSTEMD=On \
	&& make -j8 && make install \
	&& cd ../.. && rm -rf opendht
