FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt update -y --fix-missing && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y software-properties-common
RUN DEBIAN_FRONTEND=noninteractive add-apt-repository ppa:ubuntu-toolchain-r/test
RUN DEBIAN_FRONTEND=noninteractive apt update -y --fix-missing && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y build-essential git graphviz clang-12 llvm-12 llvm-12-dev llvm-12-tools openssl libssl-dev graphviz-dev libcap-dev lsof wget gpg \
                                                  libsqlite3-dev libelf-dev libc6-dbg gettext libgnutls28-dev apt-utils libtool gettext-base cmake-curses-gui \
                                                  libcurl4-openssl-dev libjson-c-dev libpcre2-dev \
                                                  pkg-config autoconf automake autotools-dev libtool libev-dev libcunit1 gnupg cmake libstdc++-13-dev

# We use llvm-17 now
RUN wget https://apt.llvm.org/llvm-snapshot.gpg.key
RUN gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg llvm-snapshot.gpg.key
RUN echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-17 main" | tee /etc/apt/sources.list.d/llvm.list
RUN DEBIAN_FRONTEND=noninteractive apt update && apt upgrade -y && apt install -y llvm-17 llvm-17-dev llvm-17-tools clang-17 lld-17

ENV LLVM_CONFIG=/usr/bin/llvm-config-17
RUN ln -s /usr/bin/clang-17 /usr/bin/clang && ln -s /usr/bin/clang-17 /usr/bin/clang++

# install fuzzer
WORKDIR /tmp
RUN git clone https://github.com/QUICTester/QUIC-Fuzz.git quic-fuzz
WORKDIR /tmp/quic-fuzz
COPY aflnet.patch .
RUN git apply aflnet.patch
WORKDIR /tmp/quic-fuzz/aflnet
RUN wget https://www.openssl.org/source/openssl-3.0.2.tar.gz
RUN tar xzvf openssl-3.0.2.tar.gz
WORKDIR /tmp/quic-fuzz/aflnet/openssl-3.0.2
RUN ./Configure linux-x86_64 no-shared
RUN make -j
WORKDIR /tmp/quic-fuzz/aflnet
RUN make clean all
WORKDIR /tmp/quic-fuzz/aflnet/llvm_mode
RUN make
WORKDIR /tmp/quic-fuzz/aflnet/SnapFuzz/SaBRe/plugins
RUN ln -sf ../../snapfuzz snapfuzz
WORKDIR /tmp/quic-fuzz/aflnet/SnapFuzz/SaBRe/
RUN mkdir build
WORKDIR /tmp/quic-fuzz/aflnet/SnapFuzz/SaBRe/build
RUN cmake -DCMAKE_BUILD_TYPE=RELEASE -DSF_MEMFS=OFF -DSF_STDIO=ON -DSF_SLEEP=ON -DSF_SMARTDEFER=OFF .. && make -j && mv plugins/snapfuzz/libsnapfuzz.so  plugins/snapfuzz/libsnapfuzz_no_snap.so
RUN cmake -DCMAKE_BUILD_TYPE=RELEASE -DSF_MEMFS=OFF -DSF_STDIO=ON -DSF_SLEEP=ON -DSF_SMARTDEFER=ON .. && make -j
WORKDIR /tmp/quic-fuzz/aflnet/
RUN ln -sf SnapFuzz/SaBRe/build/sabre sabre && ln -sf SnapFuzz/SaBRe/build/plugins/snapfuzz/libsnapfuzz.so libsnapfuzz.so && ln -sf SnapFuzz/SaBRe/build/plugins/snapfuzz/libsnapfuzz_no_snap.so libsnapfuzz_no_snap.so

# install ChatAFL
WORKDIR /tmp
RUN git clone https://github.com/ChatAFLndss/ChatAFL.git chatafl
WORKDIR /tmp/chatafl/ChatAFL
RUN git checkout 1ea603eb && \
    cp /tmp/quic-fuzz/patches/chat_afl.patch chat_afl.patch && \
    cp /tmp/quic-fuzz/patches/chat_afl_quic.c quic.c && \
    cp /tmp/quic-fuzz/patches/chat_afl_quic.h quic.h
ARG OPENAI_API_KEY
RUN sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$OPENAI_API_KEY\"/" chat-llm.h && \
    git apply chat_afl.patch && \
    make clean all && \
    cp /tmp/quic-fuzz/aflnet/aflnet-replay aflnet-replay

# start install the server
WORKDIR /tmp
RUN git clone --recursive https://github.com/ngtcp2/ngtcp2
WORKDIR /tmp/ngtcp2
RUN git clone --depth 1 -b v5.7.0-stable https://github.com/wolfSSL/wolfssl
WORKDIR /tmp/ngtcp2/wolfssl
COPY wolfssl.patch .
RUN git apply wolfssl.patch
RUN autoreconf -i
RUN ./configure --prefix=$PWD/build --enable-all --enable-aesni --enable-harden --disable-ech
RUN make -j
RUN make install
WORKDIR /tmp/ngtcp2
RUN git clone --recursive https://github.com/ngtcp2/nghttp3
WORKDIR /tmp/ngtcp2/nghttp3/lib/sfparse
RUN git checkout 6e15726
WORKDIR /tmp/ngtcp2/nghttp3
RUN git checkout 6bcfffb
RUN autoreconf -i
RUN ./configure --prefix=$PWD/build --enable-lib-only
RUN make -j check
RUN make install
WORKDIR /tmp/ngtcp2
# v1.5.0
RUN git checkout e2372a8
COPY ngtcp2.patch .
RUN git apply ngtcp2.patch
RUN autoreconf -i
RUN ./configure CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX="/tmp/quic-fuzz/aflnet/afl-clang-fast++" PKG_CONFIG_PATH=$PWD/wolfssl/build/lib/pkgconfig:$PWD/nghttp3/build/lib/pkgconfig --with-wolfssl --disable-shared --enable-static
RUN AFL_USE_ASAN=1 CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" make -j check

WORKDIR /tmp
RUN git clone --recursive https://github.com/ngtcp2/ngtcp2 ngtcp2_cov
WORKDIR /tmp/ngtcp2_cov
RUN git clone --depth 1 -b v5.7.0-stable https://github.com/wolfSSL/wolfssl
WORKDIR /tmp/ngtcp2_cov/wolfssl
COPY wolfssl.patch .
RUN git apply wolfssl.patch
RUN autoreconf -i
RUN ./configure --prefix=$PWD/build --enable-all --enable-aesni --enable-harden --disable-ech
RUN make -j
RUN make install
WORKDIR /tmp/ngtcp2_cov
RUN git clone --recursive https://github.com/ngtcp2/nghttp3
WORKDIR /tmp/ngtcp2_cov/nghttp3/lib/sfparse
RUN git checkout 6e15726
WORKDIR /tmp/ngtcp2_cov/nghttp3
RUN git checkout 6bcfffb
RUN autoreconf -i
RUN ./configure --prefix=$PWD/build --enable-lib-only
RUN make -j check
RUN make install
WORKDIR /tmp/ngtcp2_cov
# v1.5.0
RUN git checkout e2372a8
COPY ngtcp2_cov.patch .
RUN git apply ngtcp2_cov.patch
RUN autoreconf -i
RUN ./configure CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX=/tmp/quic-fuzz/aflnet/afl-clang-fast++ CFLAGS="-fprofile-instr-generate -fcoverage-mapping" CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" LDFLAGS="-fprofile-instr-generate -fcoverage-mapping"  PKG_CONFIG_PATH=$PWD/wolfssl/build/lib/pkgconfig:$PWD/nghttp3/build/lib/pkgconfig --with-wolfssl --disable-shared --enable-static
RUN make -j

# copy script/file to be run in container
WORKDIR /tmp
COPY run.sh run
RUN chmod +x run
COPY cov_script.sh cov_script
RUN chmod +x cov_script
COPY server-cert.pem server-cert.pem
COPY server-key.pem server-key.pem
COPY ngtcp2_seed ngtcp2_seed
# COPY ngtcp2_RetryClientAuth_seed ngtcp2_RetryClientAuth_seed
ENV WORKDIR="/tmp"
