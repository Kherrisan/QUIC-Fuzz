FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt update -y --fix-missing && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y software-properties-common
RUN DEBIAN_FRONTEND=noninteractive add-apt-repository ppa:ubuntu-toolchain-r/test
RUN DEBIAN_FRONTEND=noninteractive apt update -y --fix-missing && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y build-essential git graphviz clang-12 llvm-12 llvm-12-dev llvm-12-tools openssl libssl-dev graphviz-dev libcap-dev lsof wget gpg \
                                                  libsqlite3-dev libelf-dev libc6-dbg gettext libgnutls28-dev apt-utils libtool gettext-base cmake-curses-gui \
                                                  libcurl4-openssl-dev libjson-c-dev libpcre2-dev \
                                                  sudo apt-transport-https curl gnupg libicu-dev

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

RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
RUN mv bazel-archive-keyring.gpg /usr/share/keyrings
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
RUN DEBIAN_FRONTEND=noninteractive apt update && sudo apt install -y bazel
RUN DEBIAN_FRONTEND=noninteractive apt install -y bazel-6.2.1

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

# install server
WORKDIR /tmp
RUN git clone https://github.com/google/quiche.git google_quiche
WORKDIR /tmp/google_quiche
RUN git checkout 149b7e62
COPY google_quiche.patch .
RUN git apply google_quiche.patch
# pull the boringssl library (specific version is in WORKSPACE.bazel)
RUN bazel build "@boringssl//:crypto" "@boringssl//:ssl"
WORKDIR /tmp/google_quiche/bazel-google_quiche/external/boringssl
COPY boringssl.patch .
RUN patch -p1 < boringssl.patch
WORKDIR /tmp/google_quiche/
# google_quiche will produce cid according to the one send by client, so no need to patch for cid
RUN bazel build "@boringssl//:crypto" "@boringssl//:ssl" "@com_google_absl//absl/algorithm:container" "@com_google_absl//absl/base:core_headers" "@com_google_absl//absl/cleanup" "@com_google_absl//absl/container:btree" "@com_google_absl//absl/container:flat_hash_map" "@com_google_absl//absl/container:flat_hash_set" "@com_google_absl//absl/container:inlined_vector" "@com_google_absl//absl/container:node_hash_map" "@com_google_absl//absl/functional:any_invocable" "@com_google_absl//absl/functional:function_ref" "@com_google_absl//absl/hash" "@com_google_absl//absl/memory" "@com_google_absl//absl/numeric:bits" "@com_google_absl//absl/numeric:int128" "@com_google_absl//absl/status" "@com_google_absl//absl/status:statusor" "@com_google_absl//absl/strings" "@com_google_absl//absl/strings:str_format" "@com_google_absl//absl/time" "@com_google_absl//absl/types:optional" "@com_google_absl//absl/types:span" "@com_google_absl//absl/types:variant" "@zlib"
RUN AFL_USE_ASAN=1 CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX=/tmp/quic-fuzz/aflnet/afl-clang-fast++ bazel build --copt="-fsanitize=address" --cxxopt="-fsanitize=address" --linkopt="-fsanitize=address" --cxxopt=-DNDEBUG "//quiche:quiche_platform_default" "//quiche:quiche_protobufs_cc_proto" "//quiche:quic_server"

WORKDIR /tmp
RUN git clone https://github.com/google/quiche.git google_quiche_cov
WORKDIR /tmp/google_quiche_cov
RUN git checkout 149b7e62
COPY google_quiche.patch .
RUN git apply google_quiche.patch
# pull the boringssl library (specific version is in WORKSPACE.bazel)
RUN CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX=/tmp/quic-fuzz/aflnet/afl-clang-fast++ bazel build "@boringssl//:crypto" "@boringssl//:ssl"
WORKDIR /tmp/google_quiche_cov/bazel-google_quiche_cov/external/boringssl
COPY boringssl.patch .
RUN patch -p1 < boringssl.patch
WORKDIR /tmp/google_quiche_cov/
COPY google_quiche_cov.patch .
RUN git apply google_quiche_cov.patch
RUN CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX=/tmp/quic-fuzz/aflnet/afl-clang-fast++ bazel build "@boringssl//:crypto" "@boringssl//:ssl" "@com_google_absl//absl/algorithm:container" "@com_google_absl//absl/base:core_headers" "@com_google_absl//absl/cleanup" "@com_google_absl//absl/container:btree" "@com_google_absl//absl/container:flat_hash_map" "@com_google_absl//absl/container:flat_hash_set" "@com_google_absl//absl/container:inlined_vector" "@com_google_absl//absl/container:node_hash_map" "@com_google_absl//absl/functional:any_invocable" "@com_google_absl//absl/functional:function_ref" "@com_google_absl//absl/hash" "@com_google_absl//absl/memory" "@com_google_absl//absl/numeric:bits" "@com_google_absl//absl/numeric:int128" "@com_google_absl//absl/status" "@com_google_absl//absl/status:statusor" "@com_google_absl//absl/strings" "@com_google_absl//absl/strings:str_format" "@com_google_absl//absl/time" "@com_google_absl//absl/types:optional" "@com_google_absl//absl/types:span" "@com_google_absl//absl/types:variant" "@zlib"
RUN CC=/tmp/quic-fuzz/aflnet/afl-clang-fast CXX=/tmp/quic-fuzz/aflnet/afl-clang-fast++ bazel build --copt="-fprofile-instr-generate" --copt="-fcoverage-mapping" --copt="-DNDEBUG" --cxxopt="-fprofile-instr-generate" --cxxopt="-fcoverage-mapping" --cxxopt="-DNDEBUG" --linkopt="-fprofile-instr-generate" --linkopt="-fcoverage-mapping" "//quiche:quiche_platform_default" "//quiche:quiche_protobufs_cc_proto" "//quiche:quic_server"

# copy script/file to be run in container
WORKDIR /tmp
COPY run.sh run
RUN chmod +x run
COPY cov_script.sh cov_script
RUN chmod +x cov_script
COPY google_quiche-cert.pem google_quiche-cert.pem
COPY google_quiche-key.pem google_quiche-key.pem
COPY google_quiche_seed google_quiche_seed
ENV WORKDIR="/tmp"