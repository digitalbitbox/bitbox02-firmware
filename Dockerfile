# Copyright 2019 Shift Cryptosecurity AG
# Copyright 2020 Shift Crypto AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Latest Ubuntu LTS
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y wget nano rsync curl gnupg2 jq unzip

# for clang-*-8, see https://apt.llvm.org/
RUN echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main" >> /etc/apt/sources.list && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

# Install gcc8-arm-none-eabi
RUN mkdir ~/Downloads &&\
    cd ~/Downloads &&\
    wget -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major &&\
    echo "fb31fbdfe08406ece43eef5df623c0b2deb8b53e405e2c878300f7a1f303ee52 gcc.tar.bz2" | sha256sum -c &&\
    cd ~/Downloads &&\
    tar -xjvf gcc.tar.bz2 &&\
    rm -f gcc.tar.bz2 &&\
    cd ~/Downloads && rsync -a gcc-arm-none-eabi-8-2018-q4-major/ /usr/local/

# Tools for building
RUN apt-get update && apt-get install -y \
    build-essential \
    llvm \
    gcc-8 \
    binutils \
    valgrind \
    cmake \
    git \
    autotools-dev \
    automake \
    autoconf \
    libtool \
    pkg-config \
    libcmocka-dev \
    libc6-i386 \
    lib32stdc++6 \
    lib32z1 \
    libusb-1.0-0-dev \
    libudev-dev \
    libhidapi-dev

RUN apt-get update && apt-get install -y \
    doxygen \
    graphviz

# Set gcc-8 as the default gcc
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 100
RUN update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-8 100

# Tools for CI
RUN apt-get update && apt-get install -y \
    python \
    python3 \
    python3-pip \
    clang-format-8 \
    clang-tidy-8

RUN python3 -m pip install --upgrade pip

# Python modules
COPY py/bitbox02 /tmp/bitbox02
RUN python3 -m pip install /tmp/bitbox02
RUN rm -r /tmp/bitbox02
COPY py/requirements.txt /tmp
RUN python3 -m pip install --upgrade --requirement /tmp/requirements.txt
RUN rm /tmp/requirements.txt

# Python modules for CI
RUN python3 -m pip install --upgrade \
    pylint==2.13.9 \
    pylint-protobuf==0.20.2 \
    black==22.3.0 \
    mypy==0.960 \
    mypy-protobuf==3.2.0

# Python modules for packaging
RUN python3 -m pip install --upgrade \
    setuptools==41.2.0 \
    wheel==0.33.6 \
    twine==1.15.0

#Install protoc from release, because the version available on the repo is too old
RUN mkdir -p /opt/protoc && \
    curl -L0 https://github.com/protocolbuffers/protobuf/releases/download/v21.2/protoc-21.2-linux-x86_64.zip -o /tmp/protoc-21.2-linux-x86_64.zip && \
    unzip /tmp/protoc-21.2-linux-x86_64.zip -d /opt/protoc
ENV PATH /opt/protoc/bin:$PATH

# Make Python3 the default, so tools/nanopb/generator/*.py run with Python3.
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Developer tools
RUN apt-get update && apt-get install -y \
    bash-completion
# Install gcovr from PIP to get a newer version than in apt repositories
RUN python3 -m pip install gcovr

# Install Go, used for the tools in tools/go and for test/gounittest
ENV GOPATH /opt/go
ENV GOROOT /opt/go_dist/go
ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH
RUN mkdir -p /opt/go_dist && \
    curl https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz | tar -xz -C /opt/go_dist

# Install lcov from release (the one from the repos is too old).
RUN cd /opt && wget https://github.com/linux-test-project/lcov/releases/download/v1.14/lcov-1.14.tar.gz && tar -xf lcov-1.14.tar.gz
ENV PATH /opt/lcov-1.14/bin:$PATH

# Install rust compiler
ENV PATH /opt/cargo/bin:$PATH
ENV RUSTUP_HOME=/opt/rustup
COPY src/rust/rust-toolchain /tmp/rust-toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- --default-toolchain $(cat /tmp/rust-toolchain | tr -d '\r\n\t') -y
RUN rustup target add thumbv7em-none-eabi
RUN rustup component add rustfmt
RUN rustup component add clippy
RUN rustup component add rust-src
RUN CARGO_HOME=/opt/cargo cargo install cbindgen --version 0.23.0
RUN CARGO_HOME=/opt/cargo cargo install bindgen --version 0.59.2
RUN git clone -b 2022-08-08 https://github.com/rust-lang/rust-analyzer.git && cd rust-analyzer && CARGO_HOME=/opt/cargo cargo xtask install --server

COPY tools/prost-build prost-build
RUN CARGO_HOME=/opt/cargo cargo install --path prost-build --locked

# Clean temporary files to reduce image size
RUN rm -rf /var/lib/apt/lists/*
