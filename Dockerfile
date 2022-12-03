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
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND noninteractive

ADD scripts/docker_install.sh /tmp/
RUN chmod +x /tmp/docker_install.sh && /tmp/docker_install.sh

# Python modules
COPY py/bitbox02 /tmp/bitbox02
RUN python3 -m pip install /tmp/bitbox02 && \
    rm -r /tmp/bitbox02
COPY py/requirements.txt /tmp
RUN python3 -m pip install --upgrade --requirement /tmp/requirements.txt && \
    rm /tmp/requirements.txt

#Install protoc from release, because the version available on the repo is too old
RUN mkdir -p /opt/protoc && \
    curl -L0 https://github.com/protocolbuffers/protobuf/releases/download/v21.2/protoc-21.2-linux-x86_64.zip -o /tmp/protoc-21.2-linux-x86_64.zip && \
    unzip /tmp/protoc-21.2-linux-x86_64.zip -d /opt/protoc
ENV PATH /opt/protoc/bin:$PATH

# Install Go, used for the tools in tools/go and for test/gounittest
ENV GOPATH=/opt/go GOROOT=/opt/go_dist/go PATH=$GOROOT/bin:$GOPATH/bin:$PATH
RUN mkdir -p /opt/go_dist && \
    curl https://dl.google.com/go/go1.19.3.linux-amd64.tar.gz | tar -xz -C /opt/go_dist

# Install lcov from release (the one from the repos is too old).
RUN cd /opt && wget https://github.com/linux-test-project/lcov/releases/download/v1.14/lcov-1.14.tar.gz && tar -xf lcov-1.14.tar.gz
ENV PATH /opt/lcov-1.14/bin:$PATH

# Install rust compiler
ENV PATH=/opt/cargo/bin:$PATH RUSTUP_HOME=/opt/rustup
COPY src/rust/rust-toolchain /tmp/rust-toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- --default-toolchain $(cat /tmp/rust-toolchain | tr -d '\r\n\t') -y
RUN rustup target add thumbv7em-none-eabi
RUN rustup component add rustfmt clippy
RUN CARGO_HOME=/opt/cargo cargo install cbindgen@0.24.3 bindgen-cli@0.61.0

COPY tools/prost-build prost-build
RUN CARGO_HOME=/opt/cargo cargo install --path prost-build --locked

# Clean temporary files to reduce image size
RUN rm -rf /var/lib/apt/lists/*
