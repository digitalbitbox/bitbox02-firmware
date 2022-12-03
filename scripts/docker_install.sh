#!/bin/bash

apt-get update
apt-get upgrade -y
apt-get install -y wget nano rsync curl gnupg2 jq unzip bzip2

# for clang-*-15, see https://apt.llvm.org/
echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main" >> /etc/apt/sources.list
echo "deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main" >> /etc/apt/sources.list
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

# Install gcc8-arm-none-eabi
mkdir ~/Downloads
cd ~/Downloads
wget -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major
echo "fb31fbdfe08406ece43eef5df623c0b2deb8b53e405e2c878300f7a1f303ee52 gcc.tar.bz2" | sha256sum -c
cd ~/Downloads
tar -xjvf gcc.tar.bz2
rm -f gcc.tar.bz2
cd ~/Downloads && rsync -a gcc-arm-none-eabi-8-2018-q4-major/ /usr/local/

# Tools for building
apt-get update
apt-get install -y \
    build-essential \
    llvm-15 \
    gcc-10 \
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
    libhidapi-dev \
    doxygen \
    graphviz \
    python3 \
    python3-pip \
    clang-format-15 \
    clang-tidy-15 \
    bash-completion


# Set gcc-10 as the default gcc
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-10 100

# Make Python3 the default
update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# install pip
python -m pip install --upgrade pip

python -m pip install --upgrade \
    # Python modules for CI
    pylint==2.13.9 \
    pylint-protobuf==0.20.2 \
    black==22.3.0 \
    mypy==0.960 \
    mypy-protobuf==3.2.0 \
    # Python modules for packaging
    setuptools==41.2.0 \
    wheel==0.33.6 \
    twine==1.15.0

# Install gcovr from PIP to get a newer version than in apt repositories
python -m pip install gcovr