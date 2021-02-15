# Copyright 2019 Shift Cryptosecurity AG
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
"""BitBox python package"""
import os.path
import re
from distutils.core import setup
import setuptools


def read(*path: str) -> str:
    cwd = os.path.dirname(os.path.realpath(__file__))
    filename = os.path.join(cwd, *path)
    with open(filename, "r") as filereader:
        return filereader.read()


def find_version() -> str:
    version_file = read("bitbox02/bitbox02", "__init__.py")
    version_match = re.search(r"^__version__ = \"(.*)\"$", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Version string not found")


setup(
    name="bitbox02",
    version=find_version(),
    author="Shift Crypto",
    author_email="support@shiftcrypto.ch",
    packages=setuptools.find_packages(),
    description="Python library for bitbox02 communication",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/digitalbitbox/bitbox02-firmware",
    python_requires=">=3.6",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
    ],
    keywords="digitalbitbox bitbox bitbox02 bitcoin litecoin ethereum erc20 u2f",
    # https://mypy.readthedocs.io/en/stable/installed_packages.html#installed-packages
    zip_safe=False,
    package_data={
        "bitbox02": ["py.typed"],
        "bitbox02.bitbox02": ["py.typed"],
        "bitbox02.bitboxbase": ["py.typed"],
        "bitbox02.communication": ["py.typed"],
        "bitbox02.communication.generated": [
            "backup_commands_pb2.pyi",
            "bitbox02_system_pb2.pyi",
            "bitboxbase_pb2.pyi",
            "btc_pb2.pyi",
            "common_pb2.pyi",
            "eth_pb2.pyi",
            "hww_pb2.pyi",
            "keystore_pb2.pyi",
            "mnemonic_pb2.pyi",
            "perform_attestation_pb2.pyi",
            "random_number_pb2.pyi",
            "system_pb2.pyi",
        ],
    },
    install_requires=[
        "hidapi>=0.7.99.post21",
        "noiseprotocol>=0.3",
        "protobuf>=3.7",
        "ecdsa>=0.14",
        "semver>=2.8.1",
        # Needed as long as we support python < 3.7
        "typing_extensions>=3.7.4",
        "base58>=2.0.0",
    ],
    extras_require={"ethereum": ["rlp>=2.0.1"]},
)
