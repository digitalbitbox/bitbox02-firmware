// Copyright 2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "eth_params.h"

#include <util.h>

#include <wally_bip32.h>

#define BIP44_COINTYPE_TESTNET 1
#define BIP44_COINTYPE_ETH 60
#define BIP44_COINTYPE_ETC 61

static const app_eth_coin_params_t _params_eth = {
    .bip44_coin = BIP44_COINTYPE_ETH + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 1,
    .unit = "ETH",
};

static const app_eth_coin_params_t _params_ropsten_eth = {
    .bip44_coin = BIP44_COINTYPE_TESTNET + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 3,
    .unit = "TETH",
};

static const app_eth_coin_params_t _params_rinkeby_eth = {
    .bip44_coin = BIP44_COINTYPE_TESTNET + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 4,
    .unit = "TETH",
};

static const app_eth_coin_params_t _params_etc = {
    .bip44_coin = BIP44_COINTYPE_ETC + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 1,
    .unit = "ETC",
};

static const app_eth_coin_params_t _params_kotti_etc = {
    .bip44_coin = BIP44_COINTYPE_TESTNET + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 6,
    .unit = "TETC",
};

static const app_eth_coin_params_t _params_mordor_etc = {
    .bip44_coin = BIP44_COINTYPE_TESTNET + BIP32_INITIAL_HARDENED_CHILD,
    .chain_id = 7,
    .unit = "TETC",
};

const app_eth_coin_params_t* app_eth_params_get(ETHCoin coin)
{
    switch (coin) {
    case ETHCoin_ETH:
        return &_params_eth;
    case ETHCoin_RopstenETH:
        return &_params_ropsten_eth;
    case ETHCoin_RinkebyETH:
        return &_params_rinkeby_eth;
    case ETHCoin_ETC:
        return &_params_etc;
    case ETHCoin_KottiETC:
        return &_params_kotti_etc;
    case ETHCoin_MordorETC:
        return &_params_mordor_etc;
    default:
        return NULL;
    }
}

static const app_eth_erc20_params_t _ropsten_erc20_params[] = {
    {
        .name = "TEST",
        .unit = "TEST",
        .contract_address =
            "\x2f\x45\xb6\xfb\x2f\x28\xa7\x3f\x11\x04\x00\x38\x6d\xa3\x10\x44\xb2\xe9\x53\xd4",
        .decimals = 18,
    },
};

static const app_eth_erc20_params_t _ethereum_erc20_params[] = {
    {
        .name = "1SG",
        .unit = "1SG",
        .contract_address =
            "\x0f\x72\x71\x4b\x35\xa3\x66\x28\x5d\xf8\x58\x86\xa2\xee\x17\x46\x01\x29\x2a\x17",
        .decimals = 18,
    },
    {
        .name = "FirstBlood",
        .unit = "1ST",
        .contract_address =
            "\xaf\x30\xd2\xa7\xe9\x0d\x7d\xc3\x61\xc8\xc4\x58\x5e\x9b\xb7\xd2\xf6\xf1\x5b\xc7",
        .decimals = 18,
    },
    {
        .name = "1World",
        .unit = "1WO",
        .contract_address =
            "\xfd\xbc\x1a\xdc\x26\xf0\xf8\xf8\x60\x6a\x5d\x63\xb7\xd3\xa3\xcd\x21\xc2\x2b\x23",
        .decimals = 8,
    },
    {
        .name = "999",
        .unit = "999",
        .contract_address =
            "\xbf\x05\x57\x19\x88\xda\xab\x22\xd3\x3c\x28\xbb\xb1\x35\x66\xea\xe9\xde\xe6\x26",
        .decimals = 3,
    },
    {
        .name = "Airbloc",
        .unit = "ABL",
        .contract_address =
            "\xf8\xb3\x58\xb3\x39\x7a\x8e\xa5\x46\x4f\x8c\xc7\x53\x64\x5d\x42\xe1\x4b\x79\xea",
        .decimals = 18,
    },
    {
        .name = "Arcblock",
        .unit = "ABT",
        .contract_address =
            "\xb9\x8d\x4c\x97\x42\x5d\x99\x08\xe6\x6e\x53\xa6\xfd\xf6\x73\xac\xca\x0b\xe9\x86",
        .decimals = 18,
    },
    {
        .name = "Abyss Token",
        .unit = "ABYSS",
        .contract_address =
            "\x0e\x8d\x6b\x47\x1e\x33\x2f\x14\x0e\x7d\x9d\xbb\x99\xe5\xe3\x82\x2f\x72\x8d\xa6",
        .decimals = 18,
    },
    {
        .name = "Aladdin",
        .unit = "ADN",
        .contract_address =
            "\x95\xa4\x1f\xb8\x0c\xa7\x03\x06\xe9\xec\xf4\xe5\x1c\xea\x31\xbd\x18\x37\x9c\x18",
        .decimals = 18,
    },
    {
        .name = "adToken",
        .unit = "ADT",
        .contract_address =
            "\xd0\xd6\xd6\xc5\xfe\x4a\x67\x7d\x34\x3c\xc4\x33\x53\x6b\xb7\x17\xba\xe1\x67\xdd",
        .decimals = 9,
    },
    {
        .name = "AdEx",
        .unit = "ADX",
        .contract_address =
            "\x44\x70\xbb\x87\xd7\x7b\x96\x3a\x01\x3d\xb9\x39\xbe\x33\x2f\x92\x7f\x2b\x99\x2e",
        .decimals = 4,
    },
    {
        .name = "Aencoin",
        .unit = "AEN",
        .contract_address =
            "\x0b\xef\x61\x9c\xf3\x8c\xf0\xc2\x29\x67\x28\x9b\x84\x19\x72\x0f\xbd\x1d\xb9\xf7",
        .decimals = 8,
    },
    {
        .name = "Aergo",
        .unit = "AERGO",
        .contract_address =
            "\xae\x31\xb8\x5b\xfe\x62\x74\x7d\x08\x36\xb8\x26\x08\xb4\x83\x03\x61\xa3\xd3\x7a",
        .decimals = 18,
    },
    {
        .name = "Asian Fintech",
        .unit = "AFIN",
        .contract_address =
            "\xee\x9e\x5e\xff\x40\x1e\xe9\x21\xb1\x38\x49\x0d\x00\xca\x8d\x1f\x13\xf6\x7a\x72",
        .decimals = 8,
    },
    {
        .name = "SingularityNET",
        .unit = "AGI",
        .contract_address =
            "\x8e\xb2\x43\x19\x39\x37\x16\x66\x8d\x76\x8d\xce\xc2\x93\x56\xae\x9c\xff\xe2\x85",
        .decimals = 8,
    },
    {
        .name = "Agrocoin",
        .unit = "AGRO",
        .contract_address =
            "\x1f\xd2\x7f\x0c\xfc\x6f\x27\x3b\x87\xa5\xe0\xf6\xfc\xf0\x63\x42\x2e\x7b\xcd\x6a",
        .decimals = 18,
    },
    {
        .name = "AgaveCoin",
        .unit = "AGVC",
        .contract_address =
            "\x8b\x79\x65\x6f\xc3\x8a\x04\x04\x4e\x49\x5e\x22\xfa\xd7\x47\x12\x6c\xa3\x05\xc4",
        .decimals = 18,
    },
    {
        .name = "AI Doctor",
        .unit = "AIDOC",
        .contract_address =
            "\x58\x4b\x44\x85\x36\x80\xee\x34\xa0\xf3\x37\xb7\x12\xa8\xf6\x6d\x81\x6d\xf1\x51",
        .decimals = 18,
    },
    {
        .name = "Ambrosus",
        .unit = "AMB",
        .contract_address =
            "\x4d\xc3\x64\x3d\xbc\x64\x2b\x72\xc1\x58\xe7\xf3\xd2\xff\x23\x2d\xf6\x1c\xb6\xce",
        .decimals = 18,
    },
    {
        .name = "Amino Network",
        .unit = "AMIO",
        .contract_address =
            "\x2e\x68\xdf\xb3\xf5\x0e\xa3\x02\xc8\x8f\x8d\xb7\x40\x96\xd5\x75\x65\xd9\x97\x0a",
        .decimals = 18,
    },
    {
        .name = "AMLT",
        .unit = "AMLT",
        .contract_address =
            "\xca\x0e\x72\x69\x60\x0d\x35\x3f\x70\xb1\x4a\xd1\x18\xa4\x95\x75\x45\x5c\x0f\x2f",
        .decimals = 18,
    },
    {
        .name = "AMO Coin",
        .unit = "AMO",
        .contract_address =
            "\x38\xc8\x7a\xa8\x9b\x2b\x8c\xd9\xb9\x5b\x73\x6e\x1f\xa7\xb6\x12\xea\x97\x21\x69",
        .decimals = 18,
    },
    {
        .name = "Ampleforth",
        .unit = "AMPL",
        .contract_address =
            "\xd4\x6b\xa6\xd9\x42\x05\x0d\x48\x9d\xbd\x93\x8a\x2c\x90\x9a\x5d\x50\x39\xa1\x61",
        .decimals = 9,
    },
    {
        .name = "Anchor",
        .unit = "ANCT",
        .contract_address =
            "\x54\x56\xbc\x77\xdd\x27\x5c\x45\xc3\xc1\x5f\x0c\xf9\x36\xb7\x63\xcf\x57\xc3\xb5",
        .decimals = 8,
    },
    {
        .name = "Ankr",
        .unit = "ANKR",
        .contract_address =
            "\x82\x90\x33\x3c\xef\x9e\x6d\x52\x8d\xd5\x61\x8f\xb9\x7a\x76\xf2\x68\xf3\xed\xd4",
        .decimals = 18,
    },
    {
        .name = "Aragon",
        .unit = "ANT",
        .contract_address =
            "\x96\x0b\x23\x6a\x07\xcf\x12\x26\x63\xc4\x30\x33\x50\x60\x9a\x66\xa7\xb2\x88\xc0",
        .decimals = 18,
    },
    {
        .name = "Aurora",
        .unit = "AOA",
        .contract_address =
            "\x9a\xb1\x65\xd7\x95\x01\x9b\x6d\x8b\x3e\x97\x1d\xda\x91\x07\x14\x21\x30\x5e\x5a",
        .decimals = 18,
    },
    {
        .name = "AppCoins",
        .unit = "APPC",
        .contract_address =
            "\x1a\x7a\x8b\xd9\x10\x6f\x2b\x8d\x97\x7e\x08\x58\x2d\xc7\xd2\x4c\x72\x3a\xb0\xdb",
        .decimals = 18,
    },
    {
        .name = "Aeron",
        .unit = "ARN",
        .contract_address =
            "\xba\x5f\x11\xb1\x6b\x15\x57\x92\xcf\x3b\x2e\x68\x80\xe8\x70\x68\x59\xa8\xae\xb6",
        .decimals = 8,
    },
    {
        .name = "ARPA Chain",
        .unit = "ARPA",
        .contract_address =
            "\xba\x50\x93\x3c\x26\x8f\x56\x7b\xdc\x86\xe1\xac\x13\x1b\xe0\x72\xc6\xb0\xb7\x1a",
        .decimals = 18,
    },
    {
        .name = "AirSwap",
        .unit = "AST",
        .contract_address =
            "\x27\x05\x4b\x13\xb1\xb7\x98\xb3\x45\xb5\x91\xa4\xd2\x2e\x65\x62\xd4\x7e\xa7\x5a",
        .decimals = 4,
    },
    {
        .name = "Artfinity",
        .unit = "AT",
        .contract_address =
            "\xe5\x4b\x34\x58\xc4\x7e\x44\xc3\x7a\x26\x7e\x7c\x63\x3a\xfe\xf8\x82\x87\xc2\x94",
        .decimals = 5,
    },
    {
        .name = "ATC Coin",
        .unit = "ATCC",
        .contract_address =
            "\xdd\xaa\xf4\xa0\x70\x2a\x03\xa4\x50\x5f\x23\x52\xa1\xab\xa0\x01\xff\xc3\x44\xbe",
        .decimals = 18,
    },
    {
        .name = "ATLANT",
        .unit = "ATL",
        .contract_address =
            "\x78\xb7\xfa\xda\x55\xa6\x4d\xd8\x95\xd8\xc8\xc3\x57\x79\xdd\x8b\x67\xfa\x8a\x05",
        .decimals = 18,
    },
    {
        .name = "ATN",
        .unit = "ATN",
        .contract_address =
            "\x46\x17\x33\xc1\x7b\x07\x55\xca\x56\x49\xb6\xdb\x08\xb3\xe2\x13\xfc\xf2\x25\x46",
        .decimals = 18,
    },
    {
        .name = "Cube",
        .unit = "AUTO",
        .contract_address =
            "\x62\x2d\xff\xcc\x4e\x83\xc6\x4b\xa9\x59\x53\x0a\x5a\x55\x80\x68\x7a\x57\x58\x1b",
        .decimals = 18,
    },
    {
        .name = "B2BX",
        .unit = "B2B",
        .contract_address =
            "\x5d\x51\xfc\xce\xd3\x11\x4a\x8b\xb5\xe9\x0c\xdd\x0f\x9d\x68\x2b\xcb\xcc\x53\x93",
        .decimals = 18,
    },
    {
        .name = "BaaSid",
        .unit = "BAAS",
        .contract_address =
            "\x3e\x65\xe1\xee\xfd\xe5\xea\x7c\xcf\xc9\xa9\xa1\x63\x4a\xbe\x90\xf3\x22\x62\xf8",
        .decimals = 18,
    },
    {
        .name = "Band Protocol",
        .unit = "BAND",
        .contract_address =
            "\xba\x11\xd0\x0c\x5f\x74\x25\x5f\x56\xa5\xe3\x66\xf4\xf7\x7f\x5a\x18\x6d\x7f\x55",
        .decimals = 18,
    },
    {
        .name = "Basic Attention Token",
        .unit = "BAT",
        .contract_address =
            "\x0d\x87\x75\xf6\x48\x43\x06\x79\xa7\x09\xe9\x8d\x2b\x0c\xb6\x25\x0d\x28\x87\xef",
        .decimals = 18,
    },
    {
        .name = "BABB",
        .unit = "BAX",
        .contract_address =
            "\x9a\x02\x42\xb7\xa3\x3d\xac\xbe\x40\xed\xb9\x27\x83\x4f\x96\xeb\x39\xf8\xfb\xcb",
        .decimals = 18,
    },
    {
        .name = "Brickblock",
        .unit = "BBK",
        .contract_address =
            "\x4a\x60\x58\x66\x6c\xf1\x05\x7e\xac\x3c\xd3\xa5\xa6\x14\x62\x05\x47\x55\x9f\xc9",
        .decimals = 18,
    },
    {
        .name = "Blockmason Credit Protocol",
        .unit = "BCPT",
        .contract_address =
            "\x1c\x44\x81\x75\x0d\xaa\x5f\xf5\x21\xa2\xa7\x49\x0d\x99\x81\xed\x46\x46\x5d\xbd",
        .decimals = 18,
    },
    {
        .name = "BitCapitalVendor",
        .unit = "BCV",
        .contract_address =
            "\x10\x14\x61\x3e\x2b\x3c\xbc\x4d\x57\x50\x54\xd4\x98\x2e\x58\x0d\x9b\x99\xd7\xb1",
        .decimals = 8,
    },
    {
        .name = "Buggyra Coin Zero",
        .unit = "BCZERO",
        .contract_address =
            "\xd4\x52\x47\xc0\x73\x79\xd9\x49\x04\xe0\xa8\x7b\x44\x81\xf0\xa1\xdd\xfa\x0c\x64",
        .decimals = 18,
    },
    {
        .name = "BidiPass",
        .unit = "BDP",
        .contract_address =
            "\x59\x31\x14\xf0\x3a\x0a\x57\x5a\xec\xe9\xed\x67\x5e\x52\xed\x68\xd2\x17\x2b\x8c",
        .decimals = 18,
    },
    {
        .name = "DAO.Casino",
        .unit = "BET",
        .contract_address =
            "\x8a\xa3\x3a\x78\x99\xfc\xc8\xea\x5f\xbe\x6a\x60\x8a\x10\x9c\x38\x93\xa1\xb8\xb2",
        .decimals = 18,
    },
    {
        .name = "BitForex Token",
        .unit = "BF",
        .contract_address =
            "\x5b\x71\xbe\xe9\xd9\x61\xb1\xb8\x48\xf8\x48\x5e\xec\x8d\x87\x87\xf8\x02\x17\xf5",
        .decimals = 18,
    },
    {
        .name = "BnkToTheFuture",
        .unit = "BFT",
        .contract_address =
            "\x01\xff\x50\xf8\xb7\xf7\x4e\x4f\x00\x58\x0d\x95\x96\xcd\x3d\x0d\x6d\x6e\x32\x6f",
        .decimals = 18,
    },
    {
        .name = "BHEX Token",
        .unit = "BHT",
        .contract_address =
            "\xfc\x29\xb6\xe6\x26\xb6\x77\x76\x67\x5f\xff\x55\xd5\xbc\x04\x52\xd0\x42\xf4\x34",
        .decimals = 18,
    },
    {
        .name = "Bibox Token",
        .unit = "BIX",
        .contract_address =
            "\xb3\x10\x4b\x4b\x9d\xa8\x20\x25\xe8\xb9\xf8\xfb\x28\xb3\x55\x3c\xe2\xf6\x70\x69",
        .decimals = 18,
    },
    {
        .name = "Bloom",
        .unit = "BLT",
        .contract_address =
            "\x10\x7c\x45\x04\xcd\x79\xc5\xd2\x69\x6e\xa0\x03\x0a\x8d\xd4\xe9\x26\x01\xb8\x2e",
        .decimals = 18,
    },
    {
        .name = "Bluzelle",
        .unit = "BLZ",
        .contract_address =
            "\x57\x32\x04\x6a\x88\x37\x04\x40\x4f\x28\x4c\xe4\x1f\xfa\xdd\x5b\x00\x7f\xd6\x68",
        .decimals = 18,
    },
    {
        .name = "Blackmoon",
        .unit = "BMC",
        .contract_address =
            "\xdf\x6e\xf3\x43\x35\x07\x80\xbf\x8c\x34\x10\xbf\x06\x2e\x0c\x01\x5b\x1d\xd6\x71",
        .decimals = 8,
    },
    {
        .name = "BitMart Token",
        .unit = "BMX",
        .contract_address =
            "\x98\x6e\xe2\xb9\x44\xc4\x2d\x01\x7f\x52\xaf\x21\xc4\xc6\x9b\x84\xdb\xea\x35\xd8",
        .decimals = 18,
    },
    {
        .name = "Chimpion",
        .unit = "BNANA",
        .contract_address =
            "\x07\xef\x9e\x82\x72\x1a\xc1\x68\x09\xd2\x4d\xaf\xbe\x17\x92\xce\x01\x65\x4d\xb4",
        .decimals = 18,
    },
    {
        .name = "Bankera",
        .unit = "BNK",
        .contract_address =
            "\xc8\x0c\x5e\x40\x22\x01\x72\xb3\x6a\xde\xe2\xc9\x51\xf2\x6f\x2a\x57\x78\x10\xc5",
        .decimals = 8,
    },
    {
        .name = "Bancor",
        .unit = "BNT",
        .contract_address =
            "\x1f\x57\x3d\x6f\xb3\xf1\x3d\x68\x9f\xf8\x44\xb4\xce\x37\x79\x4d\x79\xa7\xff\x1c",
        .decimals = 18,
    },
    {
        .name = "BOSAGORA",
        .unit = "BOA",
        .contract_address =
            "\x74\x6d\xda\x2e\xa2\x43\x40\x0d\x5a\x63\xe0\x70\x0f\x19\x0a\xb7\x9f\x06\x48\x9e",
        .decimals = 7,
    },
    {
        .name = "BOLT",
        .unit = "BOLT",
        .contract_address =
            "\x9f\x23\x5d\x23\x35\x48\x57\xef\xe6\xc5\x41\xdb\x92\xa9\xef\x18\x77\x68\x9b\xcb",
        .decimals = 18,
    },
    {
        .name = "BORA",
        .unit = "BORA",
        .contract_address =
            "\x26\xfb\x86\x57\x9e\x37\x1c\x7a\xed\xc4\x61\xb2\xdd\xef\x0a\x86\x28\xc9\x3d\x3b",
        .decimals = 18,
    },
    {
        .name = "botXcoin",
        .unit = "BOTX",
        .contract_address =
            "\xef\x19\xf4\xe4\x88\x30\x09\x3c\xe5\xbc\x8b\x3f\xf7\xf9\x03\xa0\xae\x3e\x9f\xa1",
        .decimals = 18,
    },
    {
        .name = "BOX Token",
        .unit = "BOX",
        .contract_address =
            "\xe1\xa1\x78\xb6\x81\xbd\x05\x96\x4d\x3e\x3e\xd3\x3a\xe7\x31\x57\x7d\x9d\x96\xdd",
        .decimals = 18,
    },
    {
        .name = "ContentBox",
        .unit = "BOX",
        .contract_address =
            "\x63\xf5\x84\xfa\x56\xe6\x0e\x4d\x0f\xe8\x80\x2b\x27\xc7\xe6\xe3\xb3\x3e\x00\x7f",
        .decimals = 18,
    },
    {
        .name = "Blockport",
        .unit = "BPT",
        .contract_address =
            "\x32\x76\x82\x77\x9b\xab\x2b\xf4\xd1\x33\x7e\x89\x74\xab\x9d\xe8\x27\x5a\x7c\xa8",
        .decimals = 18,
    },
    {
        .name = "Bitsdaq",
        .unit = "BQQQ",
        .contract_address =
            "\x1b\x80\xee\xea\xdc\xc5\x90\xf3\x05\x94\x5b\xcc\x25\x8c\xfa\x77\x0b\xbe\x18\x90",
        .decimals = 18,
    },
    {
        .name = "BQT",
        .unit = "BQTX",
        .contract_address =
            "\x9d\x8b\xe9\x4d\x06\x12\x17\x0c\xe5\x33\xac\x4d\x7b\x43\xcc\x3c\xd9\x1e\x5a\x1a",
        .decimals = 18,
    },
    {
        .name = "Bread",
        .unit = "BRD",
        .contract_address =
            "\x55\x8e\xc3\x15\x2e\x2e\xb2\x17\x49\x05\xcd\x19\xae\xa4\xe3\x4a\x23\xde\x9a\xd6",
        .decimals = 18,
    },
    {
        .name = "Breezecoin",
        .unit = "BRZE",
        .contract_address =
            "\x77\xc0\x75\x55\xaf\x5f\xfd\xc9\x46\xfb\x47\xce\x15\xea\x68\x62\x0e\x4e\x71\x70",
        .decimals = 18,
    },
    {
        .name = "BitMax Token",
        .unit = "BTMX",
        .contract_address =
            "\x1c\x28\x9a\x12\xa8\x55\x2b\x31\x4d\x0d\x15\x3d\x69\x91\xfd\x27\xa5\x4a\xa6\x40",
        .decimals = 18,
    },
    {
        .name = "Bitrue Coin",
        .unit = "BTR",
        .contract_address =
            "\xd4\x33\x13\x8d\x12\xbe\xb9\x92\x9f\xf6\xfd\x58\x3d\xc8\x36\x63\xee\xa6\xaa\xa5",
        .decimals = 18,
    },
    {
        .name = "Blocktrade Token",
        .unit = "BTT",
        .contract_address =
            "\xfa\x45\x6c\xf5\x52\x50\xa8\x39\x08\x8b\x27\xee\x32\xa4\x24\xd7\xda\xcb\x54\xff",
        .decimals = 18,
    },
    {
        .name = "BTU Protocol",
        .unit = "BTU",
        .contract_address =
            "\xb6\x83\xd8\x3a\x53\x2e\x2c\xb7\xdf\xa5\x27\x5e\xed\x36\x98\x43\x63\x71\xcc\x9f",
        .decimals = 18,
    },
    {
        .name = "Binance USD",
        .unit = "BUSD",
        .contract_address =
            "\x4f\xab\xb1\x45\xd6\x46\x52\xa9\x48\xd7\x25\x33\x02\x3f\x6e\x7a\x62\x3c\x7c\x53",
        .decimals = 18,
    },
    {
        .name = "Blue Whale EXchange",
        .unit = "BWX",
        .contract_address =
            "\xce\x51\x14\xd7\xfa\x83\x61\xf0\xc0\x88\xee\x26\xfa\x3a\x54\x46\xc4\xa1\xf5\x0b",
        .decimals = 18,
    },
    {
        .name = "Bitbook Gambling",
        .unit = "BXK",
        .contract_address =
            "\xeb\x69\x85\xac\xd6\xd0\xcb\xff\x60\xb8\x80\x32\xb0\xb2\x9a\xc1\xd9\xd6\x6a\x1b",
        .decimals = 18,
    },
    {
        .name = "Bit-Z Token",
        .unit = "BZ",
        .contract_address =
            "\x43\x75\xe7\xad\x8a\x01\xb8\xec\x3e\xd0\x41\x39\x9f\x62\xd9\xcd\x12\x0e\x00\x63",
        .decimals = 18,
    },
    {
        .name = "Bezant",
        .unit = "BZNT",
        .contract_address =
            "\xe1\xae\xe9\x84\x95\x36\x5f\xc1\x79\x69\x9c\x1b\xb3\xe7\x61\xfa\x71\x6b\xee\x62",
        .decimals = 18,
    },
    {
        .name = "CRYPTO20",
        .unit = "C20",
        .contract_address =
            "\x26\xe7\x53\x07\xfc\x0c\x02\x14\x72\xfe\xb8\xf7\x27\x83\x95\x31\xf1\x12\xf3\x17",
        .decimals = 18,
    },
    {
        .name = "Change",
        .unit = "CAG",
        .contract_address =
            "\x7d\x4b\x8c\xce\x05\x91\xc9\x04\x4a\x22\xee\x54\x35\x33\xb7\x2e\x97\x6e\x36\xc3",
        .decimals = 18,
    },
    {
        .name = "Cajutel",
        .unit = "CAJ",
        .contract_address =
            "\x3c\x6a\x7a\xb4\x7b\x5f\x05\x8b\xe0\xe7\xc7\xfe\x1a\x4b\x79\x25\xb8\xac\xa4\x0e",
        .decimals = 18,
    },
    {
        .name = "CanYaCoin",
        .unit = "CAN",
        .contract_address =
            "\x1d\x46\x24\x14\xfe\x14\xcf\x48\x9c\x7a\x21\xca\xc7\x85\x09\xf4\xbf\x8c\xd7\xc0",
        .decimals = 6,
    },
    {
        .name = "Cashaa",
        .unit = "CAS",
        .contract_address =
            "\xe8\x78\x0b\x48\xbd\xb0\x5f\x92\x86\x97\xa5\xe8\x15\x5f\x67\x2e\xd9\x14\x62\xf7",
        .decimals = 18,
    },
    {
        .name = "CashBet Coin",
        .unit = "CBC",
        .contract_address =
            "\x26\xdb\x54\x39\xf6\x51\xca\xf4\x91\xa8\x7d\x48\x79\x9d\xa8\x1f\x19\x1b\xdb\x6b",
        .decimals = 8,
    },
    {
        .name = "CommerceBlock",
        .unit = "CBT",
        .contract_address =
            "\x07\x6c\x97\xe1\xc8\x69\x07\x2e\xe2\x2f\x8c\x91\x97\x8c\x99\xb4\xbc\xb0\x25\x91",
        .decimals = 18,
    },
    {
        .name = "Clipper Coin",
        .unit = "CCC",
        .contract_address =
            "\xbf\x59\xe6\xfe\x2b\xc4\xee\x8d\x30\x3e\x49\x33\x90\xb4\xaa\xca\xb1\x6f\xcc\x91",
        .decimals = 18,
    },
    {
        .name = "Blox",
        .unit = "CDT",
        .contract_address =
            "\x17\x7d\x39\xac\x67\x6e\xd1\xc6\x7a\x2b\x26\x8a\xd7\xf1\xe5\x88\x26\xe5\xb0\xaf",
        .decimals = 18,
    },
    {
        .name = "CEEK VR",
        .unit = "CEEK",
        .contract_address =
            "\xb0\x56\xc3\x8f\x6b\x7d\xc4\x06\x43\x67\x40\x3e\x26\x42\x4c\xd2\xc6\x06\x55\xe1",
        .decimals = 18,
    },
    {
        .name = "Celer Network",
        .unit = "CELR",
        .contract_address =
            "\x4f\x92\x54\xc8\x3e\xb5\x25\xf9\xfc\xf3\x46\x49\x0b\xbb\x3e\xd2\x8a\x81\xc6\x67",
        .decimals = 18,
    },
    {
        .name = "Centrality",
        .unit = "CENNZ",
        .contract_address =
            "\x11\x22\xb6\xa0\xe0\x0d\xce\x05\x63\x08\x2b\x6e\x29\x53\xf3\xa9\x43\x85\x5c\x1f",
        .decimals = 18,
    },
    {
        .name = "CoinEx Token",
        .unit = "CET",
        .contract_address =
            "\x08\x1f\x67\xaf\xa0\xcc\xf8\xc7\xb1\x75\x40\x76\x7b\xbe\x95\xdf\x2b\xa8\xd9\x7f",
        .decimals = 18,
    },
    {
        .name = "CoinPoker",
        .unit = "CHP",
        .contract_address =
            "\xf3\xdb\x75\x60\xe8\x20\x83\x46\x58\xb5\x90\xc9\x62\x34\xc3\x33\xcd\x3d\x5e\x5e",
        .decimals = 18,
    },
    {
        .name = "Chromia",
        .unit = "CHR",
        .contract_address =
            "\x91\x50\x44\x52\x67\x58\x53\x3d\xfb\x91\x8e\xce\xb6\xe4\x4b\xc2\x16\x32\x06\x0d",
        .decimals = 6,
    },
    {
        .name = "SwissBorg",
        .unit = "CHSB",
        .contract_address =
            "\xba\x9d\x41\x99\xfa\xb4\xf2\x6e\xfe\x35\x51\xd4\x90\xe3\x82\x14\x86\xf1\x35\xba",
        .decimals = 8,
    },
    {
        .name = "Chiliz",
        .unit = "CHZ",
        .contract_address =
            "\x35\x06\x42\x4f\x91\xfd\x33\x08\x44\x66\xf4\x02\xd5\xd9\x7f\x05\xf8\xe3\xb4\xaf",
        .decimals = 18,
    },
    {
        .name = "Cryptoindex.com 100",
        .unit = "CIX100",
        .contract_address =
            "\x63\x93\xe8\x22\x87\x47\x28\xf8\xaf\xa7\xe1\xc9\x94\x4e\x41\x7d\x37\xca\x58\x78",
        .decimals = 18,
    },
    {
        .name = "Color Platform",
        .unit = "CLR",
        .contract_address =
            "\x23\x96\xfb\xc0\xe2\xe3\xae\x4b\x72\x06\xeb\xdb\x57\x06\xe2\xa5\x92\x03\x49\xcb",
        .decimals = 18,
    },
    {
        .name = "Cindicator",
        .unit = "CND",
        .contract_address =
            "\xd4\xc4\x35\xf5\xb0\x9f\x85\x5c\x33\x17\xc8\x52\x4c\xb1\xf5\x86\xe4\x27\x95\xfa",
        .decimals = 18,
    },
    {
        .name = "Content Neutrality Network",
        .unit = "CNN",
        .contract_address =
            "\x87\x13\xd2\x66\x37\xcf\x49\xe1\xb6\xb4\xa7\xce\x57\x10\x6a\xab\xc9\x32\x53\x43",
        .decimals = 18,
    },
    {
        .name = "Cocos-BCX",
        .unit = "COCOS",
        .contract_address =
            "\x0c\x6f\x5f\x7d\x55\x5e\x75\x18\xf6\x84\x1a\x79\x43\x6b\xd2\xb1\xee\xf0\x33\x81",
        .decimals = 18,
    },
    {
        .name = "CONUN",
        .unit = "CON",
        .contract_address =
            "\x4d\xd6\x72\xe7\x7c\x79\x58\x44\xfe\x3a\x46\x4e\xf8\xef\x0f\xaa\xe6\x17\xc8\xfb",
        .decimals = 18,
    },
    {
        .name = "Constant",
        .unit = "CONST",
        .contract_address =
            "\x49\x83\xf7\x67\xb1\xbc\x44\x32\x8e\x43\x47\x29\xdd\xab\xea\x0a\x06\x4c\xa1\xac",
        .decimals = 2,
    },
    {
        .name = "Cosmo Coin",
        .unit = "COSM",
        .contract_address =
            "\xd1\xe1\x0c\x37\xa2\x7d\x95\xd9\x57\x20\x29\x1b\x1d\xc6\xf1\x2f\x74\xc7\x14\x43",
        .decimals = 18,
    },
    {
        .name = "Covesting",
        .unit = "COV",
        .contract_address =
            "\xe2\xfb\x65\x29\xef\x56\x6a\x08\x0e\x6d\x23\xde\x0b\xd3\x51\x31\x10\x87\xd5\x67",
        .decimals = 18,
    },
    {
        .name = "Cryptopay",
        .unit = "CPAY",
        .contract_address =
            "\x0e\xbb\x61\x42\x04\xe4\x7c\x09\xb6\xc3\xfe\xb9\xaa\xec\xad\x8e\xe0\x60\xe2\x3e",
        .decimals = 0,
    },
    {
        .name = "CPChain",
        .unit = "CPC",
        .contract_address =
            "\xfa\xe4\xee\x59\xcd\xd8\x6e\x3b\xe9\xe8\xb9\x0b\x53\xaa\x86\x63\x27\xd7\xc0\x90",
        .decimals = 18,
    },
    {
        .name = "Contents Protocol",
        .unit = "CPT",
        .contract_address =
            "\x9b\x62\x51\x3c\x8a\x27\x29\x0c\xf6\xa7\xa9\xe2\x93\x86\xe6\x00\x24\x5e\xa8\x19",
        .decimals = 18,
    },
    {
        .name = "Cryptaur",
        .unit = "CPT",
        .contract_address =
            "\x88\xd5\x0b\x46\x6b\xe5\x52\x22\x01\x9d\x71\xf9\xe8\xfa\xe1\x7f\x5f\x45\xfc\xa1",
        .decimals = 8,
    },
    {
        .name = "Carry",
        .unit = "CRE",
        .contract_address =
            "\x11\x5e\xc7\x9f\x1d\xe5\x67\xec\x68\xb7\xae\x7e\xda\x50\x1b\x40\x66\x26\x47\x8e",
        .decimals = 18,
    },
    {
        .name = "Credo",
        .unit = "CREDO",
        .contract_address =
            "\x4e\x06\x03\xe2\xa2\x7a\x30\x48\x0e\x5e\x3a\x4f\xe5\x48\xe2\x9e\xf1\x2f\x64\xbe",
        .decimals = 18,
    },
    {
        .name = "Crypto.com Coin",
        .unit = "CRO",
        .contract_address =
            "\xa0\xb7\x3e\x1f\xf0\xb8\x09\x14\xab\x6f\xe0\x44\x4e\x65\x84\x8c\x4c\x34\x45\x0b",
        .decimals = 8,
    },
    {
        .name = "Crypterium",
        .unit = "CRPT",
        .contract_address =
            "\x80\xa7\xe0\x48\xf3\x7a\x50\x50\x03\x51\xc2\x04\xcb\x40\x77\x66\xfa\x3b\xae\x7f",
        .decimals = 18,
    },
    {
        .name = "Credits",
        .unit = "CS",
        .contract_address =
            "\x46\xb9\xad\x94\x4d\x10\x59\x45\x0d\xa1\x16\x35\x11\x06\x9c\x71\x8f\x69\x9d\x31",
        .decimals = 6,
    },
    {
        .name = "BitDice",
        .unit = "CSNO",
        .contract_address =
            "\x29\xd7\x52\x77\xac\x7f\x03\x35\xb2\x16\x5d\x08\x95\xe8\x72\x5c\xbf\x65\x8d\x73",
        .decimals = 8,
    },
    {
        .name = "Caspian",
        .unit = "CSP",
        .contract_address =
            "\xa6\x44\x6d\x65\x5a\x0c\x34\xbc\x4f\x05\x04\x2e\xe8\x81\x70\xd0\x56\xcb\xaf\x45",
        .decimals = 18,
    },
    {
        .name = "Cortex",
        .unit = "CTXC",
        .contract_address =
            "\xea\x11\x75\x5a\xe4\x1d\x88\x9c\xee\xc3\x9a\x63\xe6\xff\x75\xa0\x2b\xc1\xc0\x0d",
        .decimals = 18,
    },
    {
        .name = "carVertical",
        .unit = "CV",
        .contract_address =
            "\xda\x6c\xb5\x8a\x0d\x0c\x01\x61\x0a\x29\xc5\xa6\x5c\x30\x3e\x13\xe8\x85\x88\x7c",
        .decimals = 18,
    },
    {
        .name = "Civic",
        .unit = "CVC",
        .contract_address =
            "\x41\xe5\x56\x00\x54\x82\x4e\xa6\xb0\x73\x2e\x65\x6e\x3a\xd6\x4e\x20\xe9\x4e\x45",
        .decimals = 8,
    },
    {
        .name = "Content Value Network",
        .unit = "CVNT",
        .contract_address =
            "\x64\x00\xb5\x52\x2f\x8d\x44\x8c\x08\x03\xe6\x24\x54\x36\xdd\x1c\x81\xdf\x09\xce",
        .decimals = 8,
    },
    {
        .name = "CyberVein",
        .unit = "CVT",
        .contract_address =
            "\xbe\x42\x8c\x38\x67\xf0\x5d\xea\x2a\x89\xfc\x76\xa1\x02\xb5\x44\xea\xc7\xf7\x72",
        .decimals = 18,
    },
    {
        .name = "CWV Chain",
        .unit = "CWV",
        .contract_address =
            "\xed\x49\x4c\x9e\x2f\x8e\x34\xe5\x3b\xdd\x0e\xa9\xb4\xd8\x03\x05\xcb\x15\xc5\xc2",
        .decimals = 18,
    },
    {
        .name = "CyberMusic",
        .unit = "CYMT",
        .contract_address =
            "\x78\xc2\x92\xd1\x44\x5e\x6b\x95\x58\xbf\x42\xe8\xbc\x36\x92\x71\xde\xd0\x62\xea",
        .decimals = 8,
    },
    {
        .name = "CanonChain",
        .unit = "CZR",
        .contract_address =
            "\x02\x23\xfc\x70\x57\x42\x14\xf6\x58\x13\xfe\x33\x6d\x87\x0a\xc4\x7e\x14\x7f\xae",
        .decimals = 18,
    },
    {
        .name = "Davinci Coin",
        .unit = "DAC",
        .contract_address =
            "\xaa\xd5\x4c\x9f\x27\xb8\x76\xd2\x53\x84\x55\xdd\xa6\x92\x07\x27\x9f\xf6\x73\xa5",
        .decimals = 18,
    },
    {
        .name = "DACSEE",
        .unit = "DACS",
        .contract_address =
            "\xa3\x11\x08\xe5\xba\xb5\x49\x45\x60\xdb\x34\xc9\x54\x92\x65\x8a\xf2\x39\x35\x7c",
        .decimals = 18,
    },
    {
        .name = "Edge",
        .unit = "DADI",
        .contract_address =
            "\xfb\x2f\x26\xf2\x66\xfb\x28\x05\xa3\x87\x23\x0f\x2a\xa0\xa3\x31\xb4\xd9\x6f\xba",
        .decimals = 18,
    },
    {
        .name = "Constellation",
        .unit = "DAG",
        .contract_address =
            "\xa8\x25\x8a\xbc\x8f\x28\x11\xdd\x48\xec\xcd\x20\x9d\xb6\x8f\x25\xe3\xe3\x46\x67",
        .decimals = 8,
    },
    {
        .name = "Digital Asset Guarantee Token",
        .unit = "DAGT",
        .contract_address =
            "\x56\xd1\xae\x30\xc9\x72\x88\xda\x4b\x58\xbc\x39\xf0\x26\x09\x17\x78\xe4\xe3\x16",
        .decimals = 18,
    },
    {
        .name = "Dai Stablecoin",
        .unit = "DAI",
        .contract_address =
            "\x6b\x17\x54\x74\xe8\x90\x94\xc4\x4d\xa9\x8b\x95\x4e\xed\xea\xc4\x95\x27\x1d\x0f",
        .decimals = 18,
    },
    {
        .name = "Streamr DATAcoin",
        .unit = "DATA",
        .contract_address =
            "\x0c\xf0\xee\x63\x78\x8a\x08\x49\xfe\x52\x97\xf3\x40\x7f\x70\x1e\x12\x2c\xc0\x23",
        .decimals = 18,
    },
    {
        .name = "Dentacoin",
        .unit = "DCN",
        .contract_address =
            "\x08\xd3\x2b\x0d\xa6\x3e\x2c\x3b\xcf\x80\x19\xc9\xc5\xd8\x49\xd7\xa9\xd7\x91\xe6",
        .decimals = 0,
    },
    {
        .name = "Scry.info",
        .unit = "DDD",
        .contract_address =
            "\x9f\x5f\x3c\xfd\x7a\x32\x70\x0c\x93\xf9\x71\x63\x74\x07\xff\x17\xb9\x1c\x73\x42",
        .decimals = 18,
    },
    {
        .name = "Darico Ecosystem Coin",
        .unit = "DEC",
        .contract_address =
            "\x89\xc6\xc8\x56\xa6\xdb\x3e\x46\x10\x71\x63\xd0\xcd\xa7\xa7\xff\x21\x1b\xd6\x55",
        .decimals = 18,
    },
    {
        .name = "Dent",
        .unit = "DENT",
        .contract_address =
            "\x35\x97\xbf\xd5\x33\xa9\x9c\x9a\xa0\x83\x58\x7b\x07\x44\x34\xe6\x1e\xb0\xa2\x58",
        .decimals = 8,
    },
    {
        .name = "DEX",
        .unit = "DEX",
        .contract_address =
            "\x49\x7b\xae\xf2\x94\xc1\x1a\x5f\x0f\x5b\xea\x3f\x2a\xdb\x30\x73\xdb\x44\x8b\x56",
        .decimals = 18,
    },
    {
        .name = "DigixDAO",
        .unit = "DGD",
        .contract_address =
            "\xe0\xb7\x92\x7c\x4a\xf2\x37\x65\xcb\x51\x31\x4a\x0e\x05\x21\xa9\x64\x5f\x0e\x2a",
        .decimals = 9,
    },
    {
        .name = "Digitex Futures",
        .unit = "DGTX",
        .contract_address =
            "\x1c\x83\x50\x14\x78\xf1\x32\x09\x77\x04\x70\x08\x49\x6d\xac\xbd\x60\xbb\x15\xef",
        .decimals = 18,
    },
    {
        .name = "Digix Gold Token",
        .unit = "DGX",
        .contract_address =
            "\x4f\x3a\xfe\xc4\xe5\xa3\xf2\xa6\xa1\xa4\x11\xde\xf7\xd7\xdf\xe5\x0e\xe0\x57\xbf",
        .decimals = 9,
    },
    {
        .name = "Etheroll",
        .unit = "DICE",
        .contract_address =
            "\x2e\x07\x1d\x29\x66\xaa\x7d\x8d\xec\xb1\x00\x58\x85\xba\x19\x77\xd6\x03\x8a\x65",
        .decimals = 16,
    },
    {
        .name = "Agrello",
        .unit = "DLT",
        .contract_address =
            "\x07\xe3\xc7\x06\x53\x54\x8b\x04\xf0\xa7\x59\x70\xc1\xf8\x1b\x4c\xbb\xfb\x60\x6f",
        .decimals = 18,
    },
    {
        .name = "DMarket",
        .unit = "DMT",
        .contract_address =
            "\x2c\xcb\xff\x3a\x04\x2c\x68\x71\x6e\xd2\xa2\xcb\x0c\x54\x4a\x9f\x1d\x19\x35\xe1",
        .decimals = 8,
    },
    {
        .name = "district0x",
        .unit = "DNT",
        .contract_address =
            "\x0a\xbd\xac\xe7\x0d\x37\x90\x23\x5a\xf4\x48\xc8\x85\x47\x60\x3b\x94\x56\x04\xea",
        .decimals = 18,
    },
    {
        .name = "Dock",
        .unit = "DOCK",
        .contract_address =
            "\xe5\xda\xda\x80\xaa\x64\x77\xe8\x5d\x09\x74\x7f\x28\x42\xf7\x99\x3d\x0d\xf7\x1c",
        .decimals = 18,
    },
    {
        .name = "Diamond Platform Token",
        .unit = "DPT",
        .contract_address =
            "\x10\xc7\x15\x15\x60\x24\x29\xc1\x9d\x53\x01\x1e\xa7\x04\x0b\x87\xa4\x89\x48\x38",
        .decimals = 18,
    },
    {
        .name = "DreamTeam Token",
        .unit = "DREAM",
        .contract_address =
            "\x82\xf4\xde\xd9\xce\xc9\xb5\x75\x0f\xbf\xf5\xc2\x18\x5a\xee\x35\xaf\xc1\x65\x87",
        .decimals = 6,
    },
    {
        .name = "Dragon Coins",
        .unit = "DRG",
        .contract_address =
            "\x81\x4f\x67\xfa\x28\x6f\x75\x72\xb0\x41\xd0\x41\xb1\xd9\x9b\x43\x2c\x91\x55\xee",
        .decimals = 8,
    },
    {
        .name = "Dragonchain",
        .unit = "DRGN",
        .contract_address =
            "\x41\x9c\x4d\xb4\xb9\xe2\x5d\x6d\xb2\xad\x96\x91\xcc\xb8\x32\xc8\xd9\xfd\xa0\x5e",
        .decimals = 18,
    },
    {
        .name = "Dropil",
        .unit = "DROP",
        .contract_address =
            "\x46\x72\xba\xd5\x27\x10\x74\x71\xcb\x50\x67\xa8\x87\xf4\x65\x6d\x58\x5a\x8a\x31",
        .decimals = 18,
    },
    {
        .name = "DATA",
        .unit = "DTA",
        .contract_address =
            "\x69\xb1\x48\x39\x5c\xe0\x01\x5c\x13\xe3\x6b\xff\xba\xd6\x3f\x49\xef\x87\x4e\x03",
        .decimals = 18,
    },
    {
        .name = "Dynamic Trading Rights",
        .unit = "DTR",
        .contract_address =
            "\xd2\x34\xbf\x24\x10\xa0\x00\x9d\xf9\xc3\xc6\x3b\x61\x0c\x09\x73\x8f\x18\xcc\xd7",
        .decimals = 8,
    },
    {
        .name = "Dusk Network",
        .unit = "DUSK",
        .contract_address =
            "\x94\x0a\x2d\xb1\xb7\x00\x8b\x6c\x77\x6d\x4f\xaa\xca\x72\x9d\x6d\x4a\x4a\xa5\x51",
        .decimals = 18,
    },
    {
        .name = "DxChain Token",
        .unit = "DX",
        .contract_address =
            "\x97\x3e\x52\x69\x11\x76\xd3\x64\x53\x86\x8d\x9d\x86\x57\x27\x88\xd2\x70\x41\xa9",
        .decimals = 18,
    },
    {
        .name = "EURBASE",
        .unit = "EBASE",
        .contract_address =
            "\x86\xfa\xdb\x80\xd8\xd2\xcf\xf3\xc3\x68\x08\x19\xe4\xda\x99\xc1\x02\x32\xba\x0f",
        .decimals = 18,
    },
    {
        .name = "Ecoreal Estate",
        .unit = "ECOREAL",
        .contract_address =
            "\xb0\x52\xf8\xa3\x3d\x8b\xb0\x68\x41\x4e\xad\xe0\x6a\xf6\x95\x51\x99\xf9\xf0\x10",
        .decimals = 18,
    },
    {
        .name = "Eden",
        .unit = "EDN",
        .contract_address =
            "\x05\x86\x0d\x45\x3c\x79\x74\xcb\xf4\x65\x08\xc0\x6c\xba\x14\xe2\x11\xc6\x29\xce",
        .decimals = 18,
    },
    {
        .name = "Eidoo",
        .unit = "EDO",
        .contract_address =
            "\xce\xd4\xe9\x31\x98\x73\x4d\xda\xff\x84\x92\xd5\x25\xbd\x25\x8d\x49\xeb\x38\x8e",
        .decimals = 18,
    },
    {
        .name = "Endor Protocol",
        .unit = "EDR",
        .contract_address =
            "\xc5\x28\xc2\x8f\xec\x0a\x90\xc0\x83\x32\x8b\xc4\x5f\x58\x7e\xe2\x15\x76\x0a\x0f",
        .decimals = 18,
    },
    {
        .name = "Egretia",
        .unit = "EGT",
        .contract_address =
            "\x8e\x1b\x44\x8e\xc7\xad\xfc\x7f\xa3\x5f\xc2\xe8\x85\x67\x8b\xd3\x23\x17\x6e\x34",
        .decimals = 18,
    },
    {
        .name = "EDUCare",
        .unit = "EKT",
        .contract_address =
            "\x4e\xcd\xb6\x38\x5f\x3d\xb3\x84\x7f\x9c\x4a\x9b\xf3\xf9\x91\x7b\xb2\x7a\x54\x52",
        .decimals = 8,
    },
    {
        .name = "ELA Coin",
        .unit = "ELAC",
        .contract_address =
            "\xec\x6c\x86\x1c\x2a\x2b\x1e\x5f\xf5\x33\x67\x31\xbc\x80\xc2\x9d\xbf\xf8\x82\x73",
        .decimals = 18,
    },
    {
        .name = "aelf",
        .unit = "ELF",
        .contract_address =
            "\xbf\x21\x79\x85\x9f\xc6\xd5\xbe\xe9\xbf\x91\x58\x63\x2d\xc5\x16\x78\xa4\x10\x0e",
        .decimals = 18,
    },
    {
        .name = "Eminer",
        .unit = "EM",
        .contract_address =
            "\x35\xb0\x87\x22\xaa\x26\xbe\x11\x9c\x16\x08\x02\x9c\xcb\xc9\x76\xac\x5c\x10\x82",
        .decimals = 8,
    },
    {
        .name = "Emirex Token",
        .unit = "EMRX",
        .contract_address =
            "\xbd\xbc\x2a\x5b\x32\xf3\xa5\x14\x1a\xcd\x18\xc3\x98\x83\x06\x6e\x4d\xab\x97\x74",
        .decimals = 8,
    },
    {
        .name = "Enigma",
        .unit = "ENG",
        .contract_address =
            "\xf0\xee\x6b\x27\xb7\x59\xc9\x89\x3c\xe4\xf0\x94\xb4\x9a\xd2\x8f\xd1\x5a\x23\xe4",
        .decimals = 8,
    },
    {
        .name = "Enjin Coin",
        .unit = "ENJ",
        .contract_address =
            "\xf6\x29\xcb\xd9\x4d\x37\x91\xc9\x25\x01\x52\xbd\x8d\xfb\xdf\x38\x0e\x2a\x3b\x9c",
        .decimals = 18,
    },
    {
        .name = "Dimension Chain",
        .unit = "EON",
        .contract_address =
            "\x4c\xb1\x0f\x4d\xf4\xbf\x4f\x64\xd4\x79\x7d\x00\xd4\x68\x18\x1e\xf7\x31\xbe\x9a",
        .decimals = 8,
    },
    {
        .name = "eosDAC",
        .unit = "EOSDAC",
        .contract_address =
            "\x7e\x9e\x43\x1a\x0b\x8c\x4d\x53\x2c\x74\x5b\x10\x43\xc7\xfa\x29\xa4\x8d\x4f\xba",
        .decimals = 18,
    },
    {
        .name = "ERC20",
        .unit = "ERC20",
        .contract_address =
            "\xc3\x76\x1e\xb9\x17\xcd\x79\x0b\x30\xda\xd9\x9f\x6c\xc5\xb4\xff\x93\xc4\xf9\xea",
        .decimals = 18,
    },
    {
        .name = "Elitium",
        .unit = "EUM",
        .contract_address =
            "\x6a\xb4\xa7\xd7\x5b\x0a\x42\xb6\xbc\x83\xe8\x52\xda\xb9\xe1\x21\xf9\xc6\x10\xaa",
        .decimals = 18,
    },
    {
        .name = "STASIS EURO",
        .unit = "EURS",
        .contract_address =
            "\xdb\x25\xf2\x11\xab\x05\xb1\xc9\x7d\x59\x55\x16\xf4\x57\x94\x52\x8a\x80\x7a\xd8",
        .decimals = 2,
    },
    {
        .name = "Envion",
        .unit = "EVN",
        .contract_address =
            "\xd7\x80\xae\x2b\xf0\x4c\xd9\x6e\x57\x7d\x3d\x01\x47\x62\xf8\x31\xd9\x71\x29\xd0",
        .decimals = 18,
    },
    {
        .name = "Everus",
        .unit = "EVR",
        .contract_address =
            "\x31\x37\x61\x97\x05\xb5\xfc\x22\xa3\x04\x89\x89\xf9\x83\x90\x5e\x45\x6b\x59\xab",
        .decimals = 8,
    },
    {
        .name = "Everex",
        .unit = "EVX",
        .contract_address =
            "\xf3\xdb\x5f\xa2\xc6\x6b\x7a\xf3\xeb\x0c\x0b\x78\x25\x10\x81\x6c\xbe\x48\x13\xb8",
        .decimals = 4,
    },
    {
        .name = "EveryCoin ",
        .unit = "EVY",
        .contract_address =
            "\xee\xd3\xae\x7b\x0f\x8b\x5b\x9b\xb8\xc0\x35\xa9\x94\x13\x82\xb1\x82\x26\x71\xcd",
        .decimals = 12,
    },
    {
        .name = "EXMR FDN",
        .unit = "EXMR",
        .contract_address =
            "\x33\x1f\xa6\xc9\x7c\x64\xe4\x74\x75\x16\x4b\x9f\xc8\x14\x3b\x53\x3c\x5e\xf5\x29",
        .decimals = 18,
    },
    {
        .name = "FABRK",
        .unit = "FAB",
        .contract_address =
            "\x12\x68\x3d\xc9\xee\xc9\x5a\x5f\x74\x2d\x40\x20\x6e\x73\x31\x9e\x6b\x9d\x8a\x91",
        .decimals = 18,
    },
    {
        .name = "Fatcoin",
        .unit = "FAT",
        .contract_address =
            "\x2e\xc9\x5b\x8e\xda\x54\x9b\x79\xa1\x24\x83\x35\xa3\x9d\x29\x9d\x00\xed\x31\x4c",
        .decimals = 18,
    },
    {
        .name = "Fetch.ai",
        .unit = "FET",
        .contract_address =
            "\x1d\x28\x7c\xc2\x5d\xad\x7c\xca\xf7\x6a\x26\xbc\x66\x0c\x5f\x7c\x8e\x2a\x05\xbd",
        .decimals = 18,
    },
    {
        .name = "Flowchain",
        .unit = "FLC",
        .contract_address =
            "\x5b\x53\xf9\x75\x5f\x82\x43\x9c\xba\x66\x00\x7e\xc7\x07\x3c\x59\xe0\xda\x4a\x7d",
        .decimals = 18,
    },
    {
        .name = "FLETA",
        .unit = "FLETA",
        .contract_address =
            "\x77\x88\xd7\x59\xf2\x1f\x53\x53\x30\x51\xa9\xae\x65\x7f\xa0\x5a\x1e\x06\x8f\xc6",
        .decimals = 18,
    },
    {
        .name = "Folgory Coin",
        .unit = "FLG",
        .contract_address =
            "\x5e\x04\x0a\xc7\x21\x40\xf0\x61\x7b\xc2\x4a\xb7\x13\x4c\x0c\x6e\xca\xe0\xe9\x65",
        .decimals = 18,
    },
    {
        .name = "FNB Protocol",
        .unit = "FNB",
        .contract_address =
            "\x47\xb2\x8f\x36\x5b\xf4\xcb\x38\xdb\x4b\x63\x56\x86\x4b\xde\x7b\xc4\xb3\x51\x29",
        .decimals = 18,
    },
    {
        .name = "FOAM",
        .unit = "FOAM",
        .contract_address =
            "\x49\x46\xfc\xea\x7c\x69\x26\x06\xe8\x90\x80\x02\xe5\x5a\x58\x2a\xf4\x4a\xc1\x21",
        .decimals = 18,
    },
    {
        .name = "The Force Protocol",
        .unit = "FOR",
        .contract_address =
            "\x1f\xcd\xce\x58\x95\x9f\x53\x66\x21\xd7\x6f\x5b\x7f\xfb\x95\x5b\xaa\x5a\x67\x2f",
        .decimals = 18,
    },
    {
        .name = "Fusion",
        .unit = "FSN",
        .contract_address =
            "\xd0\x35\x2a\x01\x9e\x9a\xb9\xd7\x57\x77\x6f\x53\x23\x77\xaa\xeb\xd3\x6f\xd5\x41",
        .decimals = 18,
    },
    {
        .name = "1irstcoin",
        .unit = "FST",
        .contract_address =
            "\x31\x0c\x93\xdf\xc1\xc5\xe3\x4c\xdf\x51\x67\x81\x03\xf6\x3c\x41\x76\x20\x89\xcd",
        .decimals = 6,
    },
    {
        .name = "Fantom",
        .unit = "FTM",
        .contract_address =
            "\x4e\x15\x36\x1f\xd6\xb4\xbb\x60\x9f\xa6\x3c\x81\xa2\xbe\x19\xd8\x73\x71\x78\x70",
        .decimals = 18,
    },
    {
        .name = "FTX Token",
        .unit = "FTT",
        .contract_address =
            "\x50\xd1\xc9\x77\x19\x02\x47\x60\x76\xec\xfc\x8b\x2a\x83\xad\x6b\x93\x55\xa4\xc9",
        .decimals = 18,
    },
    {
        .name = "Etherparty",
        .unit = "FUEL",
        .contract_address =
            "\xea\x38\xea\xa3\xc8\x6c\x8f\x9b\x75\x15\x33\xba\x2e\x56\x2d\xeb\x9a\xcd\xed\x40",
        .decimals = 18,
    },
    {
        .name = "FunFair",
        .unit = "FUN",
        .contract_address =
            "\x41\x9d\x0d\x8b\xdd\x9a\xf5\xe6\x06\xae\x22\x32\xed\x28\x5a\xff\x19\x0e\x71\x1b",
        .decimals = 8,
    },
    {
        .name = "Function X",
        .unit = "FX",
        .contract_address =
            "\x8c\x15\xef\x5b\x4b\x21\x95\x1d\x50\xe5\x3e\x4f\xbd\xa8\x29\x8f\xfa\xd2\x50\x57",
        .decimals = 18,
    },
    {
        .name = "Flexacoin",
        .unit = "FXC",
        .contract_address =
            "\x4a\x57\xe6\x87\xb9\x12\x64\x35\xa9\xb1\x9e\x4a\x80\x21\x13\xe2\x66\xad\xeb\xde",
        .decimals = 18,
    },
    {
        .name = "GAPS",
        .unit = "GAP",
        .contract_address =
            "\xcd\x85\x44\xde\xfe\xde\xc7\xc6\xb6\x0b\x5a\x42\x32\x32\x03\x65\xb1\xb2\x1f\xcc",
        .decimals = 18,
    },
    {
        .name = "Hashgard",
        .unit = "GARD",
        .contract_address =
            "\x5c\x64\x03\x1c\x62\x06\x18\x65\xe5\xfd\x0f\x53\xd3\xcd\xae\xf8\x0f\x72\xe9\x9d",
        .decimals = 18,
    },
    {
        .name = "Gold Bits Coin",
        .unit = "GBC",
        .contract_address =
            "\xc8\x05\x8d\x59\xe2\x08\x39\x9b\x76\xe6\x6d\xa1\xec\x66\x9d\xd6\xb1\xbe\xe2\xea",
        .decimals = 10,
    },
    {
        .name = "Global Digital Content",
        .unit = "GDC",
        .contract_address =
            "\x30\x1c\x75\x5b\xa0\xfc\xa0\x0b\x19\x23\x76\x8f\xff\xb3\xdf\x7f\x4e\x63\xaf\x31",
        .decimals = 18,
    },
    {
        .name = "DAOstack",
        .unit = "GEN",
        .contract_address =
            "\x54\x3f\xf2\x27\xf6\x4a\xa1\x7e\xa1\x32\xbf\x98\x86\xca\xb5\xdb\x55\xdc\xad\xdf",
        .decimals = 18,
    },
    {
        .name = "GET Protocol",
        .unit = "GET",
        .contract_address =
            "\x8a\x85\x42\x88\xa5\x97\x60\x36\xa7\x25\x87\x91\x64\xca\x3e\x91\xd3\x0c\x6a\x1b",
        .decimals = 18,
    },
    {
        .name = "GoWithMi",
        .unit = "GMAT",
        .contract_address =
            "\xa1\x10\xee\xeb\xc0\x75\x14\x07\xbd\xca\xea\x4c\xd2\x30\xf0\x4a\x2b\x82\xa3\x3a",
        .decimals = 18,
    },
    {
        .name = "GMB",
        .unit = "GMB",
        .contract_address =
            "\x1d\x46\x4a\xc5\xe0\x46\xe5\xfe\x28\x0c\x95\x88\xed\xf8\xeb\x68\x1b\x07\x00\x8f",
        .decimals = 18,
    },
    {
        .name = "Gnosis",
        .unit = "GNO",
        .contract_address =
            "\x68\x10\xe7\x76\x88\x0c\x02\x93\x3d\x47\xdb\x1b\x9f\xc0\x59\x08\xe5\x38\x6b\x96",
        .decimals = 18,
    },
    {
        .name = "Golem",
        .unit = "GNT",
        .contract_address =
            "\xa7\x44\x76\x44\x31\x19\xa9\x42\xde\x49\x85\x90\xfe\x1f\x24\x54\xd7\xd4\xac\x0d",
        .decimals = 18,
    },
    {
        .name = "Genaro Network",
        .unit = "GNX",
        .contract_address =
            "\x6e\xc8\xa2\x4c\xab\xdc\x33\x9a\x06\xa1\x72\xf8\x22\x3e\xa5\x57\x05\x5a\xda\xa5",
        .decimals = 9,
    },
    {
        .name = "GNY",
        .unit = "GNY",
        .contract_address =
            "\x24\x75\x51\xf2\xeb\x33\x62\xe2\x22\xc7\x42\xe9\xc7\x88\xb8\x95\x7d\x9b\xc8\x7e",
        .decimals = 18,
    },
    {
        .name = "ParkinGo",
        .unit = "GOT",
        .contract_address =
            "\x61\x3f\xa2\xa6\xe6\xda\xa7\x0c\x65\x90\x60\xe8\x6b\xa1\x44\x3d\x26\x79\xc9\xd7",
        .decimals = 18,
    },
    {
        .name = "Grid+",
        .unit = "GRID",
        .contract_address =
            "\x12\xb1\x9d\x3e\x2c\xcc\x14\xda\x04\xfa\xe3\x3e\x63\x65\x2c\xe4\x69\xb3\xf2\xfd",
        .decimals = 12,
    },
    {
        .name = "Global Social Chain",
        .unit = "GSC",
        .contract_address =
            "\x22\x8b\xa5\x14\x30\x9f\xfd\xf0\x3a\x81\xa2\x05\xa6\xd0\x40\xe4\x29\xd6\xe8\x0c",
        .decimals = 18,
    },
    {
        .name = "Gatechain Token",
        .unit = "GT",
        .contract_address =
            "\xe6\x67\x47\xa1\x01\xbf\xf2\xdb\xa3\x69\x71\x99\xdc\xce\x5b\x74\x3b\x45\x47\x59",
        .decimals = 18,
    },
    {
        .name = "Game.com",
        .unit = "GTC",
        .contract_address =
            "\xb7\x08\x35\xd7\x82\x2e\xbb\x94\x26\xb5\x65\x43\xe3\x91\x84\x6c\x10\x7b\xd3\x2c",
        .decimals = 18,
    },
    {
        .name = "Gifto",
        .unit = "GTO",
        .contract_address =
            "\xc5\xbb\xae\x50\x78\x1b\xe1\x66\x93\x06\xb9\xe0\x01\xef\xf5\x7a\x29\x57\xb0\x9d",
        .decimals = 5,
    },
    {
        .name = "Gemini Dollar",
        .unit = "GUSD",
        .contract_address =
            "\x05\x6f\xd4\x09\xe1\xd7\xa1\x24\xbd\x70\x17\x45\x9d\xfe\xa2\xf3\x87\xb6\xd5\xcd",
        .decimals = 2,
    },
    {
        .name = "Genesis Vision",
        .unit = "GVT",
        .contract_address =
            "\x10\x3c\x3a\x20\x9d\xa5\x9d\x3e\x7c\x4a\x89\x30\x7e\x66\x52\x1e\x08\x1c\xfd\xf0",
        .decimals = 18,
    },
    {
        .name = "Hubii Network",
        .unit = "HBT",
        .contract_address =
            "\xdd\x6c\x68\xbb\x32\x46\x2e\x01\x70\x50\x11\xa4\xe2\xad\x1a\x60\x74\x0f\x21\x7f",
        .decimals = 15,
    },
    {
        .name = "HedgeTrade",
        .unit = "HEDG",
        .contract_address =
            "\xf1\x29\x04\x73\xe2\x10\xb2\x10\x8a\x85\x23\x7f\xbc\xd7\xb6\xeb\x42\xcc\x65\x4f",
        .decimals = 18,
    },
    {
        .name = "Esportbits",
        .unit = "HLT",
        .contract_address =
            "\xa8\x09\xd3\x63\xa6\x6c\x57\x6a\x2a\x81\x4c\xdb\xfe\xfc\x10\x7c\x60\x0a\x55\xf0",
        .decimals = 18,
    },
    {
        .name = "Hi Mutual Society",
        .unit = "HMC",
        .contract_address =
            "\xaa\x0b\xb1\x0c\xec\x1f\xa3\x72\xeb\x3a\xbc\x17\xc9\x33\xfc\x6b\xa8\x63\xdd\x9e",
        .decimals = 18,
    },
    {
        .name = "Humaniq",
        .unit = "HMQ",
        .contract_address =
            "\xcb\xcc\x0f\x03\x6e\xd4\x78\x8f\x63\xfc\x0f\xee\x32\x87\x3d\x6a\x74\x87\xb9\x08",
        .decimals = 8,
    },
    {
        .name = "Holo",
        .unit = "HOT",
        .contract_address =
            "\x6c\x6e\xe5\xe3\x1d\x82\x8d\xe2\x41\x28\x2b\x96\x06\xc8\xe9\x8e\xa4\x85\x26\xe2",
        .decimals = 18,
    },
    {
        .name = "Hydro Protocol",
        .unit = "HOT",
        .contract_address =
            "\x9a\xf8\x39\x68\x7f\x6c\x94\x54\x2a\xc5\xec\xe2\xe3\x17\xda\xae\x35\x54\x93\xa1",
        .decimals = 18,
    },
    {
        .name = "Huobi Pool Token",
        .unit = "HPT",
        .contract_address =
            "\xa6\x6d\xaa\x57\x43\x20\x24\x02\x3d\xb6\x54\x77\xba\x87\xd4\xe7\xf5\xf9\x52\x13",
        .decimals = 18,
    },
    {
        .name = "Huobi Token",
        .unit = "HT",
        .contract_address =
            "\x6f\x25\x96\x37\xdc\xd7\x4c\x76\x77\x81\xe3\x7b\xc6\x13\x3c\xd6\xa6\x8a\xa1\x61",
        .decimals = 18,
    },
    {
        .name = "Humanscape",
        .unit = "HUM",
        .contract_address =
            "\x17\x4a\xfe\x7a\x03\x2b\x5a\x33\xa3\x27\x0a\x9f\x6c\x30\x74\x6e\x25\x70\x85\x32",
        .decimals = 18,
    },
    {
        .name = "Hxro",
        .unit = "HXRO",
        .contract_address =
            "\x4b\xd7\x05\x56\xae\x3f\x8a\x6e\xc6\xc4\x08\x0a\x0c\x32\x7b\x24\x32\x54\x38\xf3",
        .decimals = 18,
    },
    {
        .name = "Hydro",
        .unit = "HYDRO",
        .contract_address =
            "\xeb\xbd\xf3\x02\xc9\x40\xc6\xbf\xd4\x9c\x6b\x16\x5f\x45\x7f\xdb\x32\x46\x49\xbc",
        .decimals = 18,
    },
    {
        .name = "Hyperion",
        .unit = "HYN",
        .contract_address =
            "\xe9\x9a\x89\x4a\x69\xd7\xc2\xe3\xc9\x2e\x61\xb6\x4c\x50\x5a\x6a\x57\xd2\xbc\x07",
        .decimals = 18,
    },
    {
        .name = "IDEX",
        .unit = "IDEX",
        .contract_address =
            "\xb7\x05\x26\x82\x13\xd5\x93\xb8\xfd\x88\xd3\xfd\xef\xf9\x3a\xff\x5c\xbd\xcf\xae",
        .decimals = 18,
    },
    {
        .name = "indaHash",
        .unit = "IDH",
        .contract_address =
            "\x51\x36\xc9\x8a\x80\x81\x1c\x3f\x46\xbd\xda\x8b\x5c\x45\x55\xcf\xd9\xf8\x12\xf0",
        .decimals = 6,
    },
    {
        .name = "Invictus Hyperion Fund",
        .unit = "IHF",
        .contract_address =
            "\xaf\x12\x50\xfa\x68\xd7\xde\xcd\x34\xfd\x75\xde\x87\x42\xbc\x03\xb2\x9b\xd5\x8e",
        .decimals = 18,
    },
    {
        .name = "IHT Real Estate Protocol",
        .unit = "IHT",
        .contract_address =
            "\xed\xa8\xb0\x16\xef\xa8\xb1\x16\x12\x08\xcf\x04\x1c\xd8\x69\x72\xee\xe0\xf3\x1e",
        .decimals = 18,
    },
    {
        .name = "INLOCK",
        .unit = "ILK",
        .contract_address =
            "\xf7\x84\x68\x2c\x82\x52\x6e\x24\x5f\x50\x97\x51\x90\xef\x0f\xff\x4e\x4f\xc0\x77",
        .decimals = 8,
    },
    {
        .name = "Insight Chain",
        .unit = "INB",
        .contract_address =
            "\x17\xaa\x18\xa4\xb6\x4a\x55\xab\xed\x7f\xa5\x43\xf2\xba\x4e\x91\xf2\xdc\xe4\x82",
        .decimals = 18,
    },
    {
        .name = "IntelliShare",
        .unit = "INE",
        .contract_address =
            "\x86\xe6\xa4\xf5\x12\xb1\x29\x0c\x04\x39\x70\xb0\x4e\x0b\x57\x0d\x4f\xc9\x82\x91",
        .decimals = 18,
    },
    {
        .name = "INO COIN",
        .unit = "INO",
        .contract_address =
            "\xc9\x85\x9f\xcc\xc8\x76\xe6\xb4\xb3\xc7\x49\xc5\xd2\x9e\xa0\x4f\x48\xac\xb7\x4f",
        .decimals = 0,
    },
    {
        .name = "Insolar",
        .unit = "INS",
        .contract_address =
            "\x5b\x2e\x4a\x70\x0d\xfb\xc5\x60\x06\x1e\x95\x7e\xde\xc8\xf6\xee\xeb\x74\xa3\x20",
        .decimals = 10,
    },
    {
        .name = "Insights Network",
        .unit = "INSTAR",
        .contract_address =
            "\xc7\x2f\xe8\xe3\xdd\x5b\xef\x0f\x9f\x31\xf2\x59\x39\x9f\x30\x12\x72\xef\x2a\x2d",
        .decimals = 18,
    },
    {
        .name = "IoTeX",
        .unit = "IOTX",
        .contract_address =
            "\x6f\xb3\xe0\xa2\x17\x40\x7e\xff\xf7\xca\x06\x2d\x46\xc2\x6e\x5d\x60\xa1\x4d\x69",
        .decimals = 18,
    },
    {
        .name = "IQeon",
        .unit = "IQN",
        .contract_address =
            "\x0d\xb8\xd8\xb7\x6b\xc3\x61\xba\xcb\xb7\x2e\x2c\x49\x1e\x06\x08\x5a\x97\xab\x31",
        .decimals = 18,
    },
    {
        .name = "IoT Chain",
        .unit = "ITC",
        .contract_address =
            "\x5e\x6b\x6d\x9a\xba\xd9\x09\x3f\xdc\x86\x1e\xa1\x60\x0e\xba\x1b\x35\x5c\xd9\x40",
        .decimals = 18,
    },
    {
        .name = "Ivy",
        .unit = "IVY",
        .contract_address =
            "\xa4\xea\x68\x7a\x2a\x7f\x29\xcf\x2d\xc6\x6b\x39\xc6\x8e\x44\x11\xc0\xd0\x0c\x49",
        .decimals = 18,
    },
    {
        .name = "Jibrel Network",
        .unit = "JNT",
        .contract_address =
            "\xa5\xfd\x1a\x79\x1c\x4d\xfc\xaa\xcc\x96\x3d\x4f\x73\xc6\xae\x58\x24\x14\x9e\xa7",
        .decimals = 18,
    },
    {
        .name = "Jewel",
        .unit = "JWL",
        .contract_address =
            "\x82\x75\xeb\xf5\x21\xdc\x21\x7a\xa7\x9c\x88\x13\x20\x17\xa5\xbc\xef\x00\x1d\xd9",
        .decimals = 18,
    },
    {
        .name = "BitKan",
        .unit = "KAN",
        .contract_address =
            "\x14\x10\x43\x4b\x03\x46\xf5\xbe\x67\x8d\x0f\xb5\x54\xe5\xc7\xab\x62\x0f\x8f\x4a",
        .decimals = 18,
    },
    {
        .name = "Karatgold Coin",
        .unit = "KBC",
        .contract_address =
            "\xf3\x58\x66\x84\x10\x7c\xe0\x85\x9c\x44\xaa\x2b\x2e\x0f\xb8\xcd\x87\x31\xa1\x5a",
        .decimals = 7,
    },
    {
        .name = "Kcash",
        .unit = "KCASH",
        .contract_address =
            "\x32\xd7\x48\x96\xf0\x52\x04\xd1\xb6\xae\x7b\x0a\x3c\xeb\xd7\xfc\x0c\xd8\xf9\xc7",
        .decimals = 18,
    },
    {
        .name = "KuCoin Shares",
        .unit = "KCS",
        .contract_address =
            "\x03\x9b\x56\x49\xa5\x99\x67\xe3\xe9\x36\xd7\x47\x1f\x9c\x37\x00\x10\x0e\xe1\xab",
        .decimals = 6,
    },
    {
        .name = "Selfkey",
        .unit = "KEY",
        .contract_address =
            "\x4c\xc1\x93\x56\xf2\xd3\x73\x38\xb9\x80\x2a\xa8\xe8\xfc\x58\xb0\x37\x32\x96\xe7",
        .decimals = 18,
    },
    {
        .name = "KickToken",
        .unit = "KICK",
        .contract_address =
            "\xc1\x2d\x1c\x73\xee\x7d\xc3\x61\x5b\xa4\xe3\x7e\x4a\xbf\xdb\xdd\xfa\x38\x90\x7e",
        .decimals = 8,
    },
    {
        .name = "Kyber Network",
        .unit = "KNC",
        .contract_address =
            "\xdd\x97\x4d\x5c\x2e\x29\x28\xde\xa5\xf7\x1b\x98\x25\xb8\xb6\x46\x68\x6b\xd2\x00",
        .decimals = 18,
    },
    {
        .name = "Krios",
        .unit = "KRI",
        .contract_address =
            "\xde\x12\x89\xe6\x8a\xd9\xe6\x5c\xcf\x50\xd8\x00\xc0\xce\xc2\xd5\x14\xb8\x0a\x40",
        .decimals = 18,
    },
    {
        .name = "Kryll",
        .unit = "KRL",
        .contract_address =
            "\x46\x4e\xbe\x77\xc2\x93\xe4\x73\xb4\x8c\xfe\x96\xdd\xcf\x88\xfc\xf7\xbf\xda\xc0",
        .decimals = 18,
    },
    {
        .name = "Kuai Token",
        .unit = "KT",
        .contract_address =
            "\x26\xdd\xf6\xca\xba\xdc\xbf\x4f\x01\x38\x41\xbd\x8d\x91\x48\x30\xbe\xb0\xd9\x84",
        .decimals = 8,
    },
    {
        .name = "LATOKEN",
        .unit = "LA",
        .contract_address =
            "\xe5\x03\x65\xf5\xd6\x79\xcb\x98\xa1\xdd\x62\xd6\xf6\xe5\x8e\x59\x32\x1b\xcd\xdf",
        .decimals = 18,
    },
    {
        .name = "Lambda",
        .unit = "LAMB",
        .contract_address =
            "\x89\x71\xf9\xfd\x71\x96\xe5\xce\xe2\xc1\x03\x2b\x50\xf6\x56\x85\x5a\xf7\xdd\x26",
        .decimals = 18,
    },
    {
        .name = "Cred",
        .unit = "LBA",
        .contract_address =
            "\xfe\x5f\x14\x1b\xf9\x4f\xe8\x4b\xc2\x8d\xed\x0a\xb9\x66\xc1\x6b\x17\x49\x06\x57",
        .decimals = 18,
    },
    {
        .name = "Aave",
        .unit = "LEND",
        .contract_address =
            "\x80\xfb\x78\x4b\x7e\xd6\x67\x30\xe8\xb1\xdb\xd9\x82\x0a\xfd\x29\x93\x1a\xab\x03",
        .decimals = 18,
    },
    {
        .name = "UNUS SED LEO",
        .unit = "LEO",
        .contract_address =
            "\x2a\xf5\xd2\xad\x76\x74\x11\x91\xd1\x5d\xfe\x7b\xf6\xac\x92\xd4\xbd\x91\x2c\xa3",
        .decimals = 18,
    },
    {
        .name = "LinkEye",
        .unit = "LET",
        .contract_address =
            "\xfa\x31\x18\xb3\x45\x22\x58\x0c\x35\xae\x27\xf6\xcf\x52\xda\x1d\xbb\x75\x62\x88",
        .decimals = 6,
    },
    {
        .name = "Leverj",
        .unit = "LEV",
        .contract_address =
            "\x0f\x4c\xa9\x26\x60\xef\xad\x97\xa9\xa7\x0c\xb0\xfe\x96\x9c\x75\x54\x39\x77\x2c",
        .decimals = 9,
    },
    {
        .name = "Levolution",
        .unit = "LEVL",
        .contract_address =
            "\x09\x97\x0a\xec\x76\x6b\x6f\x32\x23\xac\xa9\x11\x15\x55\xe9\x9d\xc5\x0f\xf1\x3a",
        .decimals = 18,
    },
    {
        .name = "Winding Tree",
        .unit = "LIF",
        .contract_address =
            "\xeb\x99\x51\x02\x16\x98\xb4\x2e\x43\x99\xf9\xcb\xb6\x26\x7a\xa3\x5f\x82\xd5\x9d",
        .decimals = 18,
    },
    {
        .name = "LIFE",
        .unit = "LIFE",
        .contract_address =
            "\xff\x18\xdb\xc4\x87\xb4\xc2\xe3\x22\x2d\x11\x59\x52\xba\xbf\xda\x8b\xa5\x2f\x5f",
        .decimals = 18,
    },
    {
        .name = "LikeCoin",
        .unit = "LIKE",
        .contract_address =
            "\x02\xf6\x1f\xd2\x66\xda\x6e\x8b\x10\x2d\x41\x21\xf5\xce\x7b\x99\x26\x40\xcf\x98",
        .decimals = 18,
    },
    {
        .name = "LINA",
        .unit = "LINA",
        .contract_address =
            "\xc0\x5d\x14\x44\x2a\x51\x0d\xe4\xd3\xd7\x1a\x3d\x31\x65\x85\xaa\x0c\xe3\x2b\x50",
        .decimals = 18,
    },
    {
        .name = "Chainlink",
        .unit = "LINK",
        .contract_address =
            "\x51\x49\x10\x77\x1a\xf9\xca\x65\x6a\xf8\x40\xdf\xf8\x3e\x82\x64\xec\xf9\x86\xca",
        .decimals = 18,
    },
    {
        .name = "LINKA",
        .unit = "LINKA",
        .contract_address =
            "\x57\x8b\x49\xc4\x59\x61\xf9\x8d\x8d\xf9\x28\x54\xb5\x3f\x16\x41\xaf\x0a\x50\x36",
        .decimals = 18,
    },
    {
        .name = "Linkey",
        .unit = "LKY",
        .contract_address =
            "\x49\xbd\x2d\xa7\x5b\x1f\x7a\xf1\xe4\xdf\xd6\xb1\x12\x5f\xec\xde\x59\xdb\xec\x58",
        .decimals = 18,
    },
    {
        .name = "Lendingblock",
        .unit = "LND",
        .contract_address =
            "\x09\x47\xb0\xe6\xd8\x21\x37\x88\x05\xc9\x59\x82\x91\x38\x5c\xe7\xc7\x91\xa6\xb2",
        .decimals = 18,
    },
    {
        .name = "LockTrip",
        .unit = "LOC",
        .contract_address =
            "\x5e\x33\x46\x44\x40\x10\x13\x53\x22\x26\x8a\x46\x30\xd2\xed\x5f\x8d\x09\x44\x6c",
        .decimals = 18,
    },
    {
        .name = "Locus Chain",
        .unit = "LOCUS",
        .contract_address =
            "\xc6\x45\x00\xdd\x7b\x0f\x17\x94\x80\x7e\x67\x80\x2f\x8a\xbb\xf5\xf8\xff\xb0\x54",
        .decimals = 18,
    },
    {
        .name = "Loom Network",
        .unit = "LOOM",
        .contract_address =
            "\xa4\xe8\xc3\xec\x45\x61\x07\xea\x67\xd3\x07\x5b\xf9\xe3\xdf\x3a\x75\x82\x3d\xb0",
        .decimals = 18,
    },
    {
        .name = "Loopring",
        .unit = "LRC",
        .contract_address =
            "\xbb\xbb\xca\x6a\x90\x1c\x92\x6f\x24\x0b\x89\xea\xcb\x64\x1d\x8a\xec\x7a\xea\xfd",
        .decimals = 18,
    },
    {
        .name = "LuckySevenToken",
        .unit = "LST",
        .contract_address =
            "\x6b\x9f\x1f\x09\x2e\x0b\x10\x01\x5a\x43\x91\xa8\x0c\xd3\xe6\xb6\xce\xfd\x17\x28",
        .decimals = 18,
    },
    {
        .name = "LTO Network",
        .unit = "LTO",
        .contract_address =
            "\x3d\xb6\xba\x6a\xb6\xf9\x5e\xfe\xd1\xa6\xe7\x94\xca\xd4\x92\xfa\xaa\xbf\x29\x4d",
        .decimals = 8,
    },
    {
        .name = "Lunyr",
        .unit = "LUN",
        .contract_address =
            "\xfa\x05\xa7\x3f\xfe\x78\xef\x8f\x1a\x73\x94\x73\xe4\x62\xc5\x4b\xae\x65\x67\xd9",
        .decimals = 18,
    },
    {
        .name = "Litex",
        .unit = "LXT",
        .contract_address =
            "\xbc\x46\xd9\x96\x1a\x39\x32\xf7\xd6\xb6\x4a\xbf\xde\xc8\x0c\x18\x16\xc4\xb8\x35",
        .decimals = 18,
    },
    {
        .name = "Lympo",
        .unit = "LYM",
        .contract_address =
            "\xc6\x90\xf7\xc7\xfc\xff\xa6\xa8\x2b\x79\xfa\xb7\x50\x8c\x46\x6f\xef\xdf\xc8\xc5",
        .decimals = 18,
    },
    {
        .name = "Decentraland",
        .unit = "MANA",
        .contract_address =
            "\x0f\x5d\x2f\xb2\x9f\xb7\xd3\xcf\xee\x44\x4a\x20\x02\x98\xf4\x68\x90\x8c\xc9\x42",
        .decimals = 18,
    },
    {
        .name = "Matic Network",
        .unit = "MATIC",
        .contract_address =
            "\x7d\x1a\xfa\x7b\x71\x8f\xb8\x93\xdb\x30\xa3\xab\xc0\xcf\xc6\x08\xaa\xcf\xeb\xb0",
        .decimals = 18,
    },
    {
        .name = "MineBee",
        .unit = "MB",
        .contract_address =
            "\x8d\x81\x29\x96\x32\x91\x74\x0d\xdd\xd9\x17\xab\x01\xaf\x18\xc7\xae\xd4\xba\x58",
        .decimals = 18,
    },
    {
        .name = "MovieBloc",
        .unit = "MBL",
        .contract_address =
            "\xb8\x79\xda\x8b\x24\xc9\xb8\x68\x5d\xe8\x52\x6c\xf4\x92\xe9\x54\xf1\x65\xd7\x4b",
        .decimals = 18,
    },
    {
        .name = "MCO",
        .unit = "MCO",
        .contract_address =
            "\xb6\x3b\x60\x6a\xc8\x10\xa5\x2c\xca\x15\xe4\x4b\xb6\x30\xfd\x42\xd8\xd1\xd8\x3d",
        .decimals = 8,
    },
    {
        .name = "Moeda Loyalty Points",
        .unit = "MDA",
        .contract_address =
            "\x51\xdb\x5a\xd3\x5c\x67\x1a\x87\x20\x7d\x88\xfc\x11\xd5\x93\xac\x0c\x84\x15\xbd",
        .decimals = 18,
    },
    {
        .name = "MediShares",
        .unit = "MDS",
        .contract_address =
            "\x66\x18\x60\x08\xc1\x05\x06\x27\xf9\x79\xd4\x64\xea\xbb\x25\x88\x60\x56\x3d\xbe",
        .decimals = 18,
    },
    {
        .name = "Measurable Data Token",
        .unit = "MDT",
        .contract_address =
            "\x81\x4e\x09\x08\xb1\x2a\x99\xfe\xcf\x5b\xc1\x01\xbb\x5d\x0b\x8b\x5c\xdf\x7d\x26",
        .decimals = 18,
    },
    {
        .name = "MediBloc [ERC20]",
        .unit = "MEDX",
        .contract_address =
            "\xfd\x1e\x80\x50\x8f\x24\x3e\x64\xce\x23\x4e\xa8\x8a\x5f\xd2\x82\x7c\x71\xd4\xb7",
        .decimals = 8,
    },
    {
        .name = "Metronome",
        .unit = "MET",
        .contract_address =
            "\xa3\xd5\x8c\x4e\x56\xfe\xdc\xae\x3a\x7c\x43\xa7\x25\xae\xe9\xa7\x1f\x0e\xce\x4e",
        .decimals = 18,
    },
    {
        .name = "MEXC Token",
        .unit = "MEXC",
        .contract_address =
            "\x7d\xe2\xd1\x23\x04\x29\x94\x73\x71\x05\x80\x2d\x2a\xbd\x0a\x10\xa7\xbd\xe2\x76",
        .decimals = 18,
    },
    {
        .name = "Mainframe",
        .unit = "MFT",
        .contract_address =
            "\xdf\x2c\x72\x38\x19\x8a\xd8\xb3\x89\x66\x65\x74\xf2\xd8\xbc\x41\x1a\x4b\x74\x28",
        .decimals = 18,
    },
    {
        .name = "MargiX",
        .unit = "MGX",
        .contract_address =
            "\x14\x12\xf6\xaa\x5a\xdc\x77\xc6\x20\x71\x5b\xb2\xa0\x20\xaa\x69\x0b\x85\xf6\x8a",
        .decimals = 18,
    },
    {
        .name = "MINDOL",
        .unit = "MIN",
        .contract_address =
            "\x5d\x64\xd8\x50\xc8\x36\x80\x08\xaf\xb3\x92\x24\xe9\x2a\xd0\xdc\xef\xf3\xcf\x38",
        .decimals = 18,
    },
    {
        .name = "Mithril",
        .unit = "MITH",
        .contract_address =
            "\x38\x93\xb9\x42\x2c\xd5\xd7\x0a\x81\xed\xef\xfe\x3d\x5a\x1c\x6a\x97\x83\x10\xbb",
        .decimals = 18,
    },
    {
        .name = "Morpheus Labs",
        .unit = "MITX",
        .contract_address =
            "\x4a\x52\x7d\x8f\xc1\x3c\x52\x03\xab\x24\xba\x09\x44\xf4\xcb\x14\x65\x8d\x1d\xb6",
        .decimals = 18,
    },
    {
        .name = "Maker",
        .unit = "MKR",
        .contract_address =
            "\x9f\x8f\x72\xaa\x93\x04\xc8\xb5\x93\xd5\x55\xf1\x2e\xf6\x58\x9c\xc3\xa5\x79\xa2",
        .decimals = 18,
    },
    {
        .name = "Melon",
        .unit = "MLN",
        .contract_address =
            "\xec\x67\x00\x5c\x4e\x49\x8e\xc7\xf5\x5e\x09\x2b\xd1\xd3\x5c\xbc\x47\xc9\x18\x92",
        .decimals = 18,
    },
    {
        .name = "Moss Coin",
        .unit = "MOC",
        .contract_address =
            "\x86\x5e\xc5\x8b\x06\xbf\x63\x05\xb8\x86\x79\x3a\xa2\x0a\x2d\xa3\x1d\x03\x4e\x68",
        .decimals = 18,
    },
    {
        .name = "Molecular Future",
        .unit = "MOF",
        .contract_address =
            "\x65\x34\x30\x56\x0b\xe8\x43\xc4\xa3\xd1\x43\xd0\x11\x0e\x89\x6c\x2a\xb8\xac\x0d",
        .decimals = 16,
    },
    {
        .name = "MenaPay",
        .unit = "MPAY",
        .contract_address =
            "\x38\x10\xa4\xdd\xf4\x1e\x58\x6f\xa0\xdb\xa1\x46\x3a\x79\x51\xb7\x48\xce\xcf\xca",
        .decimals = 18,
    },
    {
        .name = "Morpheus.Network",
        .unit = "MRPH",
        .contract_address =
            "\x7b\x0c\x06\x04\x34\x68\x46\x99\x67\xdb\xa2\x2d\x1a\xf3\x3d\x77\xd4\x40\x56\xc8",
        .decimals = 4,
    },
    {
        .name = "doc.com Token",
        .unit = "MTC",
        .contract_address =
            "\x90\x5e\x33\x7c\x6c\x86\x45\x26\x3d\x35\x21\x20\x5a\xa3\x7b\xf4\xd0\x34\xe7\x45",
        .decimals = 18,
    },
    {
        .name = "Monetha",
        .unit = "MTH",
        .contract_address =
            "\xaf\x4d\xce\x16\xda\x28\x77\xf8\xc9\xe0\x05\x44\xc9\x3b\x62\xac\x40\x63\x1f\x16",
        .decimals = 5,
    },
    {
        .name = "Metal",
        .unit = "MTL",
        .contract_address =
            "\xf4\x33\x08\x93\x66\x89\x9d\x83\xa9\xf2\x6a\x77\x3d\x59\xec\x7e\xcf\x30\x35\x5e",
        .decimals = 8,
    },
    {
        .name = "MVL",
        .unit = "MVL",
        .contract_address =
            "\xa8\x49\xea\xae\x99\x4f\xb8\x6a\xfa\x73\x38\x2e\x9b\xd8\x8c\x2b\x6b\x18\xdc\x71",
        .decimals = 18,
    },
    {
        .name = "Restart Energy MWAT",
        .unit = "MWAT",
        .contract_address =
            "\x64\x25\xc6\xbe\x90\x2d\x69\x2a\xe2\xdb\x75\x2b\x3c\x26\x8a\xfa\xdb\x09\x9d\x3b",
        .decimals = 18,
    },
    {
        .name = "MX Token",
        .unit = "MX",
        .contract_address =
            "\x11\xee\xf0\x4c\x88\x4e\x24\xd9\xb7\xb4\x76\x0e\x74\x76\xd0\x6d\xdf\x79\x7f\x36",
        .decimals = 18,
    },
    {
        .name = "Machine Xchange Coin",
        .unit = "MXC",
        .contract_address =
            "\x5c\xa3\x81\xbb\xfb\x58\xf0\x09\x2d\xf1\x49\xbd\x3d\x24\x3b\x08\xb9\xa8\x38\x6e",
        .decimals = 18,
    },
    {
        .name = "Maximine Coin",
        .unit = "MXM",
        .contract_address =
            "\x8e\x76\x6f\x57\xf7\xd1\x6c\xa5\x0b\x4a\x0b\x90\xb8\x8f\x64\x68\xa0\x9b\x04\x39",
        .decimals = 18,
    },
    {
        .name = "NeoWorld Cash",
        .unit = "NASH",
        .contract_address =
            "\x4b\x94\xc8\x56\x77\x63\x65\x41\x01\xf6\x90\xcf\x4d\x54\x95\x72\x06\x38\x3b\x75",
        .decimals = 18,
    },
    {
        .name = "Niobium Coin",
        .unit = "NBC",
        .contract_address =
            "\x9f\x19\x56\x17\xfa\x8f\xba\xd9\x54\x0c\x5d\x11\x3a\x99\xa0\xa0\x17\x2a\xae\xdc",
        .decimals = 18,
    },
    {
        .name = "Nucleus Vision",
        .unit = "NCASH",
        .contract_address =
            "\x80\x98\x26\xcc\xea\xb6\x8c\x38\x77\x26\xaf\x96\x27\x13\xb6\x4c\xb5\xcb\x3c\xca",
        .decimals = 18,
    },
    {
        .name = "PolySwarm",
        .unit = "NCT",
        .contract_address =
            "\x9e\x46\xa3\x8f\x5d\xaa\xbe\x86\x83\xe1\x07\x93\xb0\x67\x49\xee\xf7\xd7\x33\xd1",
        .decimals = 18,
    },
    {
        .name = "Nectar",
        .unit = "NEC",
        .contract_address =
            "\xcc\x80\xc0\x51\x05\x7b\x77\x4c\xd7\x50\x67\xdc\x48\xf8\x98\x7c\x4e\xb9\x7a\x5e",
        .decimals = 18,
    },
    {
        .name = "NEXT",
        .unit = "NET",
        .contract_address =
            "\xf2\x92\x26\x91\x45\x95\x05\x2a\x04\xf5\xaf\xbe\x64\x10\xd0\xc3\xed\x70\x75\x48",
        .decimals = 18,
    },
    {
        .name = "Neumark",
        .unit = "NEU",
        .contract_address =
            "\xa8\x23\xe6\x72\x20\x06\xaf\xe9\x9e\x91\xc3\x0f\xf5\x29\x50\x52\xfe\x6b\x8e\x32",
        .decimals = 18,
    },
    {
        .name = "Nexo",
        .unit = "NEXO",
        .contract_address =
            "\xb6\x21\x32\xe3\x5a\x6c\x13\xee\x1e\xe0\xf8\x4d\xc5\xd4\x0b\xad\x8d\x81\x52\x06",
        .decimals = 18,
    },
    {
        .name = "NAGA",
        .unit = "NGC",
        .contract_address =
            "\x72\xdd\x4b\x6b\xd8\x52\xa3\xaa\x17\x2b\xe4\xd6\xc5\xa6\xdb\xec\x58\x8c\xf1\x31",
        .decimals = 18,
    },
    {
        .name = "Numeraire",
        .unit = "NMR",
        .contract_address =
            "\x17\x76\xe1\xf2\x6f\x98\xb1\xa5\xdf\x9c\xd3\x47\x95\x3a\x26\xdd\x3c\xb4\x66\x71",
        .decimals = 18,
    },
    {
        .name = "Noah Coin",
        .unit = "NOAH",
        .contract_address =
            "\x58\xa4\x88\x41\x82\xd9\xe8\x35\x59\x7f\x40\x5e\x5f\x25\x82\x90\xe4\x6a\xe7\xc2",
        .decimals = 18,
    },
    {
        .name = "NaPoleonX",
        .unit = "NPX",
        .contract_address =
            "\x28\xb5\xe1\x2c\xce\x51\xf1\x55\x94\xb0\xb9\x1d\x5b\x5a\xda\xa7\x0f\x68\x4a\x02",
        .decimals = 2,
    },
    {
        .name = "Pundi X",
        .unit = "NPXS",
        .contract_address =
            "\xa1\x5c\x7e\xbe\x1f\x07\xca\xf6\xbf\xf0\x97\xd8\xa5\x89\xfb\x8a\xc4\x9a\xe5\xb3",
        .decimals = 18,
    },
    {
        .name = "OAX",
        .unit = "OAX",
        .contract_address =
            "\x70\x1c\x24\x4b\x98\x8a\x51\x3c\x94\x59\x73\xde\xfa\x05\xde\x93\x3b\x23\xfe\x1d",
        .decimals = 18,
    },
    {
        .name = "Ocean Protocol",
        .unit = "OCEAN",
        .contract_address =
            "\x98\x5d\xd3\xd4\x2d\xe1\xe2\x56\xd0\x9e\x1c\x10\xf1\x12\xbc\xcb\x80\x15\xad\x41",
        .decimals = 18,
    },
    {
        .name = "Odyssey",
        .unit = "OCN",
        .contract_address =
            "\x40\x92\x67\x8e\x4e\x78\x23\x0f\x46\xa1\x53\x4c\x0f\xbc\x8f\xa3\x97\x80\x89\x2b",
        .decimals = 18,
    },
    {
        .name = "ODEM",
        .unit = "ODE",
        .contract_address =
            "\xbf\x52\xf2\xab\x39\xe2\x6e\x09\x51\xd2\xa0\x2b\x49\xb7\x70\x2a\xbe\x30\x40\x6a",
        .decimals = 18,
    },
    {
        .name = "Origo",
        .unit = "OGO",
        .contract_address =
            "\xff\x0e\x5e\x01\x4c\xf9\x7e\x06\x15\xcb\x50\xf6\xf3\x9d\xa6\x38\x8e\x2f\xae\x6e",
        .decimals = 18,
    },
    {
        .name = "OKB",
        .unit = "OKB",
        .contract_address =
            "\x75\x23\x1f\x58\xb4\x32\x40\xc9\x71\x8d\xd5\x8b\x49\x67\xc5\x11\x43\x42\xa8\x6c",
        .decimals = 18,
    },
    {
        .name = "OneLedger",
        .unit = "OLT",
        .contract_address =
            "\x64\xa6\x04\x93\xd8\x88\x72\x8c\xf4\x26\x16\xe0\x34\xa0\xdf\xea\xe3\x8e\xfc\xf0",
        .decimals = 18,
    },
    {
        .name = "OmiseGO",
        .unit = "OMG",
        .contract_address =
            "\xd2\x61\x14\xcd\x6e\xe2\x89\xac\xcf\x82\x35\x0c\x8d\x84\x87\xfe\xdb\x8a\x0c\x07",
        .decimals = 18,
    },
    {
        .name = "BigONE Token",
        .unit = "ONE",
        .contract_address =
            "\x03\x96\x34\x0f\x16\xbb\xec\x97\x32\x80\xab\x05\x3e\xfc\x3f\x20\x8f\xa3\x77\x95",
        .decimals = 18,
    },
    {
        .name = "Opacity",
        .unit = "OPQ",
        .contract_address =
            "\x77\x59\x9d\x2c\x6d\xb1\x70\x22\x42\x43\xe2\x55\xe6\x66\x92\x80\xf1\x1f\x14\x73",
        .decimals = 18,
    },
    {
        .name = "Orbs",
        .unit = "ORBS",
        .contract_address =
            "\xff\x56\xcc\x6b\x1e\x6d\xed\x34\x7a\xa0\xb7\x67\x6c\x85\xab\x0b\x3d\x08\xb0\xfa",
        .decimals = 18,
    },
    {
        .name = "Origin Sport",
        .unit = "ORS",
        .contract_address =
            "\xeb\x9a\x4b\x18\x58\x16\xc3\x54\xdb\x92\xdb\x09\xcc\x3b\x50\xbe\x60\xb9\x01\xb6",
        .decimals = 18,
    },
    {
        .name = "OST",
        .unit = "OST",
        .contract_address =
            "\x2c\x4e\x8f\x2d\x74\x61\x13\xd0\x69\x6c\xe8\x9b\x35\xf0\xd8\xbf\x88\xe0\xae\xca",
        .decimals = 18,
    },
    {
        .name = "OVCODE",
        .unit = "OVC",
        .contract_address =
            "\x49\xd0\x9c\xda\x1d\xeb\x8a\x16\x80\xf1\x27\x0c\x5e\xd1\x52\x18\xfc\x4b\x18\xf0",
        .decimals = 18,
    },
    {
        .name = "Paxos Standard",
        .unit = "PAX",
        .contract_address =
            "\x8e\x87\x0d\x67\xf6\x60\xd9\x5d\x5b\xe5\x30\x38\x0d\x0e\xc0\xbd\x38\x82\x89\xe1",
        .decimals = 18,
    },
    {
        .name = "PAX Gold",
        .unit = "PAXG",
        .contract_address =
            "\x45\x80\x48\x80\xde\x22\x91\x3d\xaf\xe0\x9f\x49\x80\x84\x8e\xce\x6e\xcb\xaf\x78",
        .decimals = 18,
    },
    {
        .name = "TenX",
        .unit = "PAY",
        .contract_address =
            "\xb9\x70\x48\x62\x8d\xb6\xb6\x61\xd4\xc2\xaa\x83\x3e\x95\xdb\xe1\xa9\x05\xb2\x80",
        .decimals = 18,
    },
    {
        .name = "Paypex",
        .unit = "PAYX",
        .contract_address =
            "\x62\xa5\x6a\x4a\x2e\xf4\xd3\x55\xd3\x4d\x10\xfb\xf8\x37\xe7\x47\x50\x4d\x38\xd4",
        .decimals = 2,
    },
    {
        .name = "Peculium",
        .unit = "PCL",
        .contract_address =
            "\x0f\x02\xe2\x77\x45\xe3\xb6\xe9\xe1\x31\x0d\x19\x46\x9e\x2b\x5d\x7b\x5e\xc9\x9a",
        .decimals = 8,
    },
    {
        .name = "Perlin",
        .unit = "PERL",
        .contract_address =
            "\xb5\xa7\x3f\x5f\xc8\xbb\xdb\xce\x59\xbf\xd0\x1c\xa8\xd3\x50\x62\xe0\xda\xd8\x01",
        .decimals = 9,
    },
    {
        .name = "PCHAIN",
        .unit = "PI",
        .contract_address =
            "\xb9\xbb\x08\xab\x7e\x9f\xa0\xa1\x35\x6b\xd4\xa3\x9e\xc0\xca\x26\x7e\x03\xb0\xb3",
        .decimals = 18,
    },
    {
        .name = "PlayChip",
        .unit = "PLA",
        .contract_address =
            "\x01\x98\xf4\x6f\x52\x0f\x33\xcd\x43\x29\xbd\x4b\xe3\x80\xa2\x5a\x90\x53\x6c\xd5",
        .decimals = 18,
    },
    {
        .name = "PLANET",
        .unit = "PLA",
        .contract_address =
            "\x30\x7d\x45\xaf\xbb\x7e\x84\xf8\x2e\xf3\xd2\x51\xa6\xbb\x0f\x00\xed\xf6\x32\xe4",
        .decimals = 18,
    },
    {
        .name = "Polybius",
        .unit = "PLBT",
        .contract_address =
            "\x0a\xff\xa0\x6e\x7f\xbe\x5b\xc9\xa7\x64\xc9\x79\xaa\x66\xe8\x25\x6a\x63\x1f\x02",
        .decimals = 6,
    },
    {
        .name = "Pillar",
        .unit = "PLR",
        .contract_address =
            "\xe3\x81\x85\x04\xc1\xb3\x2b\xf1\x55\x7b\x16\xc2\x38\xb2\xe0\x1f\xd3\x14\x9c\x17",
        .decimals = 18,
    },
    {
        .name = "Pluton",
        .unit = "PLU",
        .contract_address =
            "\xd8\x91\x2c\x10\x68\x1d\x8b\x21\xfd\x37\x42\x24\x4f\x44\x65\x8d\xba\x12\x26\x4e",
        .decimals = 18,
    },
    {
        .name = "PlayCoin [ERC20]",
        .unit = "PLY",
        .contract_address =
            "\x59\xbe\x93\x7f\x05\xcf\x2c\x40\x6b\x61\xc4\x2c\x6c\x82\xa0\x93\xfa\x54\xed\xfe",
        .decimals = 9,
    },
    {
        .name = "PumaPay",
        .unit = "PMA",
        .contract_address =
            "\x84\x6c\x66\xcf\x71\xc4\x3f\x80\x40\x3b\x51\xfe\x39\x06\xb3\x59\x9d\x63\x33\x6f",
        .decimals = 18,
    },
    {
        .name = "Kleros",
        .unit = "PNK",
        .contract_address =
            "\x93\xed\x3f\xbe\x21\x20\x7e\xc2\xe8\xf2\xd3\xc3\xde\x6e\x05\x8c\xb7\x3b\xc0\x4d",
        .decimals = 18,
    },
    {
        .name = "Penta",
        .unit = "PNT",
        .contract_address =
            "\x53\x06\x6c\xdd\xbc\x00\x99\xeb\x6c\x96\x78\x5d\x9b\x3d\xf2\xaa\xee\xde\x5d\xa3",
        .decimals = 18,
    },
    {
        .name = "Po.et",
        .unit = "POE",
        .contract_address =
            "\x0e\x09\x89\xb1\xf9\xb8\xa3\x89\x83\xc2\xba\x80\x53\x26\x9c\xa6\x2e\xc9\xb1\x95",
        .decimals = 8,
    },
    {
        .name = "Polymath",
        .unit = "POLY",
        .contract_address =
            "\x99\x92\xec\x3c\xf6\xa5\x5b\x00\x97\x8c\xdd\xf2\xb2\x7b\xc6\x88\x2d\x88\xd1\xec",
        .decimals = 18,
    },
    {
        .name = "Power Ledger",
        .unit = "POWR",
        .contract_address =
            "\x59\x58\x32\xf8\xfc\x6b\xf5\x9c\x85\xc5\x27\xfe\xc3\x74\x0a\x1b\x7a\x36\x12\x69",
        .decimals = 6,
    },
    {
        .name = "PayPie",
        .unit = "PPP",
        .contract_address =
            "\xc4\x22\x09\xac\xcc\x14\x02\x9c\x10\x12\xfb\x56\x80\xd9\x5f\xbd\x60\x36\xe2\xa0",
        .decimals = 18,
    },
    {
        .name = "Populous",
        .unit = "PPT",
        .contract_address =
            "\xd4\xfa\x14\x60\xf5\x37\xbb\x90\x85\xd2\x2c\x7b\xcc\xb5\xdd\x45\x0e\xf2\x8e\x3a",
        .decimals = 8,
    },
    {
        .name = "ProChain",
        .unit = "PRA",
        .contract_address =
            "\x90\x41\xfe\x5b\x3f\xde\xa0\xf5\xe4\xaf\xdc\x17\xe7\x51\x80\x73\x8d\x87\x7a\x01",
        .decimals = 18,
    },
    {
        .name = "Presearch",
        .unit = "PRE",
        .contract_address =
            "\x88\xa3\xe4\xf3\x5d\x64\xaa\xd4\x1a\x6d\x40\x30\xac\x9a\xfe\x43\x56\xcb\x84\xfa",
        .decimals = 18,
    },
    {
        .name = "Propy",
        .unit = "PRO",
        .contract_address =
            "\x22\x6b\xb5\x99\xa1\x2c\x82\x64\x76\xe3\xa7\x71\x45\x46\x97\xea\x52\xe9\xe2\x20",
        .decimals = 8,
    },
    {
        .name = "Prometeus",
        .unit = "PROM",
        .contract_address =
            "\xfc\x82\xbb\x4b\xa8\x60\x45\xaf\x6f\x32\x73\x23\xa4\x6e\x80\x41\x2b\x91\xb2\x7d",
        .decimals = 18,
    },
    {
        .name = "PressOne",
        .unit = "PRS",
        .contract_address =
            "\xe0\xd9\x55\x30\x82\x0a\xaf\xc5\x1b\x1d\x98\x02\x3a\xa1\xff\x00\x0b\x78\xd8\xb2",
        .decimals = 18,
    },
    {
        .name = "Pivot Token",
        .unit = "PVT",
        .contract_address =
            "\x78\x69\xc4\xa1\xa3\xf6\xf8\x68\x4f\xbc\xc4\x22\xa2\x1a\xd7\xab\xe3\x16\x78\x34",
        .decimals = 18,
    },
    {
        .name = "QASH",
        .unit = "QASH",
        .contract_address =
            "\x61\x8e\x75\xac\x90\xb1\x2c\x60\x49\xba\x3b\x27\xf5\xd5\xf8\x65\x1b\x00\x37\xf6",
        .decimals = 6,
    },
    {
        .name = "Qubitica",
        .unit = "QBIT",
        .contract_address =
            "\x16\x02\xaf\x2c\x78\x2c\xc0\x3f\x92\x41\x99\x2e\x24\x32\x90\xfc\xcf\x73\xbb\x13",
        .decimals = 18,
    },
    {
        .name = "QuickX Protocol",
        .unit = "QCX",
        .contract_address =
            "\xf9\xe5\xaf\x7b\x42\xd3\x1d\x51\x67\x7c\x75\xbb\xbd\x37\xc1\x98\x6e\xc7\x9a\xee",
        .decimals = 8,
    },
    {
        .name = "QuarkChain",
        .unit = "QKC",
        .contract_address =
            "\xea\x26\xc4\xac\x16\xd4\xa5\xa1\x06\x82\x0b\xc8\xae\xe8\x5f\xd0\xb7\xb2\xb6\x64",
        .decimals = 18,
    },
    {
        .name = "Quant",
        .unit = "QNT",
        .contract_address =
            "\x4a\x22\x0e\x60\x96\xb2\x5e\xad\xb8\x83\x58\xcb\x44\x06\x8a\x32\x48\x25\x46\x75",
        .decimals = 18,
    },
    {
        .name = "Quanta Utility Token",
        .unit = "QNTU",
        .contract_address =
            "\x42\x34\xf6\x3b\x1d\x20\x2f\x6c\x01\x6c\xa3\xb6\xa0\xd4\x1d\x7d\x85\xf1\x77\x16",
        .decimals = 18,
    },
    {
        .name = "Poseidon Network",
        .unit = "QQQ",
        .contract_address =
            "\x28\x22\xf6\xd1\xb2\xf4\x1f\x93\xf3\x3d\x93\x7b\xc7\xd8\x4a\x8d\xfa\x4f\x4c\x21",
        .decimals = 18,
    },
    {
        .name = "Quantstamp",
        .unit = "QSP",
        .contract_address =
            "\x99\xea\x4d\xb9\xee\x77\xac\xd4\x0b\x11\x9b\xd1\xdc\x4e\x33\xe1\xc0\x70\xb8\x0d",
        .decimals = 18,
    },
    {
        .name = "QunQun",
        .unit = "QUN",
        .contract_address =
            "\x26\x4d\xc2\xde\xdc\xdc\xbb\x89\x75\x61\xa5\x7c\xba\x50\x85\xca\x41\x6f\xb7\xb4",
        .decimals = 18,
    },
    {
        .name = "Revain",
        .unit = "R",
        .contract_address =
            "\x48\xf7\x75\xef\xbe\x4f\x5e\xce\x6e\x0d\xf2\xf7\xb5\x93\x2d\xf5\x68\x23\xb9\x90",
        .decimals = 0,
    },
    {
        .name = "Rublix",
        .unit = "RBLX",
        .contract_address =
            "\xfc\x2c\x4d\x8f\x95\x00\x2c\x14\xed\x0a\x7a\xa6\x51\x02\xca\xc9\xe5\x95\x3b\x5e",
        .decimals = 18,
    },
    {
        .name = "Ripio Credit Network",
        .unit = "RCN",
        .contract_address =
            "\xf9\x70\xb8\xe3\x6e\x23\xf7\xfc\x3f\xd7\x52\xee\xa8\x6f\x8b\xe8\xd8\x33\x75\xa6",
        .decimals = 18,
    },
    {
        .name = "Raiden Network Token",
        .unit = "RDN",
        .contract_address =
            "\x25\x5a\xa6\xdf\x07\x54\x0c\xb5\xd3\xd2\x97\xf0\xd0\xd4\xd8\x4c\xb5\x2b\xc8\xe6",
        .decimals = 18,
    },
    {
        .name = "Remme",
        .unit = "REM",
        .contract_address =
            "\x83\x98\x4d\x61\x42\x93\x4b\xb5\x35\x79\x3a\x82\xad\xb0\xa4\x6e\xf0\xf6\x6b\x6d",
        .decimals = 4,
    },
    {
        .name = "Ren",
        .unit = "REN",
        .contract_address =
            "\x40\x8e\x41\x87\x6c\xcc\xdc\x0f\x92\x21\x06\x00\xef\x50\x37\x26\x56\x05\x2a\x38",
        .decimals = 18,
    },
    {
        .name = "Augur",
        .unit = "REP",
        .contract_address =
            "\x19\x85\x36\x5e\x9f\x78\x35\x9a\x9b\x6a\xd7\x60\xe3\x24\x12\xf4\xa4\x45\xe8\x62",
        .decimals = 18,
    },
    {
        .name = "Request",
        .unit = "REQ",
        .contract_address =
            "\x8f\x82\x21\xaf\xbb\x33\x99\x8d\x85\x84\xa2\xb0\x57\x49\xba\x73\xc3\x7a\x93\x8a",
        .decimals = 18,
    },
    {
        .name = "RealTract",
        .unit = "RET",
        .contract_address =
            "\xd7\x39\x40\x87\xe1\xdb\xbe\x47\x7f\xe4\xf1\xcf\x37\x3b\x9a\xc9\x45\x95\x65\xff",
        .decimals = 8,
    },
    {
        .name = "Refereum",
        .unit = "RFR",
        .contract_address =
            "\xd0\x92\x9d\x41\x19\x54\xc4\x74\x38\xdc\x1d\x87\x1d\xd6\x08\x1f\x5c\x5e\x14\x9c",
        .decimals = 4,
    },
    {
        .name = "RChain",
        .unit = "RHOC",
        .contract_address =
            "\x16\x82\x96\xbb\x09\xe2\x4a\x88\x80\x5c\xb9\xc3\x33\x56\x53\x6b\x98\x0d\x3f\xc5",
        .decimals = 8,
    },
    {
        .name = "iExec RLC",
        .unit = "RLC",
        .contract_address =
            "\x60\x7f\x4c\x5b\xb6\x72\x23\x0e\x86\x72\x08\x55\x32\xf7\xe9\x01\x54\x4a\x73\x75",
        .decimals = 9,
    },
    {
        .name = "OneRoot Network",
        .unit = "RNT",
        .contract_address =
            "\xff\x60\x3f\x43\x94\x6a\x3a\x28\xdf\x5e\x6a\x73\x17\x25\x55\xd8\xc8\xb0\x23\x86",
        .decimals = 18,
    },
    {
        .name = "ROOBEE",
        .unit = "ROOBEE",
        .contract_address =
            "\xa3\x1b\x17\x67\xe0\x9f\x84\x2e\xcf\xd4\xbc\x47\x1f\xe4\x4f\x83\x0e\x38\x91\xaa",
        .decimals = 18,
    },
    {
        .name = "Robotina",
        .unit = "ROX",
        .contract_address =
            "\x57\x4f\x84\x10\x8a\x98\xc5\x75\x79\x4f\x75\x48\x3d\x80\x1d\x1d\x5d\xc8\x61\xa5",
        .decimals = 18,
    },
    {
        .name = "Rocket Pool",
        .unit = "RPL",
        .contract_address =
            "\xb4\xef\xd8\x5c\x19\x99\x9d\x84\x25\x13\x04\xbd\xa9\x9e\x90\xb9\x23\x00\xbd\x93",
        .decimals = 18,
    },
    {
        .name = "Reserve Rights",
        .unit = "RSR",
        .contract_address =
            "\x87\x62\xdb\x10\x6b\x2c\x2a\x0b\xcc\xb3\xa8\x0d\x1e\xd4\x12\x73\x55\x26\x16\xe8",
        .decimals = 18,
    },
    {
        .name = "Rotharium",
        .unit = "RTH",
        .contract_address =
            "\x3f\xd8\xf3\x9a\x96\x2e\xfd\xa0\x49\x56\x98\x1c\x31\xab\x89\xfa\xb5\xfb\x8b\xc8",
        .decimals = 18,
    },
    {
        .name = "Ruff",
        .unit = "RUFF",
        .contract_address =
            "\xf2\x78\xc1\xca\x96\x90\x95\xff\xdd\xde\xd0\x20\x29\x0c\xf8\xb5\xc4\x24\xac\xe2",
        .decimals = 18,
    },
    {
        .name = "S4FE",
        .unit = "S4F",
        .contract_address =
            "\xae\xc7\xd1\x06\x9e\x3a\x91\x4a\x3e\xb5\x0f\x0b\xfb\x17\x96\x75\x1f\x2c\xe4\x8a",
        .decimals = 18,
    },
    {
        .name = "Single Collateral DAI ",
        .unit = "SAI",
        .contract_address =
            "\x89\xd2\x4a\x6b\x4c\xcb\x1b\x6f\xaa\x26\x25\xfe\x56\x2b\xdd\x9a\x23\x26\x03\x59",
        .decimals = 18,
    },
    {
        .name = "SALT",
        .unit = "SALT",
        .contract_address =
            "\x41\x56\xd3\x34\x2d\x5c\x38\x5a\x87\xd2\x64\xf9\x06\x53\x73\x35\x92\x00\x05\x81",
        .decimals = 8,
    },
    {
        .name = "Santiment Network Token",
        .unit = "SAN",
        .contract_address =
            "\x7c\x5a\x0c\xe9\x26\x7e\xd1\x9b\x22\xf8\xca\xe6\x53\xf1\x98\xe3\xe8\xda\xf0\x98",
        .decimals = 18,
    },
    {
        .name = "Sealchain",
        .unit = "SEAL",
        .contract_address =
            "\x07\xbf\x5f\x95\x85\x1e\xf2\xb2\x99\x6f\x19\x25\x69\xe4\x06\xa6\xfe\xa2\xa9\x5a",
        .decimals = 18,
    },
    {
        .name = "Seele",
        .unit = "SEELE",
        .contract_address =
            "\xb1\xee\xf1\x47\x02\x8e\x9f\x48\x0d\xbc\x5c\xca\xa3\x27\x7d\x41\x7d\x1b\x85\xf0",
        .decimals = 18,
    },
    {
        .name = "Sentinel",
        .unit = "SENT",
        .contract_address =
            "\xa4\x4e\x51\x37\x29\x3e\x85\x5b\x1b\x7b\xc7\xe2\xc6\xf8\xcd\x79\x6f\xfc\xb0\x37",
        .decimals = 8,
    },
    {
        .name = "Skrumble Network",
        .unit = "SKM",
        .contract_address =
            "\xd9\x9b\x8a\x7f\xa4\x8e\x25\xcc\xe8\x3b\x81\x81\x22\x20\xa3\xe0\x3b\xf6\x4e\x5f",
        .decimals = 18,
    },
    {
        .name = "Silverway",
        .unit = "SLV",
        .contract_address =
            "\x4c\x1c\x49\x57\xd2\x2d\x8f\x37\x3a\xed\x54\xd0\x85\x3b\x09\x06\x66\xf6\xf9\xde",
        .decimals = 18,
    },
    {
        .name = "SmartMesh",
        .unit = "SMT",
        .contract_address =
            "\x55\xf9\x39\x85\x43\x1f\xc9\x30\x40\x77\x68\x7a\x35\xa1\xba\x10\x3d\xc1\xe0\x81",
        .decimals = 18,
    },
    {
        .name = "SunContract",
        .unit = "SNC",
        .contract_address =
            "\xf4\x13\x41\x46\xaf\x2d\x51\x1d\xd5\xea\x8c\xdb\x1c\x4a\xc8\x8c\x57\xd6\x04\x04",
        .decimals = 18,
    },
    {
        .name = "Snetwork",
        .unit = "SNET",
        .contract_address =
            "\xff\x19\x13\x8b\x03\x9d\x93\x8d\xb4\x6b\xdd\xa0\x06\x7d\xc4\xba\x13\x2e\xc7\x1c",
        .decimals = 8,
    },
    {
        .name = "SingularDTV",
        .unit = "SNGLS",
        .contract_address =
            "\xae\xc2\xe8\x7e\x0a\x23\x52\x66\xd9\xc5\xad\xc9\xde\xb4\xb2\xe2\x9b\x54\xd0\x09",
        .decimals = 0,
    },
    {
        .name = "Sport and Leisure",
        .unit = "SNL",
        .contract_address =
            "\xa8\x06\xb3\xfe\xd6\x89\x11\x36\x94\x0c\xf8\x1c\x40\x85\x66\x15\x00\xaa\x27\x09",
        .decimals = 6,
    },
    {
        .name = "SONM",
        .unit = "SNM",
        .contract_address =
            "\x98\x3f\x6d\x60\xdb\x79\xea\x8c\xa4\xeb\x99\x68\xc6\xaf\xf8\xcf\xa0\x4b\x3c\x63",
        .decimals = 18,
    },
    {
        .name = "Status",
        .unit = "SNT",
        .contract_address =
            "\x74\x4d\x70\xfd\xbe\x2b\xa4\xcf\x95\x13\x16\x26\x61\x4a\x17\x63\xdf\x80\x5b\x9e",
        .decimals = 18,
    },
    {
        .name = "Sentivate",
        .unit = "SNTVT",
        .contract_address =
            "\x78\x65\xaf\x71\xcf\x0b\x28\x8b\x4e\x7f\x65\x4f\x4f\x78\x51\xeb\x46\xa2\xb7\xf8",
        .decimals = 18,
    },
    {
        .name = "Synthetix Network Token",
        .unit = "SNX",
        .contract_address =
            "\xc0\x11\xa7\x24\x00\xe5\x8e\xcd\x99\xee\x49\x7c\xf8\x9e\x37\x75\xd4\xbd\x73\x2f",
        .decimals = 18,
    },
    {
        .name = "All Sports",
        .unit = "SOC",
        .contract_address =
            "\x2d\x0e\x95\xbd\x47\x95\xd7\xac\xe0\xda\x3c\x0f\xf7\xb7\x06\xa5\x97\x0e\xb9\xd3",
        .decimals = 18,
    },
    {
        .name = "SOLVE",
        .unit = "SOLVE",
        .contract_address =
            "\x44\x6c\x90\x33\xe7\x51\x6d\x82\x0c\xc9\xa2\xce\x2d\x0b\x73\x28\xb5\x79\x40\x6f",
        .decimals = 8,
    },
    {
        .name = "SIRIN LABS Token",
        .unit = "SRN",
        .contract_address =
            "\x68\xd5\x7c\x9a\x1c\x35\xf6\x3e\x2c\x83\xee\x8e\x49\xa6\x4e\x9d\x70\x52\x8d\x25",
        .decimals = 18,
    },
    {
        .name = "STACS",
        .unit = "STACS",
        .contract_address =
            "\x28\x67\x08\xf0\x69\x22\x59\x05\x19\x46\x73\x75\x5f\x12\x35\x9e\x6a\xff\x6f\xe1",
        .decimals = 18,
    },
    {
        .name = "Storj",
        .unit = "STORJ",
        .contract_address =
            "\xb6\x4e\xf5\x1c\x88\x89\x72\xc9\x08\xcf\xac\xf5\x9b\x47\xc1\xaf\xbc\x0a\xb8\xac",
        .decimals = 8,
    },
    {
        .name = "Storm",
        .unit = "STORM",
        .contract_address =
            "\xd0\xa4\xb8\x94\x6c\xb5\x2f\x06\x61\x27\x3b\xfb\xc6\xfd\x0e\x0c\x75\xfc\x64\x33",
        .decimals = 18,
    },
    {
        .name = "STPT",
        .unit = "STPT",
        .contract_address =
            "\xde\x7d\x85\x15\x7d\x97\x14\xea\xdf\x59\x50\x45\xcc\x12\xca\x4a\x5f\x3e\x2a\xdb",
        .decimals = 18,
    },
    {
        .name = "Substratum",
        .unit = "SUB",
        .contract_address =
            "\x8d\x75\x95\x9f\x1e\x61\xec\x25\x71\xaa\x72\x79\x82\x37\x10\x1f\x08\x4d\xe6\x3a",
        .decimals = 18,
    },
    {
        .name = "sUSD",
        .unit = "SUSD",
        .contract_address =
            "\x57\xab\x1e\x02\xfe\xe2\x37\x74\x58\x0c\x11\x97\x40\x12\x9e\xac\x70\x81\xe9\xd3",
        .decimals = 18,
    },
    {
        .name = "Swace",
        .unit = "SWACE",
        .contract_address =
            "\x03\xb1\x55\xaf\x3f\x44\x59\x19\x3a\x27\x63\x95\xdd\x76\xe3\x57\xbb\x47\x2d\xa1",
        .decimals = 18,
    },
    {
        .name = "SwftCoin",
        .unit = "SWFTC",
        .contract_address =
            "\x0b\xb2\x17\xe4\x0f\x8a\x5c\xb7\x9a\xdf\x04\xe1\xaa\xb6\x0e\x5a\xbd\x0d\xfc\x1e",
        .decimals = 8,
    },
    {
        .name = "Swarm",
        .unit = "SWM",
        .contract_address =
            "\x35\x05\xf4\x94\xc3\xf0\xfe\xd0\xb5\x94\xe0\x1f\xa4\x1d\xd3\x96\x76\x45\xca\x39",
        .decimals = 18,
    },
    {
        .name = "Spectre.ai Dividend Token",
        .unit = "SXDT",
        .contract_address =
            "\x12\xb3\x06\xfa\x98\xf4\xcb\xb8\xd4\x45\x7f\xdf\xf3\xa0\xa0\xa5\x6f\x07\xcc\xdf",
        .decimals = 18,
    },
    {
        .name = "Swipe",
        .unit = "SXP",
        .contract_address =
            "\x8c\xe9\x13\x7d\x39\x32\x6a\xd0\xcd\x64\x91\xfb\x5c\xc0\xcb\xa0\xe0\x89\xb6\xa9",
        .decimals = 18,
    },
    {
        .name = "Spectre.ai Utility Token",
        .unit = "SXUT",
        .contract_address =
            "\x2c\x82\xc7\x3d\x5b\x34\xaa\x01\x59\x89\x46\x2b\x29\x48\xcd\x61\x6a\x37\x64\x1f",
        .decimals = 18,
    },
    {
        .name = "TaaS",
        .unit = "TAAS",
        .contract_address =
            "\xe7\x77\x5a\x6e\x9b\xcf\x90\x4e\xb3\x9d\xa2\xb6\x8c\x5e\xfb\x4f\x93\x60\xe0\x8c",
        .decimals = 6,
    },
    {
        .name = "Traceability Chain",
        .unit = "TAC",
        .contract_address =
            "\xca\x69\x4e\xb7\x9e\xf3\x55\xea\x09\x99\x48\x5d\x21\x1e\x68\xf3\x9a\xe9\x84\x93",
        .decimals = 8,
    },
    {
        .name = "TAGZ5",
        .unit = "TAGZ5",
        .contract_address =
            "\x4d\x04\x25\xe4\x7e\xe2\xd1\x6b\x94\xc0\x36\x71\x5d\xfc\xb5\x2a\x0c\xeb\xc4\xdc",
        .decimals = 8,
    },
    {
        .name = "Lamden",
        .unit = "TAU",
        .contract_address =
            "\xc2\x7a\x2f\x05\xfa\x57\x7a\x83\xba\x0f\xdb\x4c\x38\x44\x3c\x07\x18\x35\x65\x01",
        .decimals = 18,
    },
    {
        .name = "TokenClub",
        .unit = "TCT",
        .contract_address =
            "\x48\x24\xa7\xb6\x4e\x39\x66\xb0\x13\x3f\x4f\x4f\xfb\x1b\x9d\x6b\xeb\x75\xff\xf7",
        .decimals = 18,
    },
    {
        .name = "Telcoin",
        .unit = "TEL",
        .contract_address =
            "\x85\xe0\x76\x36\x1c\xc8\x13\xa9\x08\xff\x67\x2f\x9b\xad\x15\x41\x47\x44\x02\xb2",
        .decimals = 2,
    },
    {
        .name = "TEMCO",
        .unit = "TEMCO",
        .contract_address =
            "\x2f\xc2\x46\xaa\x66\xf0\xda\x5b\xb1\x36\x8f\x68\x85\x48\xec\xbb\xe9\xbd\xee\x5d",
        .decimals = 18,
    },
    {
        .name = "Tokenomy",
        .unit = "TEN",
        .contract_address =
            "\xdd\x16\xec\x0f\x66\xe5\x4d\x45\x3e\x67\x56\x71\x3e\x53\x33\x55\x98\x90\x40\xe4",
        .decimals = 18,
    },
    {
        .name = "TE-FOOD",
        .unit = "TFD",
        .contract_address =
            "\xe5\xf1\x66\xc0\xd8\x87\x2b\x68\x79\x00\x61\x31\x7b\xb6\xcc\xa0\x45\x82\xc9\x12",
        .decimals = 18,
    },
    {
        .name = "TrueFlip",
        .unit = "TFL",
        .contract_address =
            "\xa7\xf9\x76\xc3\x60\xeb\xbe\xd4\x46\x5c\x28\x55\x68\x4d\x1a\xae\x52\x71\xef\xa9",
        .decimals = 8,
    },
    {
        .name = "ThoreCoin",
        .unit = "THR",
        .contract_address =
            "\x1c\xb3\x20\x9d\x45\xb2\xa6\x0b\x7f\xbc\xa1\xcc\xdb\xf8\x7f\x67\x42\x37\xa4\xaa",
        .decimals = 4,
    },
    {
        .name = "ThoreNext",
        .unit = "THX",
        .contract_address =
            "\xf0\x8c\x68\xbd\x5f\x41\x94\xd9\x94\xfd\x70\x72\x67\x46\xbf\x52\x9e\xe5\xa6\x17",
        .decimals = 0,
    },
    {
        .name = "Trade Token X",
        .unit = "TIOX",
        .contract_address =
            "\xd9\x47\xb0\xce\xab\x2a\x88\x85\x86\x6b\x9a\x04\xa0\x6a\xe9\x9d\xe8\x52\xa3\xd4",
        .decimals = 18,
    },
    {
        .name = "Monolith",
        .unit = "TKN",
        .contract_address =
            "\xaa\xaf\x91\xd9\xb9\x0d\xf8\x00\xdf\x4f\x55\xc2\x05\xfd\x69\x89\xc9\x77\xe7\x3a",
        .decimals = 8,
    },
    {
        .name = "Time New Bank",
        .unit = "TNB",
        .contract_address =
            "\xf7\x92\x0b\x07\x68\xec\xb2\x0a\x12\x3f\xac\x32\x31\x1d\x07\xd1\x93\x38\x1d\x6f",
        .decimals = 18,
    },
    {
        .name = "Tierion",
        .unit = "TNT",
        .contract_address =
            "\x08\xf5\xa9\x23\x5b\x08\x17\x3b\x75\x69\xf8\x36\x45\xd2\xc7\xfb\x55\xe8\xcc\xd8",
        .decimals = 8,
    },
    {
        .name = "TOP",
        .unit = "TOP",
        .contract_address =
            "\xdc\xd8\x59\x14\xb8\xae\x28\xc1\xe6\x2f\x1c\x48\x8e\x1d\x96\x8d\x5a\xaf\xfe\x2b",
        .decimals = 18,
    },
    {
        .name = "T.OS",
        .unit = "TOSC",
        .contract_address =
            "\xd5\x06\x49\xaa\xb1\xd3\x9d\x68\xbc\x96\x5e\x0f\x6d\x1c\xfe\x00\x10\xe4\x90\x8b",
        .decimals = 8,
    },
    {
        .name = "OriginTrail",
        .unit = "TRAC",
        .contract_address =
            "\xaa\x7a\x9c\xa8\x7d\x36\x94\xb5\x75\x5f\x21\x3b\x5d\x04\x09\x4b\x8d\x0f\x0a\x6f",
        .decimals = 18,
    },
    {
        .name = "Tratin",
        .unit = "TRAT",
        .contract_address =
            "\x3e\xb5\x5d\x5b\x22\xee\x0f\x9b\x03\xd5\x9b\x49\x94\xc5\xae\x7f\xe8\x11\xbe\x92",
        .decimals = 8,
    },
    {
        .name = "Tellor",
        .unit = "TRB",
        .contract_address =
            "\x0b\xa4\x5a\x8b\x5d\x55\x75\x93\x5b\x81\x58\xa8\x8c\x63\x1e\x9f\x9c\x95\xa2\xe5",
        .decimals = 18,
    },
    {
        .name = "Tripio",
        .unit = "TRIO",
        .contract_address =
            "\x8b\x40\x76\x11\x42\xb9\xaa\x6d\xc8\x96\x4e\x61\xd0\x58\x59\x95\x42\x5c\x3d\x94",
        .decimals = 18,
    },
    {
        .name = "TrustVerse",
        .unit = "TRV",
        .contract_address =
            "\x72\x95\x5e\xcf\xf7\x6e\x48\xf2\xc8\xab\xcc\xe1\x1d\x54\xe5\x73\x4d\x6f\x36\x57",
        .decimals = 18,
    },
    {
        .name = "TrueUSD",
        .unit = "TUSD",
        .contract_address =
            "\x00\x00\x00\x00\x00\x08\x5d\x47\x80\xb7\x31\x19\xb6\x44\xae\x5e\xcd\x22\xb3\x76",
        .decimals = 18,
    },
    {
        .name = "Ubex",
        .unit = "UBEX",
        .contract_address =
            "\x67\x04\xb6\x73\xc7\x0d\xe9\xbf\x74\xc8\xfb\xa4\xb4\xbd\x74\x8f\x0e\x21\x90\xe1",
        .decimals = 18,
    },
    {
        .name = "Unibright",
        .unit = "UBT",
        .contract_address =
            "\x84\x00\xd9\x4a\x5c\xb0\xfa\x0d\x04\x1a\x37\x88\xe3\x95\x28\x5d\x61\xc9\xee\x5e",
        .decimals = 8,
    },
    {
        .name = "UNIVERSAL CASH",
        .unit = "UCASH",
        .contract_address =
            "\x92\xe5\x2a\x1a\x23\x5d\x9a\x10\x3d\x97\x09\x01\x06\x6c\xe9\x10\xaa\xce\xfd\x37",
        .decimals = 8,
    },
    {
        .name = "UGAS",
        .unit = "UGAS",
        .contract_address =
            "\x87\x16\xfc\x5d\xa0\x09\xd3\xa2\x08\xf0\x17\x8b\x63\x7a\x50\xf4\xef\x42\x40\x0f",
        .decimals = 18,
    },
    {
        .name = "UnlimitedIP",
        .unit = "UIP",
        .contract_address =
            "\x42\x90\x56\x3c\x2d\x7c\x25\x5b\x5e\xec\x87\xf2\xd3\xbd\x10\x38\x9f\x99\x1d\x68",
        .decimals = 18,
    },
    {
        .name = "Unikoin Gold",
        .unit = "UKG",
        .contract_address =
            "\x24\x69\x27\x91\xbc\x44\x4c\x5c\xd0\xb8\x1e\x3c\xbc\xab\xa4\xb0\x4a\xcd\x1f\x3b",
        .decimals = 18,
    },
    {
        .name = "Ultiledger",
        .unit = "ULT",
        .contract_address =
            "\xe8\x84\xcc\x27\x95\xb9\xc4\x5b\xee\xac\x06\x07\xda\x95\x39\xfd\x57\x1c\xcf\x85",
        .decimals = 18,
    },
    {
        .name = "UNI COIN",
        .unit = "UNI",
        .contract_address =
            "\xe6\x87\x7e\xa9\xc2\x8f\xbd\xec\x63\x1f\xfb\xc0\x87\x95\x6d\x00\x23\xa7\x6b\xf2",
        .decimals = 18,
    },
    {
        .name = "Ultra",
        .unit = "UOS",
        .contract_address =
            "\xd1\x3c\x73\x42\xe1\xef\x68\x7c\x5a\xd2\x1b\x27\xc2\xb6\x5d\x77\x2c\xab\x5c\x8c",
        .decimals = 4,
    },
    {
        .name = "Sentinel Protocol",
        .unit = "UPP",
        .contract_address =
            "\xc8\x6d\x05\x48\x09\x62\x34\x32\x21\x0c\x10\x7a\xf2\xe3\xf6\x19\xdc\xfb\xf6\x52",
        .decimals = 18,
    },
    {
        .name = "Uquid Coin",
        .unit = "UQC",
        .contract_address =
            "\xd0\x1d\xb7\x3e\x04\x78\x55\xef\xb4\x14\xe6\x20\x20\x98\xc4\xbe\x4c\xd2\x42\x3b",
        .decimals = 18,
    },
    {
        .name = "USD Coin",
        .unit = "USDC",
        .contract_address =
            "\xa0\xb8\x69\x91\xc6\x21\x8b\x36\xc1\xd1\x9d\x4a\x2e\x9e\xb0\xce\x36\x06\xeb\x48",
        .decimals = 6,
    },
    {
        .name = "USDK",
        .unit = "USDK",
        .contract_address =
            "\x1c\x48\xf8\x6a\xe5\x72\x91\xf7\x68\x63\x49\xf1\x26\x01\x91\x0b\xd8\xd4\x70\xbb",
        .decimals = 18,
    },
    {
        .name = "USDQ",
        .unit = "USDQ",
        .contract_address =
            "\x49\x54\xdb\x63\x91\xf4\xfe\xb5\x46\x8b\x6b\x94\x3d\x49\x35\x35\x35\x96\xae\xc9",
        .decimals = 18,
    },
    {
        .name = "Tether USD",
        .unit = "USDT",
        .contract_address =
            "\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7",
        .decimals = 6,
    },
    {
        .name = "Utrust",
        .unit = "UTK",
        .contract_address =
            "\x70\xa7\x28\x33\xd6\xbf\x7f\x50\x8c\x82\x24\xce\x59\xea\x1e\xf3\xd0\xea\x3a\x38",
        .decimals = 18,
    },
    {
        .name = "Universa",
        .unit = "UTNP",
        .contract_address =
            "\x9e\x33\x19\x63\x6e\x21\x26\xe3\xc0\xbc\x9e\x31\x34\xae\xc5\xe1\x50\x8a\x46\xc7",
        .decimals = 18,
    },
    {
        .name = "United Traders Token",
        .unit = "UTT",
        .contract_address =
            "\x16\xf8\x12\xbe\x7f\xff\x02\xca\xf6\x62\xb8\x5d\x5d\x58\xa5\xda\x65\x72\xd4\xdf",
        .decimals = 8,
    },
    {
        .name = "U Network",
        .unit = "UUU",
        .contract_address =
            "\x35\x43\x63\x8e\xd4\xa9\x00\x6e\x48\x40\xb1\x05\x94\x42\x71\xbc\xea\x15\x60\x5d",
        .decimals = 18,
    },
    {
        .name = "Valor Token",
        .unit = "VALOR",
        .contract_address =
            "\x29\x7e\x4e\x5e\x59\xad\x72\xb1\xb0\xa2\xfd\x44\x69\x29\xe7\x61\x17\xbe\x0e\x0a",
        .decimals = 18,
    },
    {
        .name = "VeriDocGlobal",
        .unit = "VDG",
        .contract_address =
            "\x57\xc7\x5e\xcc\xc8\x55\x71\x36\xd3\x26\x19\xa1\x91\xfb\xcd\xc8\x85\x60\xd7\x11",
        .decimals = 0,
    },
    {
        .name = "BLOCKv",
        .unit = "VEE",
        .contract_address =
            "\x34\x0d\x2b\xde\x5e\xb2\x8c\x1e\xed\x91\xb2\xf7\x90\x72\x3e\x3b\x16\x06\x13\xb7",
        .decimals = 18,
    },
    {
        .name = "Veritaseum",
        .unit = "VERI",
        .contract_address =
            "\x8f\x34\x70\xa7\x38\x8c\x05\xee\x4e\x7a\xf3\xd0\x1d\x8c\x72\x2b\x0f\xf5\x23\x74",
        .decimals = 18,
    },
    {
        .name = "VestChain",
        .unit = "VEST",
        .contract_address =
            "\x37\xf0\x4d\x2c\x3a\xe0\x75\xfa\xd5\x48\x3b\xb9\x18\x49\x1f\x65\x6b\x12\xbd\xb6",
        .decimals = 8,
    },
    {
        .name = "Voyager Token",
        .unit = "VGX",
        .contract_address =
            "\x5a\xf2\xbe\x19\x3a\x6a\xbc\xa9\xc8\x81\x70\x01\xf4\x57\x44\x77\x7d\xb3\x07\x56",
        .decimals = 8,
    },
    {
        .name = "Viberate",
        .unit = "VIB",
        .contract_address =
            "\x2c\x97\x4b\x2d\x0b\xa1\x71\x6e\x64\x4c\x1f\xc5\x99\x82\xa8\x9d\xdd\x2f\xf7\x24",
        .decimals = 18,
    },
    {
        .name = "VIBE",
        .unit = "VIBE",
        .contract_address =
            "\xe8\xff\x5c\x9c\x75\xde\xb3\x46\xac\xac\x49\x3c\x46\x3c\x89\x50\xbe\x03\xdf\xba",
        .decimals = 18,
    },
    {
        .name = "VideoCoin",
        .unit = "VID",
        .contract_address =
            "\x2c\x90\x23\xbb\xc5\x72\xff\x8d\xc1\x22\x8c\x78\x58\xa2\x80\x04\x6e\xa8\xc9\xe5",
        .decimals = 18,
    },
    {
        .name = "V-ID",
        .unit = "VIDT",
        .contract_address =
            "\x44\x5f\x51\x29\x9e\xf3\x30\x7d\xbd\x75\x03\x6d\xd8\x96\x56\x5f\x5b\x4b\xf7\xa5",
        .decimals = 18,
    },
    {
        .name = "VIDY",
        .unit = "VIDY",
        .contract_address =
            "\xc7\x7b\x23\x0f\x31\xb5\x17\xf1\xef\x36\x2e\x59\xc1\x73\xc2\xbe\x65\x40\xb5\xe8",
        .decimals = 18,
    },
    {
        .name = "VNDC",
        .unit = "VNDC",
        .contract_address =
            "\x1f\x3f\x67\x7e\xcc\x58\xf6\xa1\xf9\xe2\xcf\x41\x0d\xf4\x77\x6a\x85\x46\xb5\xde",
        .decimals = 0,
    },
    {
        .name = "VNT Chain",
        .unit = "VNT",
        .contract_address =
            "\x69\xd2\x77\x95\x33\xa4\xd2\xc7\x80\x63\x97\x13\x55\x8b\x2c\xc9\x8c\x46\xa9\xb7",
        .decimals = 8,
    },
    {
        .name = "Tael",
        .unit = "WABI",
        .contract_address =
            "\x28\x6b\xda\x14\x13\xa2\xdf\x81\x73\x1d\x49\x30\xce\x2f\x86\x2a\x35\xa6\x09\xfe",
        .decimals = 18,
    },
    {
        .name = "Wrapped Bitcoin",
        .unit = "WBTC",
        .contract_address =
            "\x22\x60\xfa\xc5\xe5\x54\x2a\x77\x3a\xa4\x4f\xbc\xfe\xdf\x7c\x19\x3b\xc2\xc5\x99",
        .decimals = 8,
    },
    {
        .name = "Winco",
        .unit = "WCO",
        .contract_address =
            "\xd4\x4b\xb6\x66\x39\x36\xca\xb1\x31\x05\x84\xa2\x77\xf7\xda\xa6\x94\x3d\x49\x04",
        .decimals = 8,
    },
    {
        .name = "Wings",
        .unit = "WINGS",
        .contract_address =
            "\x66\x70\x88\xb2\x12\xce\x3d\x06\xa1\xb5\x53\xa7\x22\x1e\x1f\xd1\x90\x00\xd9\xaf",
        .decimals = 18,
    },
    {
        .name = "Wixlar",
        .unit = "WIX",
        .contract_address =
            "\x7b\xa1\x9b\x7f\x7d\x10\x6a\x9a\x1e\x09\x85\x39\x7b\x94\xf3\x8e\xee\x0b\x55\x5e",
        .decimals = 2,
    },
    {
        .name = "WePower",
        .unit = "WPR",
        .contract_address =
            "\x4c\xf4\x88\x38\x7f\x03\x5f\xf0\x8c\x37\x15\x15\x56\x2c\xba\x71\x2f\x90\x15\xd4",
        .decimals = 18,
    },
    {
        .name = "Waltonchain",
        .unit = "WTC",
        .contract_address =
            "\xb7\xcb\x1c\x96\xdb\x6b\x22\xb0\xd3\xd9\x53\x6e\x01\x08\xd0\x62\xbd\x48\x8f\x74",
        .decimals = 18,
    },
    {
        .name = "General Attention Currency",
        .unit = "XAC",
        .contract_address =
            "\xde\x4c\x5a\x79\x19\x13\x83\x80\x27\xa2\x18\x57\x09\xe9\x8c\x5c\x60\x27\xea\x63",
        .decimals = 8,
    },
    {
        .name = "Xaurum",
        .unit = "XAUR",
        .contract_address =
            "\x4d\xf8\x12\xf6\x06\x4d\xef\x1e\x5e\x02\x9f\x1c\xa8\x58\x77\x7c\xc9\x8d\x2d\x81",
        .decimals = 8,
    },
    {
        .name = "CryptoFranc",
        .unit = "XCHF",
        .contract_address =
            "\xb4\x27\x20\x71\xec\xad\xd6\x9d\x93\x3a\xdc\xd1\x9c\xa9\x9f\xe8\x06\x64\xfc\x08",
        .decimals = 18,
    },
    {
        .name = "DigitalBits",
        .unit = "XDB",
        .contract_address =
            "\xb9\xee\xfc\x4b\x0d\x47\x2a\x44\xbe\x93\x97\x02\x54\xdf\x4f\x40\x16\x56\x9d\x27",
        .decimals = 7,
    },
    {
        .name = "XinFin Network",
        .unit = "XDCE",
        .contract_address =
            "\x41\xab\x1b\x6f\xcb\xb2\xfa\x9d\xce\xd8\x1a\xcb\xde\xc1\x3e\xa6\x31\x5f\x2b\xf2",
        .decimals = 18,
    },
    {
        .name = "ETERNAL TOKEN",
        .unit = "XET",
        .contract_address =
            "\x05\x4c\x64\x74\x1d\xba\xfd\xc1\x97\x84\x50\x54\x94\x02\x98\x23\xd8\x9c\x3b\x13",
        .decimals = 8,
    },
    {
        .name = "Mixin",
        .unit = "XIN",
        .contract_address =
            "\xa9\x74\xc7\x09\xcf\xb4\x56\x66\x86\x55\x3a\x20\x79\x06\x85\xa4\x7a\xce\xaa\x33",
        .decimals = 18,
    },
    {
        .name = "XcelToken Plus",
        .unit = "XLAB",
        .contract_address =
            "\x8c\x4e\x7f\x81\x4d\x40\xf8\x92\x9f\x91\x12\xc5\xd0\x90\x16\xf9\x23\xd3\x44\x72",
        .decimals = 18,
    },
    {
        .name = "XMax",
        .unit = "XMX",
        .contract_address =
            "\x0f\x8c\x45\xb8\x96\x78\x4a\x1e\x40\x85\x26\xb9\x30\x05\x19\xef\x86\x60\x20\x9c",
        .decimals = 8,
    },
    {
        .name = "Xensor",
        .unit = "XSR",
        .contract_address =
            "\x6b\xc1\xf3\xa1\xae\x56\x23\x1d\xbb\x64\xd3\xe8\x2e\x07\x08\x57\xea\xe8\x60\x45",
        .decimals = 18,
    },
    {
        .name = "XYO",
        .unit = "XYO",
        .contract_address =
            "\x55\x29\x6f\x69\xf4\x0e\xa6\xd2\x0e\x47\x85\x33\xc1\x5a\x6b\x08\xb6\x54\xe7\x58",
        .decimals = 18,
    },
    {
        .name = "YEE",
        .unit = "YEE",
        .contract_address =
            "\x92\x21\x05\xfa\xd8\x15\x3f\x51\x6b\xcf\xb8\x29\xf5\x6d\xc0\x97\xa0\xe1\xd7\x05",
        .decimals = 18,
    },
    {
        .name = "YGGDRASH",
        .unit = "YEED",
        .contract_address =
            "\xca\x27\x96\xf9\xf6\x1d\xc7\xb2\x38\xaa\xb0\x43\x97\x1e\x49\xc6\x16\x4d\xf3\x75",
        .decimals = 18,
    },
    {
        .name = "YOU COIN",
        .unit = "YOU",
        .contract_address =
            "\x34\x36\x4b\xee\x11\x60\x7b\x19\x63\xd6\x6b\xca\x66\x5f\xde\x93\xfc\xa6\x66\xa8",
        .decimals = 18,
    },
    {
        .name = "ZB Token",
        .unit = "ZB",
        .contract_address =
            "\xbd\x07\x93\x33\x2e\x9f\xb8\x44\xa5\x2a\x20\x5a\x23\x3e\xf2\x7a\x5b\x34\xb9\x27",
        .decimals = 18,
    },
    {
        .name = "ZEON",
        .unit = "ZEON",
        .contract_address =
            "\xe5\xb8\x26\xca\x2c\xa0\x2f\x09\xc1\x72\x5e\x9b\xd9\x8d\x9a\x88\x74\xc3\x05\x32",
        .decimals = 18,
    },
    {
        .name = "Zipper",
        .unit = "ZIP",
        .contract_address =
            "\xa9\xd2\x92\x7d\x3a\x04\x30\x9e\x00\x8b\x6a\xf6\xe2\xe2\x82\xae\x29\x52\xe7\xfd",
        .decimals = 18,
    },
    {
        .name = "0x",
        .unit = "ZRX",
        .contract_address =
            "\xe4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6d\xaf\xa5\xeb\xde\x1f\x46\x99\xf4\x98",
        .decimals = 18,
    },
    {
        .name = "ZTCoin",
        .unit = "ZT",
        .contract_address =
            "\xfe\x39\xe6\xa3\x2a\xcd\x2a\xf7\x95\x5c\xb3\xd4\x06\xba\x2b\x55\xc9\x01\xf2\x47",
        .decimals = 18,
    },
    {
        .name = "0xBitcoin",
        .unit = "0xBTC",
        .contract_address =
            "\xb6\xed\x76\x44\xc6\x94\x16\xd6\x7b\x52\x2e\x20\xbc\x29\x4a\x9a\x9b\x40\x5b\x31",
        .decimals = 8,
    },
    {
        .name = "1irstGold",
        .unit = "1GOLD",
        .contract_address =
            "\xda\x41\x29\x91\x9f\x96\x4a\x3a\x52\x6d\x31\x82\xbb\x03\xe6\x44\x9e\x5a\x88\x72",
        .decimals = 4,
    },
    {
        .name = "1Million Token",
        .unit = "1MT",
        .contract_address =
            "\xf0\xbc\x1a\xe4\xef\x7f\xfb\x12\x6a\x83\x47\xd0\x6a\xc6\xf8\xad\xd7\x70\xe1\xce",
        .decimals = 7,
    },
    {
        .name = "Uptrennd",
        .unit = "1UP",
        .contract_address =
            "\x07\x59\x72\x55\x91\x0a\x51\x50\x9c\xa4\x69\x56\x8b\x04\x8f\x25\x97\xe7\x25\x04",
        .decimals = 18,
    },
    {
        .name = "2key.network",
        .unit = "2KEY",
        .contract_address =
            "\xe4\x89\x72\xfc\xd8\x2a\x27\x44\x11\xc0\x18\x34\xe2\xf0\x31\xd4\x37\x7f\xa2\xc0",
        .decimals = 18,
    },
    {
        .name = "Crypto Cricket Club",
        .unit = "3Cs",
        .contract_address =
            "\x4f\x56\x22\x12\x52\xd1\x17\xf3\x5e\x2f\x6a\xb9\x37\xa3\xf7\x7c\xad\x38\x93\x4d",
        .decimals = 18,
    },
    {
        .name = "4ART Coin",
        .unit = "4ART",
        .contract_address =
            "\xff\x44\xb5\x71\x9f\x0b\x77\xa9\x95\x16\x36\xfc\x5e\x69\xd3\xa1\xfc\x9e\x7d\x73",
        .decimals = 18,
    },
    {
        .name = "Alpha Token",
        .unit = "A",
        .contract_address =
            "\xff\xc6\x3b\x91\x46\x96\x7a\x1b\xa3\x30\x66\xfb\x05\x7e\xe3\x72\x22\x21\xac\xf0",
        .decimals = 18,
    },
    {
        .name = "Abulaba",
        .unit = "AAA",
        .contract_address =
            "\xd9\x38\x13\x7e\x6d\x96\xc7\x2e\x4a\x60\x85\x41\x2a\xda\x2d\xad\x78\xff\x89\xc4",
        .decimals = 8,
    },
    {
        .name = "AAX Token",
        .unit = "AAB",
        .contract_address =
            "\x68\x6c\x65\x0d\xbc\xfe\xaa\x75\xd0\x9b\x88\x36\x21\xad\x81\x0f\x59\x52\xbd\x5d",
        .decimals = 18,
    },
    {
        .name = "Acute Angle Cloud",
        .unit = "AAC",
        .contract_address =
            "\xe7\x5a\xd3\xaa\xb1\x4e\x4b\x0d\xf8\xc5\xda\x42\x86\x60\x8d\xab\xb2\x1b\xd8\x64",
        .decimals = 5,
    },
    {
        .name = "Abitshadow Token",
        .unit = "ABST",
        .contract_address =
            "\xa0\xb2\x07\x10\x3f\x76\x4a\x92\x0b\x4a\xf9\xe6\x91\xf5\xbd\x95\x6d\xe1\x4d\xed",
        .decimals = 8,
    },
    {
        .name = "Arbidex",
        .unit = "ABX",
        .contract_address =
            "\x9a\x79\x4d\xc1\x93\x9f\x1d\x78\xfa\x48\x61\x3b\x89\xb8\xf9\xd0\xa2\x0d\xa0\x0e",
        .decimals = 18,
    },
    {
        .name = "Volt",
        .unit = "ACDC",
        .contract_address =
            "\xfc\x44\xec\x51\xc8\x0e\x35\xa8\x7b\xc2\x14\x02\x99\xb1\x63\x6e\xc8\x3d\xfb\x04",
        .decimals = 18,
    },
    {
        .name = "ACE (TokenStars)",
        .unit = "ACE",
        .contract_address =
            "\x06\x14\x71\x10\x02\x2b\x76\x8b\xa8\xf9\x9a\x8f\x38\x5d\xf1\x1a\x15\x1a\x9c\xc8",
        .decimals = 0,
    },
    {
        .name = "AceD",
        .unit = "ACED",
        .contract_address =
            "\x4b\x3a\x0c\x6d\x66\x8b\x43\xf3\xf0\x79\x04\xe1\x24\x32\x86\x59\xb9\x0b\xb4\xca",
        .decimals = 18,
    },
    {
        .name = "Aitheon",
        .unit = "ACU",
        .contract_address =
            "\xd5\x36\xbb\xd5\x41\x4a\x8c\x2b\xee\xd8\x2a\x63\x73\x7b\x93\x27\xd2\xfa\x35\xa6",
        .decimals = 18,
    },
    {
        .name = "Asian Dragon",
        .unit = "AD",
        .contract_address =
            "\xf6\xdb\xe8\x8b\xa5\x5f\x17\x93\xff\x07\x73\xc9\xb1\x27\x53\x00\xf8\x30\x91\x4f",
        .decimals = 8,
    },
    {
        .name = "3X Short Cardano Token",
        .unit = "ADABEAR",
        .contract_address =
            "\xb3\x29\x9d\x4b\xab\x93\xbf\x04\xd5\xb1\x1b\xc4\x9c\xd6\xdf\xad\x1f\x77\xd2\x3f",
        .decimals = 18,
    },
    {
        .name = "adbank",
        .unit = "ADB",
        .contract_address =
            "\x2b\xaa\xc9\x33\x0c\xf9\xac\x47\x9d\x81\x91\x95\x79\x4d\x79\xad\x0c\x76\x16\xe3",
        .decimals = 18,
    },
    {
        .name = "AdHive",
        .unit = "ADH",
        .contract_address =
            "\xe6\x9a\x35\x3b\x31\x52\xdd\x7b\x70\x6f\xf7\xdd\x40\xfe\x1d\x18\xb7\x80\x2d\x31",
        .decimals = 18,
    },
    {
        .name = "Adelphoi",
        .unit = "ADL",
        .contract_address =
            "\x66\x0e\x71\x48\x37\x85\xf6\x61\x33\x54\x8b\x10\xf6\x92\x6d\xc3\x32\xb0\x6e\x61",
        .decimals = 18,
    },
    {
        .name = "AEN Smart Token",
        .unit = "AENS",
        .contract_address =
            "\xd3\x8d\xe8\x86\x87\x17\x2b\xde\x44\x07\x55\xb5\x23\x79\x87\xe4\xa8\x7c\x23\xa7",
        .decimals = 8,
    },
    {
        .name = "Agrolot",
        .unit = "AGLT",
        .contract_address =
            "\x72\xc9\xfb\x7e\xd1\x9d\x3c\xe5\x1c\xea\x5c\x56\xb3\xe0\x23\xcd\x91\x8b\xaa\xdf",
        .decimals = 18,
    },
    {
        .name = "AICON",
        .unit = "AICO",
        .contract_address =
            "\xe7\xfb\x35\x59\x35\x8a\x99\xdf\x54\x46\x6d\x03\x50\xe4\xad\x6d\xc7\x09\x3d\xa3",
        .decimals = 8,
    },
    {
        .name = "AidCoin",
        .unit = "AID",
        .contract_address =
            "\x37\xe8\x78\x9b\xb9\x99\x6c\xac\x91\x56\xcd\x5f\x5f\xd3\x25\x99\xe6\xb9\x12\x89",
        .decimals = 18,
    },
    {
        .name = "AIDUS TOKEN",
        .unit = "AIDUS",
        .contract_address =
            "\xa9\x57\x04\x5a\x12\xd2\x70\xe2\xee\x0d\xca\x9a\x33\x40\xc3\x40\xe0\x5d\x46\x70",
        .decimals = 18,
    },
    {
        .name = "AICHAIN",
        .unit = "AIT",
        .contract_address =
            "\x79\x65\x07\x99\xe7\x89\x9a\x80\x2c\xb9\x6c\x0b\xc3\x3a\x6a\x8d\x4c\xe4\x93\x6c",
        .decimals = 18,
    },
    {
        .name = "Aigang",
        .unit = "AIX",
        .contract_address =
            "\x10\x63\xce\x52\x42\x65\xd5\xa3\xa6\x24\xf4\x91\x4a\xcd\x57\x3d\xd8\x9c\xe9\x88",
        .decimals = 18,
    },
    {
        .name = "Akropolis ",
        .unit = "AKRO",
        .contract_address =
            "\x8a\xb7\x40\x40\x63\xec\x4d\xbc\xfd\x45\x98\x21\x59\x92\xdc\x3f\x8e\xc8\x53\xd7",
        .decimals = 18,
    },
    {
        .name = "Aludra Network",
        .unit = "ALD",
        .contract_address =
            "\xb3\x39\xfc\xa5\x31\x36\x70\x67\xe9\x8d\x7c\x4f\x93\x03\xff\xea\xdf\xf7\xb8\x81",
        .decimals = 18,
    },
    {
        .name = "3X Short Algorand Token",
        .unit = "ALGOBEAR",
        .contract_address =
            "\x05\x7f\xb1\x0e\x3f\xec\x00\x1a\x40\xe6\xb7\x5d\x3a\x30\xb9\x9e\x23\xe5\x41\x07",
        .decimals = 18,
    },
    {
        .name = "3X Long Algorand Token",
        .unit = "ALGOBULL",
        .contract_address =
            "\x58\x49\x36\x35\x7d\x68\xf5\x14\x3f\x12\xe2\xe6\x4f\x00\x89\xdb\x93\x81\x4d\xad",
        .decimals = 18,
    },
    {
        .name = "AiLink Token",
        .unit = "ALI",
        .contract_address =
            "\x42\x89\xc0\x43\xa1\x23\x92\xf1\x02\x73\x07\xfb\x58\x27\x2d\x8e\xbd\x85\x39\x12",
        .decimals = 18,
    },
    {
        .name = "ALL BEST ICO",
        .unit = "ALLBI",
        .contract_address =
            "\x65\xac\x08\xc5\x5f\x21\xd4\xa7\x3c\xa1\xd4\x29\xa1\x7a\x68\x72\xb2\x3b\xfd\x55",
        .decimals = 18,
    },
    {
        .name = "Alt.Estate token",
        .unit = "ALT",
        .contract_address =
            "\x41\x9b\x8e\xd1\x55\x18\x0a\x8c\x9c\x64\x14\x5e\x76\xda\xd4\x9c\x0a\x4e\xfb\x97",
        .decimals = 18,
    },
    {
        .name = "ALLY",
        .unit = "ALY",
        .contract_address =
            "\x9d\x56\x86\xea\xde\xa7\x32\x7f\x5a\x0c\x48\x20\xdc\xa9\x04\x57\xa0\xe8\x87\x63",
        .decimals = 18,
    },
    {
        .name = "AMATEN",
        .unit = "AMA",
        .contract_address =
            "\x18\x30\xdd\x31\x22\x0a\x7f\x76\x88\x9e\xaf\xcc\x57\x58\xee\x52\x1a\xc3\x82\xb2",
        .decimals = 18,
    },
    {
        .name = "MicroMoney",
        .unit = "AMM",
        .contract_address =
            "\x8b\x1f\x49\x49\x14\x77\xe0\xfb\x46\xa2\x9f\xef\x53\xf1\xea\x32\x0d\x13\xc3\x49",
        .decimals = 6,
    },
    {
        .name = "Amon",
        .unit = "AMN",
        .contract_address =
            "\x73\x7f\x98\xac\x8c\xa5\x9f\x2c\x68\xad\x65\x8e\x3c\x3d\x8c\x89\x63\xe4\x0a\x4c",
        .decimals = 18,
    },
    {
        .name = "AmonD",
        .unit = "AMON",
        .contract_address =
            "\x00\x05\x9a\xe6\x9c\x16\x22\xa7\x54\x2e\xdc\x15\xe8\xd1\x7b\x06\x0f\xe3\x07\xb6",
        .decimals = 18,
    },
    {
        .name = "Aragon Court",
        .unit = "ANJ",
        .contract_address =
            "\xcd\x62\xb1\xc4\x03\xfa\x76\x1b\xaa\xdf\xc7\x4c\x52\x5c\xe2\xb5\x17\x80\xb1\x84",
        .decimals = 18,
    },
    {
        .name = "Anchor Neural World",
        .unit = "ANW",
        .contract_address =
            "\x7d\xbd\xd9\xda\xfd\xc4\xc1\xc0\x3d\x67\x92\x5a\x4f\x85\xda\xa3\x98\xaf\x32\xb0",
        .decimals = 18,
    },
    {
        .name = "smARTOFGIVING",
        .unit = "AOG",
        .contract_address =
            "\x85\x78\x53\x02\x05\xce\xcb\xe5\xdb\x83\xf7\xf2\x9e\xcf\xee\xc8\x60\xc2\x97\xc2",
        .decimals = 18,
    },
    {
        .name = "Alpha Coin",
        .unit = "APC",
        .contract_address =
            "\x15\xbd\xa0\x8c\x3a\xfb\xf5\x95\x5d\x6e\x9b\x23\x5f\xd5\x5a\x1f\xd0\xdb\xc8\x29",
        .decimals = 6,
    },
    {
        .name = "APIX",
        .unit = "APIX",
        .contract_address =
            "\xf5\x1e\xbf\x9a\x26\xdb\xc0\x2b\x13\xf8\xb3\xa9\x11\x0d\xac\x47\xa4\xd6\x2d\x78",
        .decimals = 18,
    },
    {
        .name = "apM Coin",
        .unit = "APM",
        .contract_address =
            "\xc8\xc4\x24\xb9\x1d\x8c\xe0\x13\x7b\xab\x4b\x83\x2b\x7f\x7d\x15\x41\x56\xba\x6c",
        .decimals = 18,
    },
    {
        .name = "ARAW",
        .unit = "ARAW",
        .contract_address =
            "\x30\x68\x0a\xc0\xa8\xa9\x93\x08\x82\x23\x92\x52\x65\xfd\x7a\x76\xbe\xb8\x7e\x7f",
        .decimals = 18,
    },
    {
        .name = "ArbitrageCT",
        .unit = "ARCT",
        .contract_address =
            "\x12\x45\xef\x80\xf4\xd9\xe0\x2e\xd9\x42\x53\x75\xe8\xf6\x49\xb9\x22\x1b\x31\xd8",
        .decimals = 8,
    },
    {
        .name = "ArdCoin",
        .unit = "ARDX",
        .contract_address =
            "\xb8\xe2\xe2\x10\x1e\xd1\x1e\x91\x38\x80\x3c\xd3\xe0\x6e\x16\xdd\x19\x91\x06\x47",
        .decimals = 2,
    },
    {
        .name = "Maecenas",
        .unit = "ART",
        .contract_address =
            "\xfe\xc0\xcf\x7f\xe0\x78\xa5\x00\xab\xf1\x5f\x12\x84\x95\x8f\x22\x04\x9c\x2c\x7e",
        .decimals = 18,
    },
    {
        .name = "Artis Turba",
        .unit = "ARTIS",
        .contract_address =
            "\x08\x2e\x13\x49\x4f\x12\xeb\xb7\x20\x6f\xbf\x67\xe2\x2a\x6e\x19\x75\xa1\xa6\x69",
        .decimals = 8,
    },
    {
        .name = "ARCS",
        .unit = "ARX",
        .contract_address =
            "\x20\xb1\xa8\xa9\xca\x1c\x73\x02\xb7\xf7\x74\x26\x6c\x49\x1c\x7b\x11\x62\x27\x79",
        .decimals = 18,
    },
    {
        .name = "Askobar Network",
        .unit = "ASKO",
        .contract_address =
            "\xee\xee\x2a\x62\x23\x30\xe6\xd2\x03\x66\x91\xe9\x83\xde\xe8\x73\x30\x58\x86\x03",
        .decimals = 18,
    },
    {
        .name = "ABCC Token",
        .unit = "AT",
        .contract_address =
            "\xbf\x8f\xb9\x19\xa8\xbb\xf2\x8e\x59\x08\x52\xae\xf2\xd2\x84\x49\x4e\xbc\x06\x57",
        .decimals = 18,
    },
    {
        .name = "ATMChain",
        .unit = "ATM",
        .contract_address =
            "\x9b\x11\xef\xca\xaa\x18\x90\xf6\xee\x52\xc6\xbb\x7c\xf8\x15\x3a\xc5\xd7\x41\x39",
        .decimals = 8,
    },
    {
        .name = "Atonomi",
        .unit = "ATMI",
        .contract_address =
            "\x97\xae\xb5\x06\x6e\x1a\x59\x0e\x86\x8b\x51\x14\x57\xbe\xb6\xfe\x99\xd3\x29\xf5",
        .decimals = 18,
    },
    {
        .name = "3X Long Cosmos Token",
        .unit = "ATOMBULL",
        .contract_address =
            "\x75\xf0\x03\x8b\x8f\xbf\xcc\xaf\xe2\xab\x9a\x51\x43\x16\x58\x87\x1b\xa5\x18\x2c",
        .decimals = 18,
    },
    {
        .name = "Authorship",
        .unit = "ATS",
        .contract_address =
            "\x2d\xae\xe1\xaa\x61\xd6\x0a\x25\x2d\xc8\x05\x64\x49\x9a\x69\x80\x28\x53\x58\x3a",
        .decimals = 4,
    },
    {
        .name = "Attila",
        .unit = "ATT",
        .contract_address =
            "\x89\xfb\x92\x72\x40\x75\x0c\x1b\x15\xd4\x74\x3c\xd5\x84\x40\xfc\x5f\x14\xa1\x1c",
        .decimals = 18,
    },
    {
        .name = "Aston",
        .unit = "ATX",
        .contract_address =
            "\x1a\x0f\x2a\xb4\x6e\xc6\x30\xf9\xfd\x63\x80\x29\x02\x7b\x55\x2a\xfa\x64\xb9\x4c",
        .decimals = 18,
    },
    {
        .name = "Auctus",
        .unit = "AUC",
        .contract_address =
            "\xc1\x2d\x09\x9b\xe3\x15\x67\xad\xd4\xe4\xe4\xd0\xd4\x56\x91\xc3\xf5\x8f\x56\x63",
        .decimals = 18,
    },
    {
        .name = "Afri Union Coin",
        .unit = "AUC",
        .contract_address =
            "\xbe\xea\x28\x90\x77\x58\x89\xc7\x72\x3e\x5c\x0b\x80\x52\x79\x76\x80\x3b\x5a\x99",
        .decimals = 18,
    },
    {
        .name = "Aquila Protocol",
        .unit = "AUX",
        .contract_address =
            "\x42\x3f\x3d\xa1\x66\x47\x00\x30\xa8\x6f\xa7\x62\x80\xb2\xd6\x88\xfc\xe1\xf7\x22",
        .decimals = 18,
    },
    {
        .name = "Aventus",
        .unit = "AVT",
        .contract_address =
            "\x0d\x88\xed\x6e\x74\xbb\xfd\x96\xb8\x31\x23\x16\x38\xb6\x6c\x05\x57\x1e\x82\x4f",
        .decimals = 18,
    },
    {
        .name = "Atomic Wallet Coin",
        .unit = "AWC",
        .contract_address =
            "\xad\x22\xf6\x34\x04\xf7\x30\x5e\x47\x13\xcc\xbd\x4f\x29\x6f\x34\x77\x05\x13\xf4",
        .decimals = 8,
    },
    {
        .name = "Axial Entertainment Digital Asset",
        .unit = "AXL",
        .contract_address =
            "\x4f\xac\x0c\xcd\x9e\x2e\xd9\xfd\x46\x2d\x42\xb6\x6f\xb8\x1b\xa9\xa1\xf6\xf2\x5e",
        .decimals = 18,
    },
    {
        .name = "AXPR",
        .unit = "AXPR",
        .contract_address =
            "\xc3\x9e\x62\x6a\x04\xc5\x97\x1d\x77\x0e\x31\x97\x60\xd7\x92\x65\x02\x97\x5e\x47",
        .decimals = 18,
    },
    {
        .name = "Azbit",
        .unit = "AZ",
        .contract_address =
            "\xaa\xaa\xaa\xab\xa2\xea\x3d\xaa\xb0\xa6\xc0\x5f\x1b\x96\x2c\x78\xc9\x83\x6d\x99",
        .decimals = 18,
    },
    {
        .name = "Balancer",
        .unit = "BAL",
        .contract_address =
            "\xba\x10\x00\x00\x62\x5a\x37\x54\x42\x39\x78\xa6\x0c\x93\x17\xc5\x8a\x42\x4e\x3d",
        .decimals = 18,
    },
    {
        .name = "Bali Coin",
        .unit = "BALI",
        .contract_address =
            "\x01\x3a\x06\x55\x8f\x07\xd9\xe6\xf9\xa0\x0c\x95\xa3\x3f\x3a\x0e\x02\x55\x17\x6b",
        .decimals = 18,
    },
    {
        .name = "Banca",
        .unit = "BANCA",
        .contract_address =
            "\x99\x8b\x3b\x82\xbc\x9d\xba\x17\x39\x90\xbe\x7a\xfb\x77\x27\x88\xb5\xac\xb8\xbd",
        .decimals = 18,
    },
    {
        .name = "BASIC",
        .unit = "BASIC",
        .contract_address =
            "\xf2\x5c\x91\xc8\x7e\x0b\x1f\xd9\xb4\x06\x4a\xf0\xf4\x27\x15\x7a\xab\x01\x93\xa7",
        .decimals = 18,
    },
    {
        .name = "Baz Token",
        .unit = "BAZT",
        .contract_address =
            "\xb0\x20\xed\x54\x65\x18\x31\x87\x8e\x5c\x96\x7e\x09\x53\xa9\x00\x78\x61\x78\xf9",
        .decimals = 18,
    },
    {
        .name = "TraDove B2BCoin",
        .unit = "BBC",
        .contract_address =
            "\xe7\xd3\xe4\x41\x3e\x29\xae\x35\xb0\x89\x31\x40\xf4\x50\x09\x65\xc7\x43\x65\xe5",
        .decimals = 18,
    },
    {
        .name = "Blue Baikal",
        .unit = "BBC",
        .contract_address =
            "\x67\x5c\xe9\x95\x95\x31\x36\x81\x4c\xb0\x5a\xaa\xa5\xd0\x23\x27\xe7\xdc\x8c\x93",
        .decimals = 18,
    },
    {
        .name = "Bigbom",
        .unit = "BBO",
        .contract_address =
            "\x84\xf7\xc4\x4b\x6f\xed\x10\x80\xf6\x47\xe3\x54\xd5\x52\x59\x5b\xe2\xcc\x60\x2f",
        .decimals = 18,
    },
    {
        .name = "Block-Chain.com",
        .unit = "BC",
        .contract_address =
            "\x2e\xcb\x13\xa8\xc4\x58\xc3\x79\xc4\xd9\xa7\x25\x9e\x20\x2d\xe0\x3c\x8f\x3d\x19",
        .decimals = 18,
    },
    {
        .name = "Business Credit Alliance Chain",
        .unit = "BCAC",
        .contract_address =
            "\x1a\xbd\xb3\x09\xaa\x59\x2f\x00\xa1\x01\xc5\x45\x16\x8b\xfd\xf9\xa6\xec\x61\xce",
        .decimals = 18,
    },
    {
        .name = "Blockchain Certified Data Token",
        .unit = "BCDT",
        .contract_address =
            "\xac\xfa\x20\x9f\xb7\x3b\xf3\xdd\x5b\xbf\xb1\x10\x1b\x9b\xc9\x99\xc4\x90\x62\xa5",
        .decimals = 18,
    },
    {
        .name = "bitCEO",
        .unit = "BCEO",
        .contract_address =
            "\x19\xca\x83\xa1\x3b\x4c\x4b\xe4\x3f\xa8\x2c\x5e\x41\x5e\x16\xf1\xd8\x6f\x57\xf7",
        .decimals = 18,
    },
    {
        .name = "3x Short Bitcoin Cash Token",
        .unit = "BCHBEAR",
        .contract_address =
            "\xa9\xfc\x65\xda\x36\x06\x4c\xe5\x45\xe8\x76\x90\xe0\x6f\x5d\xe1\x0c\x52\xc6\x90",
        .decimals = 18,
    },
    {
        .name = "3x Long Bitcoin Cash Token",
        .unit = "BCHBULL",
        .contract_address =
            "\x4c\x13\x3e\x08\x1d\xfb\x58\x58\xe3\x9c\xca\x74\xe6\x9b\xf6\x03\xd4\x09\xe5\x7a",
        .decimals = 18,
    },
    {
        .name = "BitCherry",
        .unit = "BCHC",
        .contract_address =
            "\x2a\xb0\x5b\x91\x5c\x30\x09\x36\x79\x16\x5b\xcd\xba\x9c\x26\xd8\xcd\x8b\xee\x99",
        .decimals = 18,
    },
    {
        .name = "Bincentive",
        .unit = "BCNT",
        .contract_address =
            "\x96\x69\x89\x0e\x48\xf3\x30\xac\xd8\x8b\x78\xd6\x3e\x1a\x6b\x34\x82\x65\x2c\xd9",
        .decimals = 18,
    },
    {
        .name = "Business Credit Substitute",
        .unit = "BCS",
        .contract_address =
            "\x31\x27\x4d\xb8\xb6\x09\xdf\x99\xe5\x98\x8e\xe5\x27\x07\x16\x43\xb5\x16\x0f\xc3",
        .decimals = 18,
    },
    {
        .name = "BDCC COIN",
        .unit = "BDCC",
        .contract_address =
            "\xc8\x7f\x95\xaa\x26\x9d\xd3\x00\xd9\xf1\xce\x49\xd8\xe1\xfd\x81\x19\xa1\x04\x56",
        .decimals = 18,
    },
    {
        .name = "BitDegree",
        .unit = "BDG",
        .contract_address =
            "\x19\x61\xb3\x33\x19\x69\xed\x52\x77\x07\x51\xfc\x71\x8e\xf5\x30\x83\x8b\x6d\xee",
        .decimals = 18,
    },
    {
        .name = "Bidesk",
        .unit = "BDK",
        .contract_address =
            "\xbf\xc1\x50\x2e\xbc\x37\x47\x5b\x94\x0c\xed\x8f\x03\x6b\x91\x01\x8a\x73\xc8\xf6",
        .decimals = 18,
    },
    {
        .name = "BEAT",
        .unit = "BEAT",
        .contract_address =
            "\x2f\xb1\x2b\xcc\xf6\xf5\xdd\x33\x8b\x76\xbe\x78\x4a\x93\xad\xe0\x72\x42\x56\x90",
        .decimals = 18,
    },
    {
        .name = "Bee Token",
        .unit = "BEE",
        .contract_address =
            "\x4d\x8f\xc1\x45\x3a\x0f\x35\x9e\x99\xc9\x67\x59\x54\xe6\x56\xd8\x0d\x99\x6f\xbf",
        .decimals = 18,
    },
    {
        .name = "BeeEx",
        .unit = "BEE",
        .contract_address =
            "\x17\x63\xad\x73\x69\x4d\x4d\x64\xfb\x71\x73\x2b\x06\x8e\x32\xac\x72\xa3\x45\xb1",
        .decimals = 18,
    },
    {
        .name = "Bela",
        .unit = "BELA",
        .contract_address =
            "\x2e\x98\xa6\x80\x4e\x4b\x6c\x83\x2e\xd0\xca\x87\x6a\x94\x3a\xbd\x34\x00\xb2\x24",
        .decimals = 18,
    },
    {
        .name = "BetProtocol",
        .unit = "BEPRO",
        .contract_address =
            "\x78\x60\x01\xc9\xc5\xca\x6e\x50\x2d\xeb\x8a\x8a\x72\x48\x0d\x21\x47\x89\x1f\x32",
        .decimals = 18,
    },
    {
        .name = "Rentberry",
        .unit = "BERRY",
        .contract_address =
            "\x6a\xeb\x95\xf0\x6c\xda\x84\xca\x34\x5c\x2d\xe0\xf3\xb7\xf9\x69\x23\xa4\x4f\x4c",
        .decimals = 14,
    },
    {
        .name = "Bitpanda Ecosystem Token",
        .unit = "BEST",
        .contract_address =
            "\x1b\x07\x33\x82\xe6\x34\x11\xe3\xbc\xff\xe9\x0a\xc1\xb9\xa4\x3f\xef\xa1\xec\x6f",
        .decimals = 8,
    },
    {
        .name = "Bethereum",
        .unit = "BETHER",
        .contract_address =
            "\x14\xc9\x26\xf2\x29\x00\x44\xb6\x47\xe1\xbf\x20\x72\xe6\x7b\x49\x5e\xff\x19\x05",
        .decimals = 18,
    },
    {
        .name = "BetterBetting",
        .unit = "BETR",
        .contract_address =
            "\x76\x31\x86\xeb\x8d\x48\x56\xd5\x36\xed\x44\x78\x30\x29\x71\x21\x4f\xeb\xc6\xa9",
        .decimals = 18,
    },
    {
        .name = "Bezop",
        .unit = "BEZ",
        .contract_address =
            "\x8a\x1e\x39\x30\xfd\xe1\xf1\x51\x47\x1c\x36\x8f\xdb\xb3\x9f\x3f\x63\xa6\x5b\x55",
        .decimals = 18,
    },
    {
        .name = "Bitfex",
        .unit = "BFX",
        .contract_address =
            "\xdb\x09\x6c\xc1\x9b\x82\x27\xe2\x11\x58\x55\xc5\xb3\x9d\xcc\x24\x74\x70\x01\x3c",
        .decimals = 18,
    },
    {
        .name = "BeeStore",
        .unit = "BHT",
        .contract_address =
            "\xa4\xfb\x38\x58\x20\xa9\xee\xf8\x42\xa4\x19\xe0\x8f\x85\x40\xfd\x7d\x1b\xf6\xe8",
        .decimals = 5,
    },
    {
        .name = "Bilaxy Token",
        .unit = "BIA",
        .contract_address =
            "\x40\xd5\x25\x77\x83\x0e\x01\xaa\xef\xa8\x06\x59\xaa\x90\xee\x8b\x34\x68\x5f\x4e",
        .decimals = 18,
    },
    {
        .name = "BIKI",
        .unit = "BIKI",
        .contract_address =
            "\x70\xde\xbc\xda\xb2\xef\x20\xbe\x3d\x1d\xbf\xf6\xa8\x45\xe9\xcc\xb6\xe4\x69\x30",
        .decimals = 8,
    },
    {
        .name = "Birdchain",
        .unit = "BIRD",
        .contract_address =
            "\x02\x6e\x62\xdd\xed\x1a\x6a\xd0\x7d\x93\xd3\x9f\x96\xb9\xea\xbd\x59\x66\x5e\x0d",
        .decimals = 18,
    },
    {
        .name = "BitRewards",
        .unit = "BIT",
        .contract_address =
            "\x47\xda\x42\x69\x6a\x86\x6c\xdc\x61\xa4\xc8\x09\xa5\x15\x50\x0a\x24\x29\x09\xc1",
        .decimals = 18,
    },
    {
        .name = "Bitcoinus",
        .unit = "BITS",
        .contract_address =
            "\xc3\x8f\x1f\xb4\x9a\xcd\xf2\xf1\x21\x3c\xaf\x33\x19\xf6\xeb\x3e\xa2\xcb\x75\x27",
        .decimals = 18,
    },
    {
        .name = "BITTO",
        .unit = "BITTO",
        .contract_address =
            "\xa1\x01\xe2\x7f\x06\xa9\x79\x85\xb9\x25\xe2\x44\x11\x1b\x61\x56\x0e\xcd\x97\xdb",
        .decimals = 18,
    },
    {
        .name = "BitScreener Token",
        .unit = "BITX",
        .contract_address =
            "\xff\x2b\x33\x53\xc3\x01\x5e\x9f\x1f\xbf\x95\xb9\xbd\xa2\x3f\x58\xaa\x7c\xe0\x07",
        .decimals = 18,
    },
    {
        .name = "BIZZCOIN",
        .unit = "BIZZ",
        .contract_address =
            "\x7a\x8c\xa2\xf8\x15\xa2\x60\x66\x01\x58\xa3\x8c\x34\xca\x32\x1a\x36\x05\xec\xfe",
        .decimals = 8,
    },
    {
        .name = "BeeKan",
        .unit = "BKBT",
        .contract_address =
            "\x6a\x27\x34\x84\x83\xd5\x91\x50\xae\x76\xef\x4c\x0f\x36\x22\xa7\x8b\x0c\xa6\x98",
        .decimals = 18,
    },
    {
        .name = "BKEX Token",
        .unit = "BKK",
        .contract_address =
            "\xd0\xbd\x12\xa8\xd5\xeb\xca\x1e\x2f\xa4\x6d\xa5\x9f\x19\x93\xec\x51\xc3\xd7\x5c",
        .decimals = 18,
    },
    {
        .name = "Blockcloud",
        .unit = "BLOC",
        .contract_address =
            "\x6f\x91\x9d\x67\x96\x7a\x97\xea\x36\x19\x5a\x23\x46\xd9\x24\x4e\x60\xfe\x0d\xdb",
        .decimals = 18,
    },
    {
        .name = "Blue Protocol",
        .unit = "BLUE",
        .contract_address =
            "\x53\x9e\xfe\x69\xbc\xdd\x21\xa8\x3e\xfd\x91\x22\x57\x1a\x64\xcc\x25\xe0\x28\x2b",
        .decimals = 8,
    },
    {
        .name = "BELIEVER",
        .unit = "BLVR",
        .contract_address =
            "\xd1\xef\x9a\x73\x10\xd0\x80\x68\x55\xc6\x72\x28\x8e\xf5\xa1\xba\xb6\x2c\xef\x33",
        .decimals = 18,
    },
    {
        .name = "Balloon-X",
        .unit = "BLX",
        .contract_address =
            "\x48\xfa\x42\xd5\x79\xce\x56\xcc\x27\x97\xe4\xd6\x78\xad\x73\x45\xa2\x79\x99\xb9",
        .decimals = 18,
    },
    {
        .name = "Blocery",
        .unit = "BLY",
        .contract_address =
            "\xf8\xad\x7d\xfe\x65\x61\x88\xa2\x3e\x89\xda\x09\x50\x6a\xdf\x7a\xd9\x29\x0d\x5d",
        .decimals = 18,
    },
    {
        .name = "BlockMesh",
        .unit = "BMH",
        .contract_address =
            "\xf0\x30\x45\xa4\xc8\x07\x7e\x38\xf3\xb8\xe2\xed\x33\xb8\xae\xe6\x9e\xdf\x86\x9f",
        .decimals = 18,
    },
    {
        .name = "Bananatok",
        .unit = "BNA",
        .contract_address =
            "\x20\x91\x0e\x5b\x5f\x08\x7f\x64\x39\xdf\xcb\x0d\xda\x4e\x27\xd1\x01\x4a\xc2\xb8",
        .decimals = 18,
    },
    {
        .name = "3X Short BNB Token",
        .unit = "BNBBEAR",
        .contract_address =
            "\x6f\xeb\xdf\xc0\xa9\xd9\x50\x2c\x45\x34\x3f\xce\x0d\xf0\x88\x28\xde\xf4\x47\x95",
        .decimals = 18,
    },
    {
        .name = "3X Long BNB Token",
        .unit = "BNBBULL",
        .contract_address =
            "\x9d\x1a\x62\xc2\xad\x99\x01\x97\x68\xb9\x12\x6f\xda\x00\x4a\x99\x52\x85\x3f\x6e",
        .decimals = 18,
    },
    {
        .name = "Bionic",
        .unit = "BNC",
        .contract_address =
            "\xef\x51\xc9\x37\x7f\xeb\x29\x85\x6e\x61\x62\x5c\xaf\x93\x90\xbd\x0b\x67\xea\x18",
        .decimals = 8,
    },
    {
        .name = "BlockNoteX",
        .unit = "BNOX",
        .contract_address =
            "\x87\x52\xbf\x7a\xd5\x3d\x25\xa4\x16\x5b\x93\x70\xf2\xbe\xcc\x22\xdd\x8a\xe8\x38",
        .decimals = 2,
    },
    {
        .name = "BenePit Protocol",
        .unit = "BNP",
        .contract_address =
            "\xd2\x7d\x76\xa1\xba\x55\xce\x5c\x02\x91\xcc\xd0\x4f\xeb\xbe\x79\x3d\x22\xeb\xf4",
        .decimals = 18,
    },
    {
        .name = "BNS Token",
        .unit = "BNS",
        .contract_address =
            "\xd9\x96\x03\x5d\xb8\x2c\xae\x33\xba\x1f\x16\xfd\xf2\x3b\x81\x6e\x5e\x9f\xaa\xbb",
        .decimals = 8,
    },
    {
        .name = "Bounty0x",
        .unit = "BNTY",
        .contract_address =
            "\xd2\xd6\x15\x86\x83\xae\xe4\xcc\x83\x80\x67\x72\x72\x09\xa0\xaa\xf4\x35\x9d\xe3",
        .decimals = 18,
    },
    {
        .name = "Bancacy",
        .unit = "BNY",
        .contract_address =
            "\x86\x14\x9c\x67\xe5\x7c\x74\x9d\x0a\x12\xe6\xd6\xc2\xbf\x1b\x61\x66\x19\xbb\x29",
        .decimals = 18,
    },
    {
        .name = "Bob's Repair",
        .unit = "BOB",
        .contract_address =
            "\xdf\x34\x79\x11\x91\x0b\x6c\x9a\x42\x86\xba\x8e\x2e\xe5\xea\x4a\x39\xeb\x21\x34",
        .decimals = 18,
    },
    {
        .name = "BOMB",
        .unit = "BOMB",
        .contract_address =
            "\x1c\x95\xb0\x93\xd6\xc2\x36\xd3\xef\x7c\x79\x6f\xe3\x3f\x9c\xc6\xb8\x60\x67\x14",
        .decimals = 0,
    },
    {
        .name = "Bonpay",
        .unit = "BON",
        .contract_address =
            "\xcc\x34\x36\x6e\x38\x42\xca\x1b\xd3\x6c\x1f\x32\x4d\x15\x25\x79\x60\xfc\xc8\x01",
        .decimals = 18,
    },
    {
        .name = "Bone",
        .unit = "BONE",
        .contract_address =
            "\x5c\x84\xbc\x60\xa7\x96\x53\x4b\xfe\xc3\x43\x9a\xf0\xe6\xdb\x61\x6a\x96\x63\x35",
        .decimals = 18,
    },
    {
        .name = "Bonk",
        .unit = "BONK",
        .contract_address =
            "\x6d\x65\x06\xe6\xf4\x38\xed\xe2\x69\x87\x7a\x0a\x72\x00\x26\x55\x91\x10\xb7\xd5",
        .decimals = 18,
    },
    {
        .name = "BOOM",
        .unit = "BOOM",
        .contract_address =
            "\xdb\x7e\xab\x9b\xa6\xbe\x88\xb8\x69\xf7\x38\xf6\xde\xeb\xa9\x6d\x49\xfe\x13\xfd",
        .decimals = 18,
    },
    {
        .name = "Bounce Token",
        .unit = "BOT",
        .contract_address =
            "\x5b\xea\xba\xeb\xb3\x14\x66\x85\xdd\x74\x17\x6f\x68\xa0\x72\x1f\x91\x29\x7d\x37",
        .decimals = 18,
    },
    {
        .name = "BoutsPro",
        .unit = "BOUTS",
        .contract_address =
            "\x13\x9d\x93\x97\x27\x4b\xb9\xe2\xc2\x9a\x9a\xa8\xaa\x0b\x58\x74\xd3\x0d\x62\xe3",
        .decimals = 18,
    },
    {
        .name = "Blockparty (BOXX Token)",
        .unit = "BOXX",
        .contract_address =
            "\x78\x01\x16\xd9\x1e\x55\x92\xe5\x8a\x3b\x3c\x76\xa3\x51\x57\x1b\x39\xab\xce\xc6",
        .decimals = 15,
    },
    {
        .name = "BlackPearl Token",
        .unit = "BPLC",
        .contract_address =
            "\x42\x6f\xc8\xbe\x95\x57\x32\x30\xf6\xe6\xbc\x4a\xf9\x18\x73\xf0\xc6\x7b\x21\xb4",
        .decimals = 18,
    },
    {
        .name = "BPOP",
        .unit = "BPOP",
        .contract_address =
            "\x04\x52\xae\xd8\x78\x80\x55\x14\xe2\x8f\xb5\xbd\x0b\x56\xbe\xf9\x21\x76\xe3\x2a",
        .decimals = 8,
    },
    {
        .name = "Blockchain Quotations Index Token",
        .unit = "BQT",
        .contract_address =
            "\x5e\xb8\x7c\xaa\x01\x05\xa6\x3a\xa8\x7a\x36\xc7\xbd\x25\x73\xbd\x13\xe8\x4f\xae",
        .decimals = 18,
    },
    {
        .name = "BROTHER",
        .unit = "BRAT",
        .contract_address =
            "\x9e\x77\xd5\xa1\x25\x1b\x6f\x7d\x45\x67\x22\xa6\xea\xc6\xd2\xd5\x98\x0b\xd8\x91",
        .decimals = 8,
    },
    {
        .name = "Brr",
        .unit = "BRR",
        .contract_address =
            "\x49\xf9\x41\xfa\x7f\x57\x31\xfe\x30\x20\x68\xd7\x9c\x86\x04\xc2\x4c\x5e\x71\x96",
        .decimals = 18,
    },
    {
        .name = "Brazilian Digital Token",
        .unit = "BRZ",
        .contract_address =
            "\x42\x04\x12\xe7\x65\xbf\xa6\xd8\x5a\xaa\xc9\x4b\x4f\x7b\x70\x8c\x89\xbe\x2e\x2b",
        .decimals = 4,
    },
    {
        .name = "Braziliex Token",
        .unit = "BRZX",
        .contract_address =
            "\xda\x51\x80\x08\x64\x61\xff\x6e\xeb\x09\x58\x01\x81\xac\x16\x05\x22\xdc\xdc\xd4",
        .decimals = 8,
    },
    {
        .name = "Bitsonic",
        .unit = "BSC",
        .contract_address =
            "\xe5\x41\x50\x44\x17\x67\x0f\xb7\x6b\x61\x2b\x41\xb4\x39\x2d\x96\x7a\x19\x56\xc7",
        .decimals = 18,
    },
    {
        .name = "BitcoinSoV",
        .unit = "BSOV",
        .contract_address =
            "\x26\x94\x6a\xda\x5e\xcb\x57\xf3\xa1\xf9\x16\x05\x05\x0c\xe4\x5c\x48\x2c\x9e\xb1",
        .decimals = 8,
    },
    {
        .name = "Bitsten Token",
        .unit = "BST",
        .contract_address =
            "\xd4\xf6\xf9\xae\x14\x39\x9f\xd5\xeb\x8d\xfc\x77\x25\xf0\x09\x4a\x1a\x7f\x5d\x80",
        .decimals = 18,
    },
    {
        .name = "BitStation",
        .unit = "BSTN",
        .contract_address =
            "\x2f\x84\x72\xdd\x7e\xcf\x7c\xa7\x60\xc8\xf6\xb4\x5d\xb2\x0c\xa7\xcf\x52\xf8\xd7",
        .decimals = 18,
    },
    {
        .name = "3x Short Bitcoin SV Token",
        .unit = "BSVBEAR",
        .contract_address =
            "\xce\x49\xc3\xc9\x2b\x33\xa1\x65\x3f\x34\x81\x1a\x9d\x7e\x34\x50\x2b\xf1\x2b\x89",
        .decimals = 18,
    },
    {
        .name = "3x Long Bitcoin SV Token",
        .unit = "BSVBULL",
        .contract_address =
            "\x6e\x13\xa9\xe4\xae\x3d\x06\x78\xe5\x11\xfb\x6d\x2a\xd5\x31\xfc\xf0\xe2\x47\xbf",
        .decimals = 18,
    },
    {
        .name = "BSYS",
        .unit = "BSYS",
        .contract_address =
            "\x30\x04\xcf\x8b\x4e\x28\xd6\x0f\x4e\x30\x5d\xf2\x5a\x57\xcd\x5f\xaf\x37\xb8\xd5",
        .decimals = 18,
    },
    {
        .name = "BitBall",
        .unit = "BTB",
        .contract_address =
            "\x06\xe0\xfe\xb0\xd7\x41\x06\xc7\xad\xa8\x49\x77\x54\x07\x4d\x22\x2e\xc6\xbc\xdf",
        .decimals = 18,
    },
    {
        .name = "PieDAO BTC++",
        .unit = "BTC++",
        .contract_address =
            "\x03\x27\x11\x24\x23\xf3\xa6\x8e\xfd\xf1\xfc\xf4\x02\xf6\xc5\xcb\x9f\x7c\x33\xfd",
        .decimals = 18,
    },
    {
        .name = "Amun Bitcoin 3x Daily Long",
        .unit = "BTC3L",
        .contract_address =
            "\x7e\x5f\x9f\x24\x8e\x84\xef\x0b\x1f\x63\x58\x63\x23\xe9\x2a\x0d\x91\xb1\x55\x68",
        .decimals = 18,
    },
    {
        .name = "Amun Bitcoin 3x Daily Short",
        .unit = "BTC3S",
        .contract_address =
            "\x11\x48\x66\x18\x69\xd3\x0e\x09\x5f\xf4\xaa\x48\xaa\x8b\x5e\xad\xed\xc7\x5f\x2a",
        .decimals = 18,
    },
    {
        .name = "Bitcoin Fast",
        .unit = "BTCF",
        .contract_address =
            "\x22\x59\x27\xf8\xfa\x71\xd1\x6e\xe0\x79\x68\xb8\x74\x63\x64\xd1\xd9\xf8\x39\xbd",
        .decimals = 8,
    },
    {
        .name = "BITCOINHEDGE",
        .unit = "BTCHG",
        .contract_address =
            "\x55\x47\x13\x6b\x91\x3b\x68\x88\x15\x96\x27\x5a\xce\x01\xe9\xa5\x89\xc5\xb1\x6b",
        .decimals = 18,
    },
    {
        .name = "BTC Lite",
        .unit = "BTCL",
        .contract_address =
            "\x5a\xcd\x19\xb9\xc9\x1e\x59\x6b\x1f\x06\x2f\x18\xe3\xd0\x2d\xa7\xed\x8d\x1e\x50",
        .decimals = 8,
    },
    {
        .name = "Bitcoin Red",
        .unit = "BTCRED",
        .contract_address =
            "\x6a\xac\x8c\xb9\x86\x1e\x42\xbf\x82\x59\xf5\xab\xdc\x6a\xe3\xae\x89\x90\x9e\x11",
        .decimals = 8,
    },
    {
        .name = "Bitcoin True",
        .unit = "BTCT",
        .contract_address =
            "\x82\x0a\x84\x81\x45\x1e\x89\x3b\xc6\x6d\xce\x50\xc8\x4d\x45\x61\x7c\xac\x37\x05",
        .decimals = 18,
    },
    {
        .name = "Bitscoin",
        .unit = "BTCX",
        .contract_address =
            "\x93\x88\xf5\x4f\xa9\x78\xaa\x9e\x24\x39\x5a\x8b\x69\x03\x33\x04\xec\xce\xa4\xdf",
        .decimals = 4,
    },
    {
        .name = "BitMax Token",
        .unit = "BTMX",
        .contract_address =
            "\xcc\xa0\xc9\xc3\x83\x07\x66\x49\x60\x4e\xe3\x1b\x20\x24\x8b\xc0\x4f\xdf\x61\xca",
        .decimals = 18,
    },
    {
        .name = "BitNautic Token",
        .unit = "BTNT",
        .contract_address =
            "\xc4\x5d\xbd\xf2\x88\x44\xfd\xb1\x48\x2c\x50\x28\x97\xd4\x33\xac\x08\xd6\xcc\xd0",
        .decimals = 18,
    },
    {
        .name = "Bitether",
        .unit = "BTR",
        .contract_address =
            "\x49\x9a\x6b\x77\xbc\x25\xc2\x6b\xcf\x82\x65\xe2\x10\x2b\x1b\x3d\xd1\x61\x70\x24",
        .decimals = 18,
    },
    {
        .name = "Biotron",
        .unit = "BTRN",
        .contract_address =
            "\x03\xc7\x80\xcd\x55\x45\x98\x59\x2b\x97\xb7\x25\x6d\xda\xad\x75\x99\x45\xb1\x25",
        .decimals = 18,
    },
    {
        .name = "Bitball Treasure",
        .unit = "BTRS",
        .contract_address =
            "\x73\xc9\x27\x5c\x3a\x2d\xd8\x4b\x57\x41\xfd\x59\xae\xbf\x10\x2c\x91\xeb\x03\x3f",
        .decimals = 18,
    },
    {
        .name = "BTS Coin",
        .unit = "BTSC",
        .contract_address =
            "\xba\x9e\xca\xa4\xd6\xf2\x2d\x3a\x69\xc4\x1d\xaa\x05\x84\xac\x0e\x24\x18\x92\x5e",
        .decimals = 18,
    },
    {
        .name = "Budbo",
        .unit = "BUBO",
        .contract_address =
            "\xcc\xbf\x21\xba\x6e\xf0\x08\x02\xab\x06\x63\x78\x96\xb7\x99\xf7\x10\x1f\x54\xa2",
        .decimals = 18,
    },
    {
        .name = "DFOhub",
        .unit = "BUIDL",
        .contract_address =
            "\xd6\xf0\xbb\x2a\x45\x11\x0f\x81\x9e\x90\x8a\x91\x52\x37\xd6\x52\xac\x7c\x5a\xa8",
        .decimals = 18,
    },
    {
        .name = "Bulleon",
        .unit = "BUL",
        .contract_address =
            "\x07\x75\xc8\x1a\x27\x3b\x35\x5e\x6a\x5b\x76\xe2\x40\xbf\x70\x87\x01\xf0\x02\x79",
        .decimals = 18,
    },
    {
        .name = "3X Long Shitcoin Index Token",
        .unit = "BULLSHIT",
        .contract_address =
            "\xd0\x6b\x25\xf6\x7a\x17\xf1\x2b\x41\xf6\x15\xb3\x4d\x87\xec\xd7\x16\xff\x55\xa0",
        .decimals = 18,
    },
    {
        .name = "BunnyToken",
        .unit = "BUNNY",
        .contract_address =
            "\x75\x5e\xb1\x4d\x2f\xef\xf2\x93\x9e\xb3\x02\x6f\x5c\xad\x9d\x03\x77\x5b\x9f\xf4",
        .decimals = 18,
    },
    {
        .name = "Blockburn",
        .unit = "BURN",
        .contract_address =
            "\x85\x15\xcd\x0f\x00\xad\x81\x99\x6d\x24\xb9\xa9\xc3\x51\x21\xa3\xb7\x59\xd6\xcd",
        .decimals = 18,
    },
    {
        .name = "BitUP Token",
        .unit = "BUT",
        .contract_address =
            "\xb2\xe2\x60\xf1\x24\x06\xc4\x01\x87\x4e\xcc\x96\x08\x93\xc0\xf7\x4c\xd6\xaf\xcd",
        .decimals = 18,
    },
    {
        .name = "1x Long Bitcoin Implied Volatility Token",
        .unit = "BVOL",
        .contract_address =
            "\x81\x82\x46\x63\x35\x3a\x9d\x29\xb0\x1b\x2d\xe9\xdd\x9a\x2b\xb2\x71\xd2\x98\xcd",
        .decimals = 18,
    },
    {
        .name = "Bittwatt",
        .unit = "BWT",
        .contract_address =
            "\xf5\x3c\x58\x0b\xc4\x06\x54\x05\xbc\x64\x9c\xc0\x77\xff\x4f\x2f\x28\x52\x8f\x4b",
        .decimals = 18,
    },
    {
        .name = "Blockchain Exchange Alliance",
        .unit = "BXA",
        .contract_address =
            "\x98\xd8\xd1\x46\xe6\x44\x17\x1c\xd4\x7f\xf8\x58\x89\x87\xb7\xbd\xee\xf7\x2a\x87",
        .decimals = 18,
    },
    {
        .name = "BonusCloud",
        .unit = "BXC",
        .contract_address =
            "\xde\xcf\x7b\xe2\x9f\x88\x32\xe9\xc2\xdd\xf0\x38\x8c\x97\x78\xb8\xba\x76\xaf\x43",
        .decimals = 18,
    },
    {
        .name = "Beaxy",
        .unit = "BXY",
        .contract_address =
            "\x82\x7d\x53\xc8\x17\x0a\xf5\x26\x25\xf4\x14\xbd\xe0\x03\x26\xfc\x8a\x08\x5e\x86",
        .decimals = 18,
    },
    {
        .name = "bZx Protocol",
        .unit = "BZRX",
        .contract_address =
            "\x56\xd8\x11\x08\x82\x35\xf1\x1c\x89\x20\x69\x8a\x20\x4a\x50\x10\xa7\x88\xf4\xb3",
        .decimals = 18,
    },
    {
        .name = "Bloomzed Token",
        .unit = "BZT",
        .contract_address =
            "\x0d\x55\x16\x10\x37\x52\xb3\x95\x4d\x95\x62\x1f\x47\x0a\x82\x61\x15\x1d\xa2\xe4",
        .decimals = 18,
    },
    {
        .name = "Carboneum [C8] Token",
        .unit = "C8",
        .contract_address =
            "\xd4\x2d\xeb\xe4\xed\xc9\x2b\xd5\xa3\xfb\xb4\x24\x3e\x1e\xcc\xf6\xd6\x3a\x4a\x5d",
        .decimals = 18,
    },
    {
        .name = "Global Crypto Alliance",
        .unit = "CALL",
        .contract_address =
            "\xbb\xe7\x61\xea\x14\x47\xa2\x0b\x75\xaa\x48\x5b\x7b\xca\xd4\x83\x74\x15\xd7\xd7",
        .decimals = 18,
    },
    {
        .name = "Cappasity",
        .unit = "CAPP",
        .contract_address =
            "\x04\xf2\xe7\x22\x1f\xdb\x1b\x52\xa6\x81\x69\xb2\x57\x93\xe5\x14\x78\xff\x03\x29",
        .decimals = 2,
    },
    {
        .name = "CARAT",
        .unit = "CARAT",
        .contract_address =
            "\x19\xea\x63\x0b\xcb\xc1\xa5\x11\xa1\x6e\x65\xb6\xec\xd4\x47\xc9\x2e\x1c\x08\x7c",
        .decimals = 18,
    },
    {
        .name = "Cardstack",
        .unit = "CARD",
        .contract_address =
            "\x95\x4b\x89\x07\x04\x69\x3a\xf2\x42\x61\x3e\xde\xf1\xb6\x03\x82\x5a\xfc\xd7\x08",
        .decimals = 18,
    },
    {
        .name = "BitClave",
        .unit = "CAT",
        .contract_address =
            "\x12\x34\x56\x74\x61\xd3\xf8\xdb\x74\x96\x58\x17\x74\xbd\x86\x9c\x83\xd5\x1c\x93",
        .decimals = 18,
    },
    {
        .name = "BlockCAT",
        .unit = "CAT",
        .contract_address =
            "\x56\xba\x2e\xe7\x89\x04\x61\xf4\x63\xf7\xbe\x02\xaa\xc3\x09\x9f\x6d\x58\x11\xa8",
        .decimals = 18,
    },
    {
        .name = "Catex Token",
        .unit = "CATT",
        .contract_address =
            "\x6e\x60\x5c\x26\x9e\x0c\x92\xe7\x0b\xee\xb8\x54\x86\xf1\xfc\x55\x0f\x93\x80\xbd",
        .decimals = 18,
    },
    {
        .name = "CryptoBossCoin",
        .unit = "CBC",
        .contract_address =
            "\x79\x0b\xfa\xca\xe7\x15\x76\x10\x7c\x06\x8f\x49\x4c\x8a\x63\x02\xae\xa6\x40\xcb",
        .decimals = 18,
    },
    {
        .name = "CashBackPro",
        .unit = "CBP",
        .contract_address =
            "\x6f\x4e\xe0\x3c\xa6\xc9\x42\xc9\x39\x7d\x2b\xa5\xf8\xf8\x3e\xa5\x8f\x91\x8f\x47",
        .decimals = 18,
    },
    {
        .name = "Cybercoin",
        .unit = "CBR",
        .contract_address =
            "\x4b\xa0\x12\xf6\xe4\x11\xa1\xbe\x55\xb9\x8e\x9e\x62\xc3\xa4\xce\xb1\x6e\xc8\x8b",
        .decimals = 18,
    },
    {
        .name = "CRYPTOBUCKS",
        .unit = "CBUCKS",
        .contract_address =
            "\x0d\x2b\xb9\xd6\x8d\xd4\x45\x1a\x09\xec\x94\xc0\x5e\x20\xbd\x39\x50\x22\xbd\x8e",
        .decimals = 2,
    },
    {
        .name = "Coin Controller Cash",
        .unit = "CCC",
        .contract_address =
            "\x94\xcb\x81\x5f\x4b\x60\x1b\x00\xb3\x63\xb3\x17\x7b\x4d\x8e\xd8\xe0\xeb\x7c\xf2",
        .decimals = 18,
    },
    {
        .name = "Coinchase Token",
        .unit = "CCH",
        .contract_address =
            "\x40\xad\xfc\x7c\x23\xc2\x2c\xc0\x6f\x94\xf1\x99\xa4\x75\x0d\x71\x96\xf4\x6f\xbe",
        .decimals = 6,
    },
    {
        .name = "CYCLEAN",
        .unit = "CCL",
        .contract_address =
            "\x74\x9f\x35\xff\x65\x93\x2e\x68\x26\x7d\xd8\x2f\x6c\xd8\x5e\xea\x73\x5d\x70\x0e",
        .decimals = 18,
    },
    {
        .name = "CustomContractNetwork",
        .unit = "CCN",
        .contract_address =
            "\x17\xb2\x64\x00\x62\x16\x95\xc2\xd8\xc2\xd8\x86\x9f\x62\x59\xe8\x2d\x75\x44\xc4",
        .decimals = 18,
    },
    {
        .name = "Ccore",
        .unit = "CCO",
        .contract_address =
            "\x67\x9b\xad\xc5\x51\x62\x6e\x01\xb2\x3c\xee\xce\xfb\xc9\xb8\x77\xea\x18\xfc\x46",
        .decimals = 18,
    },
    {
        .name = "Crystal Clear ",
        .unit = "CCT",
        .contract_address =
            "\x33\x6f\x64\x6f\x87\xd9\xf6\xbc\x6e\xd4\x2d\xd4\x6e\x8b\x3f\xd9\xdb\xd1\x5c\x22",
        .decimals = 18,
    },
    {
        .name = "Commerce Data Connection",
        .unit = "CDC",
        .contract_address =
            "\x87\x02\x6f\x79\x2d\x09\x96\x02\x32\xca\x40\x6e\x80\xc8\x9b\xd3\x5b\xaf\xe5\x66",
        .decimals = 18,
    },
    {
        .name = "CoinDeal Token",
        .unit = "CDL",
        .contract_address =
            "\xcb\x17\xcd\x35\x7c\x7a\xcd\x59\x47\x17\xd8\x99\xec\xb9\xdf\x54\x0f\x63\x3f\x27",
        .decimals = 18,
    },
    {
        .name = "CDX Network",
        .unit = "CDX",
        .contract_address =
            "\x6f\xff\x38\x06\xbb\xac\x52\xa2\x0e\x0d\x79\xbc\x53\x8d\x52\x7f\x6a\x22\xc9\x6b",
        .decimals = 18,
    },
    {
        .name = "Celsius",
        .unit = "CEL",
        .contract_address =
            "\xaa\xae\xbe\x6f\xe4\x8e\x54\xf4\x31\xb0\xc3\x90\xcf\xaf\x0b\x01\x7d\x09\xd4\x2d",
        .decimals = 4,
    },
    {
        .name = "Coinsuper Ecosystem Network",
        .unit = "CEN",
        .contract_address =
            "\x0b\xc6\x1d\xde\xd5\xf6\x71\x0c\x63\x7c\xf8\x28\x8e\xb6\x05\x87\x66\xce\x19\x21",
        .decimals = 18,
    },
    {
        .name = "CRYPTOFOREX",
        .unit = "CFX",
        .contract_address =
            "\x22\x6f\x15\xcd\xba\xa3\x68\x14\xce\x3c\xb2\x87\x56\x30\x69\xc3\x2c\xc1\xa2\x93",
        .decimals = 2,
    },
    {
        .name = "CACHE Gold",
        .unit = "CGT",
        .contract_address =
            "\xf5\x23\x84\x62\xe7\x23\x5c\x7b\x62\x81\x15\x67\xe6\x3d\xd1\x7d\x12\xc2\xea\xa0",
        .decimals = 8,
    },
    {
        .name = "Chess Coin",
        .unit = "CHESS",
        .contract_address =
            "\x5f\x75\x11\x2b\xbb\x4e\x1a\xf5\x16\xfb\xe3\xe2\x15\x28\xc6\x3d\xa2\xb6\xa1\xa5",
        .decimals = 18,
    },
    {
        .name = "Crypto Holding Frank Token",
        .unit = "CHFT",
        .contract_address =
            "\x58\x00\x2a\x6b\x6e\x65\x9a\x16\xde\x9f\x02\xf5\x29\xb1\x05\x36\xe3\x07\xb0\xd9",
        .decimals = 18,
    },
    {
        .name = "CoinHe Token",
        .unit = "CHT",
        .contract_address =
            "\x32\x77\xdd\x53\x64\x71\xa3\xcb\xeb\x0c\x94\x86\xac\xad\x49\x4c\x95\xa3\x1e\x73",
        .decimals = 18,
    },
    {
        .name = "Cipher Core Token",
        .unit = "CIPHC",
        .contract_address =
            "\x83\xeb\x94\xcb\x56\x31\x46\xa4\x2f\xe0\xa8\xb3\xd0\x51\xf2\x38\x7a\x7f\xb8\x1f",
        .decimals = 8,
    },
    {
        .name = "ConnectJob",
        .unit = "CJT",
        .contract_address =
            "\x3a\xbd\xff\x32\xf7\x6b\x42\xe7\x63\x5b\xdb\x7e\x42\x5f\x02\x31\xa5\xf3\xab\x17",
        .decimals = 18,
    },
    {
        .name = "Coinlancer",
        .unit = "CL",
        .contract_address =
            "\xe8\x1d\x72\xd1\x4b\x15\x16\xe6\x8a\xc3\x19\x0a\x46\xc9\x33\x02\xcc\x8e\xd6\x0f",
        .decimals = 18,
    },
    {
        .name = "Cloudbric",
        .unit = "CLB",
        .contract_address =
            "\xb1\xc1\xcb\x8c\x7c\x19\x92\xdb\xa2\x4e\x62\x8b\xf7\xd3\x8e\x71\xda\xd4\x6a\xeb",
        .decimals = 18,
    },
    {
        .name = "Colu Local Network",
        .unit = "CLN",
        .contract_address =
            "\x41\x62\x17\x8b\x78\xd6\x98\x54\x80\xa3\x08\xb2\x19\x0e\xe5\x51\x74\x60\x40\x6d",
        .decimals = 18,
    },
    {
        .name = "BLOCKCLOUT",
        .unit = "CLOUT",
        .contract_address =
            "\xa1\x0a\xe5\x43\xdb\x5d\x96\x7a\x73\xe9\xab\xcc\x69\xc8\x1a\x18\xa7\xfc\x0a\x78",
        .decimals = 18,
    },
    {
        .name = "CoinLoan",
        .unit = "CLT",
        .contract_address =
            "\x20\x01\xf2\xa0\xcf\x80\x1e\xcf\xda\x62\x2f\x6c\x28\xfb\x6e\x10\xd8\x03\xd9\x69",
        .decimals = 8,
    },
    {
        .name = "Celeum",
        .unit = "CLX",
        .contract_address =
            "\x9f\x8f\x7e\xa5\x04\x58\x8a\x58\xb8\xb2\x4b\x83\x2b\x5d\x25\xa4\xae\xb4\x70\x6f",
        .decimals = 18,
    },
    {
        .name = "Crowd Machine",
        .unit = "CMCT",
        .contract_address =
            "\x47\xbc\x01\x59\x77\x98\xdc\xd7\x50\x6d\xcc\xa3\x6a\xc4\x30\x2f\xc9\x3a\x8c\xfb",
        .decimals = 8,
    },
    {
        .name = "Cyber Movie Chain",
        .unit = "CMCT",
        .contract_address =
            "\x7a\xbc\x60\xb3\x29\x0f\x68\xc8\x5f\x49\x5f\xd2\xe0\xc3\xbd\x27\x88\x37\xa3\x13",
        .decimals = 8,
    },
    {
        .name = "COMSA [ETH]",
        .unit = "CMS",
        .contract_address =
            "\xf8\x33\x01\xc5\xcd\x1c\xcb\xb8\x6f\x46\x6a\x6b\x3c\x53\x31\x6e\xd2\xf8\x46\x5a",
        .decimals = 6,
    },
    {
        .name = "Coinsbit Token",
        .unit = "CNB",
        .contract_address =
            "\xc5\x38\x14\x32\x02\xf3\xb1\x13\x82\xd8\x60\x6a\xae\x90\xa9\x6b\x04\x2a\x19\xdb",
        .decimals = 18,
    },
    {
        .name = "CNNS",
        .unit = "CNNS",
        .contract_address =
            "\x6c\x3b\xe4\x06\x17\x43\x49\xcf\xa4\x50\x16\x54\x31\x3d\x97\xe6\xa3\x10\x72\xe1",
        .decimals = 18,
    },
    {
        .name = "CryptoEnergy",
        .unit = "CNRG",
        .contract_address =
            "\xc2\x1d\xbe\xe6\x5d\x62\x77\x09\x53\x03\x5f\x04\x34\xc5\x32\xd5\x78\xa6\x66\xc9",
        .decimals = 18,
    },
    {
        .name = "Connectome",
        .unit = "CNTM",
        .contract_address =
            "\x9a\x1b\xf3\x61\x79\x8e\xf6\x53\x8c\xcb\x81\x37\xea\x90\x0c\x4d\x4b\x48\xca\x3d",
        .decimals = 18,
    },
    {
        .name = "CoinUs",
        .unit = "CNUS",
        .contract_address =
            "\x72\x2f\x2f\x3e\xac\x7e\x95\x97\xc7\x3a\x59\x3f\x7c\xf3\xde\x33\xfb\xfc\x33\x08",
        .decimals = 18,
    },
    {
        .name = "Cofinex Coin",
        .unit = "CNX",
        .contract_address =
            "\xe0\xb7\xe8\x82\xc1\x94\x88\x1c\x69\x09\x24\xcb\x46\x15\x4b\x82\x41\xf9\x14\x5e",
        .decimals = 18,
    },
    {
        .name = "Coinzo Token",
        .unit = "CNZ",
        .contract_address =
            "\xc1\x96\x5d\x7d\x18\xf3\x70\x62\xb1\x8a\xb3\xd5\xd1\xfe\x7f\x69\x87\x3b\x30\xdd",
        .decimals = 18,
    },
    {
        .name = "Cobinhood",
        .unit = "COB",
        .contract_address =
            "\xb2\xf7\xeb\x1f\x2c\x37\x64\x5b\xe6\x1d\x73\x95\x30\x35\x36\x0e\x76\x8d\x81\xe6",
        .decimals = 18,
    },
    {
        .name = "Codeo Token",
        .unit = "CODEO",
        .contract_address =
            "\x46\xb4\xa7\xd9\x06\xf1\xa9\x43\xb7\x74\x4d\xf2\x36\x25\xe6\x37\x26\xd7\x90\x35",
        .decimals = 18,
    },
    {
        .name = "CoinFi",
        .unit = "COFI",
        .contract_address =
            "\x31\x36\xef\x85\x15\x92\xac\xf4\x9c\xa4\xc8\x25\x13\x1e\x36\x41\x70\xfa\x32\xb3",
        .decimals = 18,
    },
    {
        .name = "Unit Protocol",
        .unit = "COL",
        .contract_address =
            "\xc7\x6f\xb7\x59\x50\x53\x6d\x98\xfa\x62\xea\x96\x8e\x1d\x6b\x45\xff\xea\x2a\x55",
        .decimals = 18,
    },
    {
        .name = "Compound",
        .unit = "COMP",
        .contract_address =
            "\xc0\x0e\x94\xcb\x66\x2c\x35\x20\x28\x2e\x6f\x57\x17\x21\x40\x04\xa7\xf2\x68\x88",
        .decimals = 18,
    },
    {
        .name = "Coni",
        .unit = "CONI",
        .contract_address =
            "\x2c\x94\x91\x99\xcf\xf1\x4a\xea\xf1\xb3\x3d\x64\xdb\x01\xf4\x8f\xb5\x7f\x59\x2f",
        .decimals = 8,
    },
    {
        .name = "CoTrader",
        .unit = "COT",
        .contract_address =
            "\x5c\x87\x25\x00\xc0\x05\x65\x50\x5f\x36\x24\xab\x43\x5c\x22\x2e\x55\x8e\x9f\xf8",
        .decimals = 18,
    },
    {
        .name = "Couchain",
        .unit = "COU",
        .contract_address =
            "\xf0\x91\xcf\x09\xc5\x18\x11\x81\x9d\xb7\x05\x71\x0e\x96\x34\xb8\xbf\x18\xf1\x64",
        .decimals = 18,
    },
    {
        .name = "COVA",
        .unit = "COVA",
        .contract_address =
            "\xb3\x7a\x76\x9b\x37\x22\x44\x49\xd9\x2a\xac\x57\xde\x37\x9e\x12\x67\xcd\x3b\x00",
        .decimals = 18,
    },
    {
        .name = "Cashpayz Token",
        .unit = "CPC",
        .contract_address =
            "\x28\xea\x81\xfa\xc7\xb1\x71\x91\x38\xcb\xf6\x12\x67\x19\x81\x55\xb4\x33\xe0\x0e",
        .decimals = 8,
    },
    {
        .name = "CryptoAds Marketplace",
        .unit = "CRAD",
        .contract_address =
            "\x60\x8f\x00\x6b\x68\x13\xf9\x70\x97\x37\x2d\x0d\x31\xfb\x0f\x11\xd1\xca\x3e\x4e",
        .decimals = 18,
    },
    {
        .name = "CryCash",
        .unit = "CRC",
        .contract_address =
            "\xf4\x1e\x5f\xbc\x2f\x6a\xac\x20\x0d\xd8\x61\x9e\x12\x1c\xe1\xf0\x5d\x15\x00\x77",
        .decimals = 18,
    },
    {
        .name = "CryptalDash",
        .unit = "CRD",
        .contract_address =
            "\xca\xaa\x93\x71\x2b\xda\xc3\x7f\x73\x6c\x32\x3c\x93\xd4\xd5\xfd\xef\xcc\x31\xcc",
        .decimals = 18,
    },
    {
        .name = "CRDT",
        .unit = "CRDT",
        .contract_address =
            "\xda\xab\x5e\x69\x5b\xb0\xe8\xce\x83\x84\xee\x56\xba\x38\xfa\x82\x90\x61\x8e\x52",
        .decimals = 18,
    },
    {
        .name = "Cybereits",
        .unit = "CRE",
        .contract_address =
            "\x61\xf3\x3d\xa4\x05\x94\xce\xc1\xe3\xdc\x90\x0f\xaf\x99\xf8\x61\xd0\x1e\x2e\x7d",
        .decimals = 18,
    },
    {
        .name = "Cream Finance",
        .unit = "CREAM",
        .contract_address =
            "\x2b\xa5\x92\xf7\x8d\xb6\x43\x65\x27\x72\x99\x29\xaa\xf6\xc9\x08\x49\x7c\xb2\x00",
        .decimals = 18,
    },
    {
        .name = "Verify",
        .unit = "CRED",
        .contract_address =
            "\x67\x2a\x1a\xd4\xf6\x67\xfb\x18\xa3\x33\xaf\x13\x66\x7a\xa0\xaf\x1f\x5b\x5b\xdd",
        .decimals = 18,
    },
    {
        .name = "CONTRACOIN",
        .unit = "CTCN",
        .contract_address =
            "\xfd\x6c\x31\xbb\x6f\x05\xfc\x8d\xb6\x4f\x4b\x74\x0a\xb7\x58\x60\x5c\x27\x1f\xd8",
        .decimals = 18,
    },
    {
        .name = "Cryptrust",
        .unit = "CTRT",
        .contract_address =
            "\x86\x06\xa8\xf2\x8e\x1e\x2f\xd5\x0b\x90\x74\xd6\x5c\x01\x54\x8b\x1f\x04\x0b\x32",
        .decimals = 8,
    },
    {
        .name = "Cartesi",
        .unit = "CTSI",
        .contract_address =
            "\x49\x16\x04\xc0\xfd\xf0\x83\x47\xdd\x1f\xa4\xee\x06\x2a\x82\x2a\x5d\xd0\x6b\x5d",
        .decimals = 18,
    },
    {
        .name = "Castweet",
        .unit = "CTT",
        .contract_address =
            "\x1a\x47\x43\xcf\x1a\xf4\xc2\x89\x35\x13\x90\xa2\xb3\xfe\x7c\x13\xd2\xf7\xc2\x35",
        .decimals = 18,
    },
    {
        .name = "CITEX Token",
        .unit = "CTT",
        .contract_address =
            "\x13\xc2\xb7\xf8\x51\xe7\x56\x41\x5c\xf7\xd5\x1d\x04\xdc\xf4\xf9\x4a\x5b\x38\x2e",
        .decimals = 18,
    },
    {
        .name = "Curio",
        .unit = "CUR",
        .contract_address =
            "\x13\x33\x9f\xd0\x79\x34\xcd\x67\x42\x69\x72\x6e\xdf\x3b\x5c\xce\xe9\xdd\x93\xde",
        .decimals = 18,
    },
    {
        .name = "Custody Token",
        .unit = "CUST",
        .contract_address =
            "\xf6\xab\xff\x61\x60\x43\xc2\xda\x57\x25\x73\xdc\xc5\x83\xb6\x56\x29\x7b\x30\xe7",
        .decimals = 18,
    },
    {
        .name = "CryptoWorldNews",
        .unit = "CWN",
        .contract_address =
            "\xab\x7b\x6f\x7b\xea\xe1\xf0\x3a\x6b\x2a\x7f\x94\xd1\xac\x33\x2f\xc9\xbe\x34\x10",
        .decimals = 18,
    },
    {
        .name = "CargoX",
        .unit = "CXO",
        .contract_address =
            "\xb6\xee\x96\x68\x77\x1a\x79\xbe\x79\x67\xee\x29\xa6\x3d\x41\x84\xf8\x09\x71\x43",
        .decimals = 18,
    },
    {
        .name = "CYBR Token",
        .unit = "CYBR",
        .contract_address =
            "\xae\xaa\xbb\x69\xdc\xb0\xfe\x92\x6b\x19\x79\xf0\xb0\x32\xfc\xd1\x7f\xd7\xb2\xe0",
        .decimals = 18,
    },
    {
        .name = "CyberFM",
        .unit = "CYFM",
        .contract_address =
            "\x3f\x06\xb5\xd7\x84\x06\xcd\x97\xbd\xf1\x0f\x5c\x42\x0b\x24\x1d\x32\x75\x9c\x80",
        .decimals = 18,
    },
    {
        .name = "Crystal Token",
        .unit = "CYL",
        .contract_address =
            "\x26\xcb\x36\x41\xaa\xa4\x39\x11\xf1\xd4\xcb\x2c\xe5\x44\xeb\x65\x2a\xac\x7c\x47",
        .decimals = 18,
    },
    {
        .name = "DABANKING",
        .unit = "DAB",
        .contract_address =
            "\x5e\x7e\xbe\xa6\x8a\xb0\x51\x98\xf7\x71\xd7\x7a\x87\x54\x80\x31\x4f\x1d\x0a\xae",
        .decimals = 18,
    },
    {
        .name = "DACC",
        .unit = "DACC",
        .contract_address =
            "\xf8\xc5\x95\xd0\x70\xd1\x04\x37\x7f\x58\x71\x5c\xe2\xe6\xc9\x3e\x49\xa8\x7f\x3c",
        .decimals = 6,
    },
    {
        .name = "DAD",
        .unit = "DAD",
        .contract_address =
            "\x5b\x32\x25\x14\xff\x72\x72\x53\x29\x26\x37\xd9\x05\x43\x01\x60\x0c\x2c\x81\xe8",
        .decimals = 9,
    },
    {
        .name = "Dalecoin",
        .unit = "DALC",
        .contract_address =
            "\x07\xd9\xe4\x9e\xa4\x02\x19\x4b\xf4\x8a\x82\x76\xda\xfb\x16\xe4\xed\x63\x33\x17",
        .decimals = 8,
    },
    {
        .name = "Datamine",
        .unit = "DAM",
        .contract_address =
            "\xf8\x0d\x58\x9b\x3d\xbe\x13\x0c\x27\x0a\x69\xf1\xa6\x9d\x05\x0f\x26\x87\x86\xdf",
        .decimals = 18,
    },
    {
        .name = "Daneel",
        .unit = "DAN",
        .contract_address =
            "\x9b\x70\x74\x0e\x70\x8a\x08\x3c\x6f\xf3\x8d\xf5\x22\x97\x02\x0f\x5d\xfa\xa5\xee",
        .decimals = 10,
    },
    {
        .name = "Dapp Token",
        .unit = "DAPPT",
        .contract_address =
            "\x38\x6c\xab\xc0\xb1\x4a\x50\x7a\x4e\x02\x4d\xea\x15\x55\x43\x42\x86\x5b\x20\xde",
        .decimals = 18,
    },
    {
        .name = "DAPS Coin",
        .unit = "DAPS",
        .contract_address =
            "\x93\x19\x0d\xbc\xe9\xb9\xbd\x4a\xa5\x46\x27\x0a\x8d\x1d\x65\x90\x5b\x5f\xdd\x28",
        .decimals = 18,
    },
    {
        .name = "Datum",
        .unit = "DAT",
        .contract_address =
            "\x81\xc9\x15\x1d\xe0\xc8\xba\xfc\xd3\x25\xa5\x7e\x3d\xb5\xa5\xdf\x1c\xeb\xf7\x9c",
        .decimals = 18,
    },
    {
        .name = "Decentralized Asset Trading Platform",
        .unit = "DATP",
        .contract_address =
            "\x81\x3b\x42\x8a\xf3\x92\x02\x26\xe0\x59\xb6\x8a\x62\xe4\xc0\x49\x33\xd4\xea\x7a",
        .decimals = 8,
    },
    {
        .name = "DATx",
        .unit = "DATX",
        .contract_address =
            "\xab\xbb\xb6\x44\x7b\x68\xff\xd6\x14\x1d\xa7\x7c\x18\xc7\xb5\x87\x6e\xd6\xc5\xab",
        .decimals = 18,
    },
    {
        .name = "DAV Coin",
        .unit = "DAV",
        .contract_address =
            "\xd8\x2d\xf0\xab\xd3\xf5\x14\x25\xeb\x15\xef\x75\x80\xfd\xa5\x57\x27\x87\x5f\x14",
        .decimals = 18,
    },
    {
        .name = "Dawn Protocol",
        .unit = "DAWN",
        .contract_address =
            "\x58\x0c\x85\x20\xde\xda\x0a\x44\x15\x22\xae\xae\x0f\x9f\x7a\x5f\x29\x62\x9a\xfa",
        .decimals = 18,
    },
    {
        .name = "DAEX",
        .unit = "DAX",
        .contract_address =
            "\x0b\x4b\xdc\x47\x87\x91\x89\x72\x74\x65\x2d\xc1\x5e\xf5\xc1\x35\xca\xe6\x1e\x60",
        .decimals = 18,
    },
    {
        .name = "Chronologic",
        .unit = "DAY",
        .contract_address =
            "\xe8\x14\xae\xe9\x60\xa8\x52\x08\xc3\xdb\x54\x2c\x53\xe7\xd4\xa6\xc8\xd5\xf6\x0f",
        .decimals = 18,
    },
    {
        .name = "Decentralized Crypto Token",
        .unit = "DCTO",
        .contract_address =
            "\x9c\xcb\xd0\x5d\x4d\x25\xc7\x45\xd4\x9f\x5e\x6b\xf1\x7e\x09\x11\x3e\xb4\xc7\x69",
        .decimals = 18,
    },
    {
        .name = "Decentralized Data Assets Management",
        .unit = "DDAM",
        .contract_address =
            "\xd5\xdc\x89\x21\xa5\xc5\x8f\xb0\xeb\xa6\xdb\x6b\x40\xea\xb4\x02\x83\xdc\x3c\x01",
        .decimals = 9,
    },
    {
        .name = "DigiDinar Token",
        .unit = "DDRT",
        .contract_address =
            "\x94\x50\x1b\x6a\x15\x3c\x89\x73\xfd\x1f\x32\x1f\xcc\x81\x88\xd4\x0d\xc5\xd7\x2d",
        .decimals = 8,
    },
    {
        .name = "Debitum",
        .unit = "DEB",
        .contract_address =
            "\x15\x12\x02\xc9\xc1\x8e\x49\x56\x56\xf3\x72\x28\x1f\x49\x3e\xb7\x69\x89\x61\xd5",
        .decimals = 18,
    },
    {
        .name = "DeepCloud AI",
        .unit = "DEEP",
        .contract_address =
            "\x6c\xbe\xde\xc4\xf1\xac\x9d\x87\x49\x87\xd2\x76\x95\x96\x54\x4e\x0d\x91\x61\xab",
        .decimals = 18,
    },
    {
        .name = "DeltaChain",
        .unit = "DELTA",
        .contract_address =
            "\xde\x1e\x0a\xe6\x10\x1b\x46\x52\x0c\xf6\x6f\xdc\x0b\x10\x59\xc5\xcc\x3d\x10\x6c",
        .decimals = 8,
    },
    {
        .name = "DEAPcoin",
        .unit = "DEP",
        .contract_address =
            "\x1a\x34\x96\xc1\x8d\x55\x8b\xd9\xc6\xc8\xf6\x09\xe1\xb1\x29\xf6\x7a\xb0\x81\x63",
        .decimals = 18,
    },
    {
        .name = "Dev Protocol",
        .unit = "DEV",
        .contract_address =
            "\x5c\xaf\x45\x4b\xa9\x2e\x6f\x2c\x92\x9d\xf1\x46\x67\xee\x36\x0e\xd9\xfd\x5b\x26",
        .decimals = 18,
    },
    {
        .name = "DEXA COIN",
        .unit = "DEXA",
        .contract_address =
            "\x72\x54\x40\x51\x2c\xb7\xb7\x8b\xf5\x6b\x33\x4e\x50\xe3\x17\x07\x41\x82\x31\xcb",
        .decimals = 18,
    },
    {
        .name = "DEXTools",
        .unit = "DEXT",
        .contract_address =
            "\x26\xce\x25\x14\x88\x32\xc0\x4f\x3d\x7f\x26\xf3\x24\x78\xa9\xfe\x55\x19\x71\x66",
        .decimals = 18,
    },
    {
        .name = "dForce",
        .unit = "DF",
        .contract_address =
            "\x43\x1a\xd2\xff\x6a\x9c\x36\x58\x05\xeb\xad\x47\xee\x02\x11\x48\xd6\xf7\xdb\xe0",
        .decimals = 18,
    },
    {
        .name = "Fantasy Sports",
        .unit = "DFS",
        .contract_address =
            "\xce\xc3\x83\x06\x55\x8a\x31\xcd\xbb\x2a\x9d\x62\x85\x94\x7c\x5b\x44\xa2\x4f\x3e",
        .decimals = 18,
    },
    {
        .name = "DigiFinexToken",
        .unit = "DFT",
        .contract_address =
            "\xa2\xa5\x4f\x1e\xc1\xf0\x93\x16\xef\x12\xc1\x77\x0d\x32\xed\x8f\x21\xb1\xfb\x6a",
        .decimals = 8,
    },
    {
        .name = "DIA",
        .unit = "DIA",
        .contract_address =
            "\x84\xca\x8b\xc7\x99\x72\x72\xc7\xcf\xb4\xd0\xcd\x3d\x55\xcd\x94\x2b\x3c\x94\x19",
        .decimals = 18,
    },
    {
        .name = "D Community",
        .unit = "DILI",
        .contract_address =
            "\x37\xf7\x4e\x99\x79\x48\x53\x77\x7a\x10\xea\x1d\xc0\x8a\x64\xc8\x69\x58\xf0\x6a",
        .decimals = 18,
    },
    {
        .name = "Digital Insurance Token",
        .unit = "DIT",
        .contract_address =
            "\xf1\x49\x22\x00\x1a\x2f\xb8\x54\x1a\x43\x39\x05\x43\x7a\xe9\x54\x41\x9c\x24\x39",
        .decimals = 8,
    },
    {
        .name = "dKargo",
        .unit = "DKA",
        .contract_address =
            "\x5d\xc6\x0c\x4d\x5e\x75\xd2\x25\x88\xfa\x17\xff\xeb\x90\xa6\x3e\x53\x5e\xfc\xe0",
        .decimals = 18,
    },
    {
        .name = "DMM: Governance",
        .unit = "DMG",
        .contract_address =
            "\xed\x91\x87\x99\x19\xb7\x1b\xb6\x90\x5f\x23\xaf\x0a\x68\xd2\x31\xec\xf8\x7b\x14",
        .decimals = 18,
    },
    {
        .name = "Decentralized Machine Learning",
        .unit = "DML",
        .contract_address =
            "\xbc\xdf\xe3\x38\xd5\x5c\x06\x1c\x08\x4d\x81\xfd\x79\x3d\xed\x00\xa2\x7f\x22\x6d",
        .decimals = 18,
    },
    {
        .name = "DMme",
        .unit = "DMME",
        .contract_address =
            "\x95\x56\xf8\xee\x79\x5d\x99\x1f\xf3\x71\xf5\x47\x16\x2d\x5e\xfb\x27\x69\x42\x5f",
        .decimals = 18,
    },
    {
        .name = "DMScript",
        .unit = "DMST",
        .contract_address =
            "\xf2\x99\x92\xd7\xb5\x89\xa0\xa6\xbd\x2d\xe7\xbe\x29\xa9\x7a\x6e\xb7\x3e\xaf\x85",
        .decimals = 18,
    },
    {
        .name = "EncrypGen",
        .unit = "DNA",
        .contract_address =
            "\x82\xb0\xe5\x04\x78\xee\xaf\xde\x39\x2d\x45\xd1\x25\x9e\xd1\x07\x1b\x6f\xda\x81",
        .decimals = 18,
    },
    {
        .name = "Donut",
        .unit = "DONUT",
        .contract_address =
            "\xc0\xf9\xbd\x5f\xa5\x69\x8b\x65\x05\xf6\x43\x90\x0f\xfa\x51\x5e\xa5\xdf\x54\xa9",
        .decimals = 18,
    },
    {
        .name = "DOS Network",
        .unit = "DOS",
        .contract_address =
            "\x70\x86\x1e\x86\x2e\x1a\xc0\xc9\x6f\x85\x3c\x82\x31\x82\x6e\x46\x9e\xad\x37\xb1",
        .decimals = 18,
    },
    {
        .name = "Dovu",
        .unit = "DOV",
        .contract_address =
            "\xac\x32\x11\xa5\x02\x54\x14\xaf\x28\x66\xff\x09\xc2\x3f\xc1\x8b\xc9\x7e\x79\xb1",
        .decimals = 18,
    },
    {
        .name = "DOWCOIN",
        .unit = "DOW",
        .contract_address =
            "\x76\x97\x4c\x7b\x79\xdc\x8a\x6a\x10\x9f\xd7\x1f\xd7\xce\xb9\xe4\x0e\xff\x53\x82",
        .decimals = 18,
    },
    {
        .name = "Delphy",
        .unit = "DPY",
        .contract_address =
            "\x6c\x2a\xdc\x20\x73\x99\x4f\xb2\xcc\xc5\x03\x2c\xc2\x90\x6f\xa2\x21\xe9\xb3\x91",
        .decimals = 18,
    },
    {
        .name = "Dragonbit",
        .unit = "DRGB",
        .contract_address =
            "\x9d\x3e\x08\x92\xd1\x1f\x19\xf5\x18\x1d\x4a\x4c\x5d\x04\x18\x7a\x9e\x0d\x70\x32",
        .decimals = 18,
    },
    {
        .name = "3X Long Dragon Index Token",
        .unit = "DRGNBULL",
        .contract_address =
            "\x33\x35\xf1\x6a\xf9\x00\x8b\xfd\x32\xf1\xee\x6c\x2b\xe5\xd4\xf8\x4f\xa0\xb9\xda",
        .decimals = 18,
    },
    {
        .name = "DoDreamChain",
        .unit = "DRM",
        .contract_address =
            "\x89\x55\x1b\x94\x0e\x2a\x8e\xd8\xec\xcf\x50\x99\x35\xba\xc9\x21\x3f\xe3\x05\x84",
        .decimals = 18,
    },
    {
        .name = "DomRaider",
        .unit = "DRT",
        .contract_address =
            "\x9a\xf4\xf2\x69\x41\x67\x7c\x70\x6c\xfe\xcf\x6d\x33\x79\xff\x01\xbb\x85\xd5\xab",
        .decimals = 8,
    },
    {
        .name = "DeFi Nation Signals DAO",
        .unit = "DSD",
        .contract_address =
            "\x1e\x3a\x24\x46\xc7\x29\xd3\x43\x73\xb8\x7f\xd2\xc9\xcb\xb3\x9a\x93\x19\x86\x58",
        .decimals = 18,
    },
    {
        .name = "DSLA Protocol",
        .unit = "DSLA",
        .contract_address =
            "\x3a\xff\xcc\xa6\x4c\x2a\x6f\x4e\x3b\x6b\xd9\xc6\x4c\xd2\xc9\x69\xef\xd1\xec\xbe",
        .decimals = 18,
    },
    {
        .name = "DSYS",
        .unit = "DSYS",
        .contract_address =
            "\x10\xa3\x4b\xbe\x9b\x3c\x5a\xd5\x36\xca\x23\xd5\xee\xfa\x81\xca\x44\x8e\x92\xff",
        .decimals = 18,
    },
    {
        .name = "Dether",
        .unit = "DTH",
        .contract_address =
            "\x5a\xdc\x96\x1d\x6a\xc3\xf7\x06\x2d\x2e\xa4\x5f\xef\xb8\xd8\x16\x7d\x44\xb1\x90",
        .decimals = 18,
    },
    {
        .name = "DTOP Token",
        .unit = "DTOP",
        .contract_address =
            "\x54\xad\x74\xed\xea\xb4\x8e\x09\xcc\xc4\x3e\xe3\x24\xf2\x60\x30\x71\xda\xd7\x2b",
        .decimals = 18,
    },
    {
        .name = "Datarius Credit",
        .unit = "DTRC",
        .contract_address =
            "\xc2\x04\x64\xe0\xc3\x73\x48\x6d\x2b\x33\x35\x57\x6e\x83\xa2\x18\xb1\x61\x8a\x5e",
        .decimals = 18,
    },
    {
        .name = "Databroker",
        .unit = "DTX",
        .contract_address =
            "\x76\x5f\x0c\x16\xd1\xdd\xc2\x79\x29\x5c\x1a\x7c\x24\xb0\x88\x3f\x62\xd3\x3f\x75",
        .decimals = 18,
    },
    {
        .name = "DUO Network Token",
        .unit = "DUO",
        .contract_address =
            "\x56\xe0\xb2\xc7\x69\x4e\x6e\x10\x39\x1e\x87\x07\x74\xda\xa4\x5c\xf6\x58\x34\x86",
        .decimals = 18,
    },
    {
        .name = "DragonVein",
        .unit = "DVC",
        .contract_address =
            "\x19\x45\x24\x35\x5f\x26\xaf\x66\x34\x68\xd4\x99\x6f\x20\x7a\x91\x8c\x73\xe0\x13",
        .decimals = 8,
    },
    {
        .name = "Decentralized Vulnerability Platform",
        .unit = "DVP",
        .contract_address =
            "\x8e\x30\xea\x23\x29\xd9\x58\x02\xfd\x80\x4f\x42\x91\x22\x0b\x0e\x2f\x57\x98\x12",
        .decimals = 18,
    },
    {
        .name = "Derivex",
        .unit = "DVX",
        .contract_address =
            "\x97\x57\x69\x55\x75\x10\x16\x7d\x25\xbe\xed\x6e\x32\x80\x65\x37\x17\x3e\x29\x2c",
        .decimals = 18,
    },
    {
        .name = "DWS",
        .unit = "DWS",
        .contract_address =
            "\xf4\xb5\x48\x74\xcd\x8a\x6c\x86\x3e\x3a\x90\x4c\x18\xfd\xa9\x64\x66\x1e\xc3\x63",
        .decimals = 18,
    },
    {
        .name = "DXdao",
        .unit = "DXD",
        .contract_address =
            "\xa1\xd6\x5e\x8f\xb6\xe8\x7b\x60\xfe\xcc\xbc\x58\x2f\x7f\x97\x80\x4b\x72\x55\x21",
        .decimals = 18,
    },
    {
        .name = "Dexter G",
        .unit = "DXG",
        .contract_address =
            "\x45\x71\xf3\xa3\x86\xd1\xbd\x18\xe2\x5d\x70\xd1\x17\xe7\x06\x7f\xa0\xbd\x9d\x08",
        .decimals = 18,
    },
    {
        .name = "Datawallet",
        .unit = "DXT",
        .contract_address =
            "\x8d\xb5\x4c\xa5\x69\xd3\x01\x9a\x2b\xa1\x26\xd0\x3c\x37\xc4\x4b\x5e\xf8\x1e\xf6",
        .decimals = 8,
    },
    {
        .name = "Dynamite",
        .unit = "DYNMT",
        .contract_address =
            "\x3b\x7f\x24\x7f\x21\xbf\x3a\x07\x08\x8c\x2d\x34\x23\xf6\x42\x33\xd4\xb0\x69\xf7",
        .decimals = 2,
    },
    {
        .name = "DoYourTip",
        .unit = "DYT",
        .contract_address =
            "\x74\x06\x23\xd2\xc7\x97\xb7\xd8\xd1\xec\xb9\x8e\x9b\x4a\xfc\xf9\x9e\xc3\x1e\x14",
        .decimals = 18,
    },
    {
        .name = "Digital Rand",
        .unit = "DZAR",
        .contract_address =
            "\x9c\xb2\xf2\x6a\x23\xb8\xd8\x99\x73\xf0\x8c\x95\x7c\x4d\x7c\xdf\x75\xcd\x34\x1c",
        .decimals = 6,
    },
    {
        .name = "EBCoin",
        .unit = "EBC",
        .contract_address =
            "\x31\xf3\xd9\xd1\xbe\xce\x0c\x03\x3f\xf7\x8f\xa6\xda\x60\xa6\x04\x8f\x3e\x13\xc5",
        .decimals = 18,
    },
    {
        .name = "eBitcoin",
        .unit = "EBTC",
        .contract_address =
            "\xeb\x7c\x20\x02\x71\x72\xe5\xd1\x43\xfb\x03\x0d\x50\xf9\x1c\xec\xe2\xd1\x48\x5d",
        .decimals = 8,
    },
    {
        .name = "Echoin",
        .unit = "EC",
        .contract_address =
            "\x12\xfd\x19\xda\xc0\xfa\xb6\x1b\xed\x5e\x0f\x09\x09\x1b\x47\x0c\x45\x2d\x4d\x61",
        .decimals = 18,
    },
    {
        .name = "Ethereum Cash",
        .unit = "ECASH",
        .contract_address =
            "\x5d\x21\xef\x5f\x25\xa9\x85\x38\x0b\x65\xc8\xe9\x43\xa0\x08\x2f\xed\xa0\xdb\x84",
        .decimals = 18,
    },
    {
        .name = "e-Chat",
        .unit = "ECHT",
        .contract_address =
            "\x1a\x22\x77\xc8\x39\x30\xb7\xa6\x4c\x3e\x3d\x55\x44\xea\xa8\xc4\xf9\x46\xb1\xb7",
        .decimals = 18,
    },
    {
        .name = "Omnitude",
        .unit = "ECOM",
        .contract_address =
            "\x17\x1d\x75\x0d\x42\xd6\x61\xb6\x2c\x27\x7a\x6b\x48\x6a\xdb\x82\x34\x8c\x3e\xca",
        .decimals = 18,
    },
    {
        .name = "EurocoinToken",
        .unit = "ECTE",
        .contract_address =
            "\xe9\xfa\x21\xe6\x71\xbc\xfb\x04\xe6\x86\x87\x84\xb8\x9c\x19\xd5\xaa\x24\x24\xea",
        .decimals = 18,
    },
    {
        .name = "ECOSC",
        .unit = "ECU",
        .contract_address =
            "\x8f\xc9\xb6\x35\x4e\x83\x9a\xb1\xc8\xb3\x1f\x4a\xfa\x53\x60\x70\x92\xb8\xc2\xe5",
        .decimals = 18,
    },
    {
        .name = "Decurian",
        .unit = "ECU",
        .contract_address =
            "\xd3\xcd\xc4\xe7\x57\x50\xdc\x1e\x59\xf8\x34\x22\x00\x74\x2b\x6b\x29\x49\x0e\x70",
        .decimals = 3,
    },
    {
        .name = "Edgeless",
        .unit = "EDG",
        .contract_address =
            "\x08\x71\x1d\x3b\x02\xc8\x75\x8f\x2f\xb3\xab\x4e\x80\x22\x84\x18\xa7\xf8\xe3\x9c",
        .decimals = 0,
    },
    {
        .name = "Freight Trust & Clearing Network",
        .unit = "EDI",
        .contract_address =
            "\x79\xc5\xa1\xae\x58\x63\x22\xa0\x7b\xfb\x60\xbe\x36\xe1\xb3\x1c\xe8\xc8\x4a\x1e",
        .decimals = 18,
    },
    {
        .name = "EduCoin",
        .unit = "EDU",
        .contract_address =
            "\xf2\x63\x29\x2e\x14\xd9\xd8\xec\xd5\x5b\x58\xda\xd1\xf1\xdf\x82\x5a\x87\x4b\x7c",
        .decimals = 18,
    },
    {
        .name = "Ethereum eRush",
        .unit = "EER",
        .contract_address =
            "\x3c\xc5\xeb\x07\xe0\xe1\x22\x76\x13\xf1\xdf\x58\xf3\x8b\x54\x98\x23\xd1\x1c\xb9",
        .decimals = 18,
    },
    {
        .name = "EcoG9coin",
        .unit = "EGC",
        .contract_address =
            "\xc0\xec\x8c\xae\xc5\x5f\x37\xd4\x7f\xbf\xa5\x95\x72\x74\x18\x86\x8a\x21\xfd\x48",
        .decimals = 8,
    },
    {
        .name = "Engine",
        .unit = "EGCC",
        .contract_address =
            "\xaf\x8a\x21\x5e\x81\xfa\xea\x7c\x18\x0c\xe2\x2b\x72\x48\x35\x25\x12\x18\x13\xbd",
        .decimals = 18,
    },
    {
        .name = "Nestree",
        .unit = "EGG",
        .contract_address =
            "\x65\xcc\xd7\x2c\x08\x13\xce\x6f\x27\x03\x59\x3b\x63\x32\x02\xa0\xf3\xca\x6a\x0c",
        .decimals = 18,
    },
    {
        .name = "Egoras",
        .unit = "EGR",
        .contract_address =
            "\x73\xce\xe8\x34\x8b\x9b\xdd\x48\xc6\x4e\x13\x45\x2b\x8a\x6f\xbc\x81\x63\x05\x73",
        .decimals = 18,
    },
    {
        .name = "EchoLink",
        .unit = "EKO",
        .contract_address =
            "\xa6\xa8\x40\xe5\x0b\xca\xa5\x0d\xa0\x17\xb9\x1a\x0d\x86\xb8\xb2\xd4\x11\x56\xee",
        .decimals = 18,
    },
    {
        .name = "ELYSIA",
        .unit = "EL",
        .contract_address =
            "\x27\x81\x24\x6f\xe7\x07\xbb\x15\xce\xe3\xe5\xea\x35\x4e\x21\x54\xa2\x87\x7b\x16",
        .decimals = 18,
    },
    {
        .name = "Elamachain",
        .unit = "ELAMA",
        .contract_address =
            "\xfb\x44\x4c\x1f\x2b\x71\x8d\xdf\xc3\x85\xcb\x8f\xd9\xf2\xd1\xd7\x76\xb2\x46\x68",
        .decimals = 18,
    },
    {
        .name = "Electrum Dark",
        .unit = "ELD",
        .contract_address =
            "\x79\x6e\x47\xb8\x5a\x0d\x75\x9f\x30\x0f\x1d\xe9\x6a\x35\x83\x00\x42\x35\xd4\xd8",
        .decimals = 18,
    },
    {
        .name = "Electrify.Asia",
        .unit = "ELEC",
        .contract_address =
            "\xd4\x9f\xf1\x36\x61\x45\x13\x13\xca\x15\x53\xfd\x69\x54\xbd\x1d\x9b\x6e\x02\xb9",
        .decimals = 18,
    },
    {
        .name = "Elementeum",
        .unit = "ELET",
        .contract_address =
            "\x6c\x37\xbf\x4f\x04\x27\x12\xc9\x78\xa7\x3e\x3f\xd5\x6d\x1f\x57\x38\xdd\x7c\x43",
        .decimals = 18,
    },
    {
        .name = "ELTCOIN",
        .unit = "ELTCOIN",
        .contract_address =
            "\x44\x19\x7a\x4c\x44\xd6\xa0\x59\x29\x7c\xaf\x6b\xe4\xf7\xe1\x72\xbd\x56\xca\xaf",
        .decimals = 8,
    },
    {
        .name = "Elysian",
        .unit = "ELY",
        .contract_address =
            "\xa9\x55\x92\xdc\xff\xa3\xc0\x80\xb4\xb4\x0e\x45\x9c\x5f\x56\x92\xf6\x7d\xb7\xf8",
        .decimals = 18,
    },
    {
        .name = "Ethereum Message Search",
        .unit = "EMS",
        .contract_address =
            "\x17\xe6\x61\x6c\x45\xd2\x67\xbc\x20\xa9\x89\x2b\x58\xa0\x16\x21\xc5\x92\xb7\x2d",
        .decimals = 18,
    },
    {
        .name = "ENTONE",
        .unit = "ENTONE",
        .contract_address =
            "\xec\x1a\x71\x8d\x1a\x6f\x8f\x8d\x94\xec\xec\x6f\xe9\x14\x65\x69\x7b\xb2\xb8\x8c",
        .decimals = 8,
    },
    {
        .name = "EnterCoin",
        .unit = "ENTRC",
        .contract_address =
            "\xd9\xd0\x1d\x4c\xb8\x24\x21\x9a\x8f\x48\x2a\x0f\xad\x47\x9c\xb9\x71\xfd\x06\x28",
        .decimals = 8,
    },
    {
        .name = "EUNOMIA",
        .unit = "ENTS",
        .contract_address =
            "\x0f\x61\x2a\x09\xea\xd5\x5b\xb8\x1b\x65\x34\xe8\x0e\xd5\xa2\x1b\xf0\xa2\x7b\x16",
        .decimals = 8,
    },
    {
        .name = "EOS TRUST",
        .unit = "EOST",
        .contract_address =
            "\x87\x21\x0f\x1d\x34\x22\xba\x75\xb6\xc4\x0c\x63\xc7\x8d\x79\x32\x4d\xab\xcd\x55",
        .decimals = 18,
    },
    {
        .name = "Emphy",
        .unit = "EPY",
        .contract_address =
            "\x50\xee\x67\x46\x89\xd7\x5c\x0f\x88\xe8\xf8\x3c\xfe\x8c\x4b\x69\xe8\xfd\x59\x0d",
        .decimals = 8,
    },
    {
        .name = "QuadrantProtocol",
        .unit = "EQUAD",
        .contract_address =
            "\xc2\x8e\x93\x18\x14\x72\x5b\xbe\xb9\xe6\x70\x67\x6f\xab\xbc\xb6\x94\xfe\x7d\xf2",
        .decimals = 18,
    },
    {
        .name = "Eroscoin",
        .unit = "ERO",
        .contract_address =
            "\x74\xce\xda\x77\x28\x1b\x33\x91\x42\xa3\x68\x17\xfa\x5f\x9e\x29\x41\x2b\xab\x85",
        .decimals = 8,
    },
    {
        .name = "Eristica",
        .unit = "ERT",
        .contract_address =
            "\x92\xa5\xb0\x4d\x0e\xd5\xd9\x4d\x7a\x19\x3d\x1d\x33\x4d\x3d\x16\x99\x6f\x4e\x13",
        .decimals = 18,
    },
    {
        .name = "Era Swap",
        .unit = "ES",
        .contract_address =
            "\xef\x13\x44\xbd\xf8\x0b\xef\x3f\xf4\x42\x8d\x8b\xec\xec\x3e\xea\x4a\x2c\xf5\x74",
        .decimals = 18,
    },
    {
        .name = "Escroco Emerald",
        .unit = "ESCE",
        .contract_address =
            "\x49\x61\x46\x61\x73\x7e\xfb\xfc\x6a\x10\x2e\xfa\xee\xfd\xc8\xe1\x97\xf7\xcc\x0e",
        .decimals = 8,
    },
    {
        .name = "Switch",
        .unit = "ESH",
        .contract_address =
            "\xd6\xa5\x5c\x63\x86\x5a\xff\xd6\x7e\x2f\xb9\xf2\x84\xf8\x7b\x7a\x9e\x5f\xf3\xbd",
        .decimals = 18,
    },
    {
        .name = "Essentia",
        .unit = "ESS",
        .contract_address =
            "\xfc\x05\x98\x7b\xd2\xbe\x48\x9a\xcc\xf0\xf5\x09\xe4\x4b\x01\x45\xd6\x82\x40\xf7",
        .decimals = 18,
    },
    {
        .name = "Esports Token",
        .unit = "EST",
        .contract_address =
            "\x18\xf5\xb4\x90\x8e\x88\x61\xe3\x11\x4b\xa9\xa0\xa9\xa4\xe8\x4c\x5f\x18\x0c\xc0",
        .decimals = 9,
    },
    {
        .name = "EasySwap",
        .unit = "ESWA",
        .contract_address =
            "\xa0\x47\x1c\xdd\x5c\x0d\xc2\x61\x45\x35\xfd\x75\x05\xb1\x7a\x65\x1a\x8f\x0d\xab",
        .decimals = 8,
    },
    {
        .name = "EtherSportz",
        .unit = "ESZ",
        .contract_address =
            "\xe8\xa1\xdf\x95\x8b\xe3\x79\x04\x5e\x2b\x46\xa3\x1a\x98\xb9\x3a\x2e\xcd\xfd\xed",
        .decimals = 18,
    },
    {
        .name = "3X Long Ethereum Classic Token",
        .unit = "ETCBULL",
        .contract_address =
            "\x97\x4c\x98\xbc\x2e\x82\xfa\x18\xde\x92\xb7\xe6\x97\xa1\xd9\xbd\x25\x68\x2e\x80",
        .decimals = 18,
    },
    {
        .name = "Entherfound",
        .unit = "ETF",
        .contract_address =
            "\xc2\xb5\x88\x12\xc2\x40\x20\xea\x92\x4c\x3d\x7c\x24\x1c\x44\x16\x05\xf1\x2e\x75",
        .decimals = 8,
    },
    {
        .name = "Ethereum Gold",
        .unit = "ETG",
        .contract_address =
            "\x28\xc8\xd0\x1f\xf6\x33\xea\x9c\xd8\xfc\x6a\x45\x1d\x74\x57\x88\x9e\x69\x8d\xe6",
        .decimals = 0,
    },
    {
        .name = "Ethereum Gold Project",
        .unit = "ETGP",
        .contract_address =
            "\xa9\x6f\x31\xf1\xc1\x87\xc2\x89\x80\x17\x6c\x3a\x27\xba\x70\x69\xf4\x8a\xbd\xe4",
        .decimals = 8,
    },
    {
        .name = "Amun Ether 3x Daily Long",
        .unit = "ETH3L",
        .contract_address =
            "\x23\x9b\x0f\xa9\x17\xd8\x5c\x21\xcf\x64\x35\x46\x4c\x2c\x6a\xa3\xd4\x5f\x67\x20",
        .decimals = 18,
    },
    {
        .name = "EtherBone",
        .unit = "ETHBN",
        .contract_address =
            "\x96\xb5\x2b\x5b\xf8\xd9\x02\x25\x2d\x07\x14\xa1\xbd\x26\x51\xa7\x85\xfd\x26\x60",
        .decimals = 18,
    },
    {
        .name = "1X Short Ethereum Token",
        .unit = "ETHHEDGE",
        .contract_address =
            "\x10\xe1\xe9\x53\xdd\xba\x59\x70\x11\xf8\xbf\xa8\x06\xab\x0c\xc3\x41\x5a\x62\x2b",
        .decimals = 18,
    },
    {
        .name = "Ethereum Meta",
        .unit = "ETHM",
        .contract_address =
            "\x34\x0e\xf8\x3e\xc8\x56\x08\x92\x16\x8d\x40\x62\x72\x0f\x03\x04\x60\x46\x86\x56",
        .decimals = 18,
    },
    {
        .name = "ETHPlus",
        .unit = "ETHP",
        .contract_address =
            "\xee\xd7\x36\xb2\xb8\x09\x55\x0d\x89\xa9\x41\xc2\x00\x5d\xe9\x35\x88\xc6\x28\xe2",
        .decimals = 18,
    },
    {
        .name = "ETHplode",
        .unit = "ETHPLO",
        .contract_address =
            "\xe0\xc6\xce\x3e\x73\x02\x9f\x20\x1e\x5c\x0b\xed\xb9\x7f\x67\x57\x2a\x93\x71\x1c",
        .decimals = 6,
    },
    {
        .name = "EnergiToken",
        .unit = "ETK",
        .contract_address =
            "\x3c\x4a\x3f\xfd\x81\x3a\x10\x7f\xeb\xd5\x7b\x2f\x01\xbc\x34\x42\x64\xd9\x0f\xde",
        .decimals = 2,
    },
    {
        .name = "En-Tan-Mo",
        .unit = "ETM",
        .contract_address =
            "\x60\x20\xda\x0f\x7c\x18\x57\xdb\xe4\x43\x1e\xc9\x2a\x15\xcc\x31\x8d\x93\x3e\xaa",
        .decimals = 18,
    },
    {
        .name = "Essek Tov",
        .unit = "ETO",
        .contract_address =
            "\x45\x26\xdc\x4a\xc8\xf6\x92\x53\x5e\xd9\xbf\x23\x5a\x3a\x20\xa2\xb9\xff\x33\x28",
        .decimals = 18,
    },
    {
        .name = "Egoras Dollar",
        .unit = "EUSD",
        .contract_address =
            "\xa9\x0c\x43\xe0\xd6\xc9\x2b\x8e\x61\x71\xa8\x29\xbe\xb3\x8b\xe2\x8a\x0a\xd0\x73",
        .decimals = 18,
    },
    {
        .name = "EventChain",
        .unit = "EVC",
        .contract_address =
            "\xb6\x2d\x18\xde\xa7\x40\x45\xe8\x22\x35\x2c\xe4\xb3\xee\x77\x31\x9d\xc5\xff\x2f",
        .decimals = 18,
    },
    {
        .name = "Eva Cash",
        .unit = "EVC",
        .contract_address =
            "\xba\x14\xb2\x45\xd4\x49\x96\x5b\xdb\xeb\x63\x0e\xbe\x13\x5b\x56\x94\x74\xf5\xb1",
        .decimals = 6,
    },
    {
        .name = "Devery",
        .unit = "EVE",
        .contract_address =
            "\x92\x31\x08\xa4\x39\xc4\xe8\xc2\x31\x5c\x4f\x65\x21\xe5\xce\x95\xb4\x4e\x9b\x4c",
        .decimals = 18,
    },
    {
        .name = "Evedo",
        .unit = "EVED",
        .contract_address =
            "\x5a\xae\xfe\x84\xe0\xfb\x3d\xd1\xf0\xfc\xff\x6f\xa7\x46\x81\x24\x98\x6b\x91\xbd",
        .decimals = 18,
    },
    {
        .name = "EvenCoin",
        .unit = "EVN",
        .contract_address =
            "\x68\x90\x9e\x58\x6e\xea\xc8\xf4\x73\x15\xe8\x4b\x4c\x97\x88\xdd\x54\xef\x65\xbb",
        .decimals = 18,
    },
    {
        .name = "8X8 PROTOCOL",
        .unit = "EXE",
        .contract_address =
            "\x41\x2d\x39\x7d\xdc\xa0\x7d\x75\x3e\x3e\x0c\x61\xe3\x67\xfb\x1b\x47\x4b\x3e\x7d",
        .decimals = 18,
    },
    {
        .name = "EXRNchain",
        .unit = "EXRN",
        .contract_address =
            "\xe4\x69\xc4\x47\x3a\xf8\x22\x17\xb3\x0c\xf1\x7b\x10\xbc\xdb\x6c\x8c\x79\x6e\x75",
        .decimals = 0,
    },
    {
        .name = "Experty",
        .unit = "EXY",
        .contract_address =
            "\x5c\x74\x3a\x35\xe9\x03\xf6\xc5\x84\x51\x4e\xc6\x17\xac\xee\x06\x11\xcf\x44\xf3",
        .decimals = 18,
    },
    {
        .name = "EYES Protocol",
        .unit = "EYES",
        .contract_address =
            "\x2d\xca\x19\xe9\x44\x45\x3e\x46\xd9\x13\x09\x50\xca\x13\x54\x61\xb3\xbc\x0c\x30",
        .decimals = 18,
    },
    {
        .name = "EZOOW",
        .unit = "EZW",
        .contract_address =
            "\x78\xa2\xa1\x02\x9e\x31\x68\xb4\x9d\x3a\x27\x6c\x78\x70\x50\xff\x51\x06\xdc\xf2",
        .decimals = 18,
    },
    {
        .name = "EzyStayz",
        .unit = "EZY",
        .contract_address =
            "\xa6\xd5\xc7\x20\xa9\xaf\x5a\x40\x5d\xfb\x6b\x9f\x44\xfc\x44\xfa\xb5\xd4\xa5\x8d",
        .decimals = 8,
    },
    {
        .name = "Future1coin",
        .unit = "F1C",
        .contract_address =
            "\xb0\xa0\xa0\x70\x64\x0b\x45\x0e\xb1\x36\xdc\x37\x72\x08\x46\x9e\xe4\xf4\x9f\xbc",
        .decimals = 18,
    },
    {
        .name = "Faceter",
        .unit = "FACE",
        .contract_address =
            "\x1c\xca\xa0\xf2\xa7\x21\x0d\x76\xe1\xfd\xec\x74\x0d\x5f\x32\x3e\x2e\x1b\x16\x72",
        .decimals = 18,
    },
    {
        .name = "FairGame",
        .unit = "FAIR",
        .contract_address =
            "\x9b\x20\xda\xbc\xec\x77\xf6\x28\x91\x13\xe6\x18\x93\xf7\xbe\xef\xae\xb1\x99\x0a",
        .decimals = 18,
    },
    {
        .name = "FANBI TOKEN",
        .unit = "FBT",
        .contract_address =
            "\x7a\x97\x16\x68\x5f\x85\x2e\xe2\x68\xfe\xb8\x6d\xff\xa5\x62\xd2\x14\xcc\x13\xdb",
        .decimals = 6,
    },
    {
        .name = "FirmaChain",
        .unit = "FCT",
        .contract_address =
            "\xe1\xba\xd9\x22\xf8\x4b\x19\x8a\x08\x29\x2f\xb6\x00\x31\x93\x00\xae\x32\x47\x1b",
        .decimals = 18,
    },
    {
        .name = "Friendz",
        .unit = "FDZ",
        .contract_address =
            "\x23\x35\x20\x36\xe9\x11\xa2\x2c\xfc\x69\x2b\x5e\x2e\x19\x66\x92\x65\x8a\xde\xd9",
        .decimals = 18,
    },
    {
        .name = "Fesschain",
        .unit = "FESS",
        .contract_address =
            "\xe0\x93\x94\xf8\xba\x64\x24\x30\xed\x44\x8c\xa2\x0f\x34\x2e\xc7\xaa\x1b\xa2\xe1",
        .decimals = 18,
    },
    {
        .name = "FidexToken",
        .unit = "FEX",
        .contract_address =
            "\x1c\x1c\x14\xa6\xb5\x07\x49\x05\xce\x5d\x36\x7b\x0a\x7e\x09\x8b\x58\xeb\xfd\x47",
        .decimals = 8,
    },
    {
        .name = "FEX Token",
        .unit = "FEX",
        .contract_address =
            "\x27\x12\x20\xfb\xef\xd5\x84\xa6\xb0\xa6\xad\x45\x77\x21\xc0\x76\x32\x16\x46\xa1",
        .decimals = 18,
    },
    {
        .name = "Two Prime FF1 Token",
        .unit = "FF1",
        .contract_address =
            "\x59\xaf\x03\x56\xcd\xeb\xd1\xfa\x23\xae\x5d\xad\xff\x91\x70\xbb\xfc\x31\x27\x8c",
        .decimals = 18,
    },
    {
        .name = "Force For Fast",
        .unit = "FFF",
        .contract_address =
            "\x22\xf0\x98\xf0\x8c\x4e\xda\x4b\xe4\xad\x6b\x4b\xa5\x98\x66\xf3\xe9\x8c\xef\x92",
        .decimals = 18,
    },
    {
        .name = "Fireball",
        .unit = "FIRE",
        .contract_address =
            "\x3f\x8a\x2f\x7b\xcd\x70\xe7\xf7\xbd\xd3\xfb\xb0\x79\xc1\x1d\x07\x35\x88\xde\xa2",
        .decimals = 18,
    },
    {
        .name = "FortKnoxster",
        .unit = "FKX",
        .contract_address =
            "\x00\x9e\x86\x49\x23\xb4\x92\x63\xc7\xf1\x0d\x19\xb7\xf8\xab\x7a\x9a\x5a\xad\x33",
        .decimals = 18,
    },
    {
        .name = "Flowchain",
        .unit = "FLC",
        .contract_address =
            "\x32\xc4\xad\xb9\xcf\x57\xf9\x72\xbc\x37\x51\x29\xde\x91\xc8\x97\xb4\xf3\x64\xf1",
        .decimals = 18,
    },
    {
        .name = "Flixxo",
        .unit = "FLIXX",
        .contract_address =
            "\xf0\x4a\x8a\xc5\x53\xfc\xed\xb5\xba\x99\xa6\x47\x99\x15\x58\x26\xc1\x36\xb0\xbe",
        .decimals = 18,
    },
    {
        .name = "Feellike",
        .unit = "FLL",
        .contract_address =
            "\x92\x35\xbd\xa0\x6b\x88\x07\x16\x1b\x8f\xbb\x1e\x10\x2c\xb6\x54\x55\x5b\x21\x2f",
        .decimals = 3,
    },
    {
        .name = "Fire Lotto",
        .unit = "FLOT",
        .contract_address =
            "\x04\x93\x99\xa6\xb0\x48\xd5\x29\x71\xf7\xd1\x22\xae\x21\xa1\x53\x27\x22\x28\x5f",
        .decimals = 18,
    },
    {
        .name = "FLIP",
        .unit = "FLP",
        .contract_address =
            "\x3a\x1b\xda\x28\xad\xb5\xb0\xa8\x12\xa7\xcf\x10\xa1\x95\x0c\x92\x0f\x79\xbc\xd3",
        .decimals = 18,
    },
    {
        .name = "Flit Token",
        .unit = "FLT",
        .contract_address =
            "\xb3\x51\xda\x6f\xfe\xbd\x5d\xdd\xd1\xda\x03\x79\x29\xfc\xf3\x34\xd6\xb4\xa8\xd5",
        .decimals = 18,
    },
    {
        .name = "FLUX",
        .unit = "FLUX",
        .contract_address =
            "\x46\x9e\xda\x64\xae\xd3\xa3\xad\x6f\x86\x8c\x44\x56\x42\x91\xaa\x41\x5c\xb1\xd9",
        .decimals = 18,
    },
    {
        .name = "FLAMA",
        .unit = "FMA",
        .contract_address =
            "\x0f\x87\x94\xf6\x6c\x71\x70\xc4\xf9\x16\x3a\x84\x98\x37\x1a\x74\x71\x14\xf6\xc4",
        .decimals = 18,
    },
    {
        .name = "FinexboxToken",
        .unit = "FNB",
        .contract_address =
            "\xe6\xd2\xc3\xcb\x98\x6d\xb6\x68\x18\xc1\x4c\x70\x32\xdb\x05\xd1\xd2\xa6\xee\x74",
        .decimals = 8,
    },
    {
        .name = "FundRequest",
        .unit = "FND",
        .contract_address =
            "\x4d\xf4\x7b\x49\x69\xb2\x91\x1c\x96\x65\x06\xe3\x59\x2c\x41\x38\x94\x93\x95\x3b",
        .decimals = 18,
    },
    {
        .name = "FNKOS",
        .unit = "FNKOS",
        .contract_address =
            "\x07\x07\x68\x1f\x34\x4d\xeb\x24\x18\x40\x37\xfc\x02\x28\x85\x6f\x21\x37\xb0\x2e",
        .decimals = 18,
    },
    {
        .name = "Falcon Project",
        .unit = "FNT",
        .contract_address =
            "\xdc\x58\x64\xed\xe2\x8b\xd4\x40\x5a\xa0\x4d\x93\xe0\x5a\x05\x31\x79\x7d\x9d\x59",
        .decimals = 6,
    },
    {
        .name = "Fintab",
        .unit = "FNTB",
        .contract_address =
            "\xbd\x4b\x60\xa1\x38\xb3\xfc\xe3\x58\x4e\xa0\x1f\x50\xc0\x90\x8c\x18\xf9\x67\x7a",
        .decimals = 8,
    },
    {
        .name = "Fortuna",
        .unit = "FOTA",
        .contract_address =
            "\x42\x70\xbb\x23\x8f\x6d\xd8\xb1\xc3\xca\x01\xf9\x6c\xa6\x5b\x26\x47\xc0\x6d\x3c",
        .decimals = 18,
    },
    {
        .name = "4THPILLAR TECHNOLOGIES",
        .unit = "FOUR",
        .contract_address =
            "\x47\x30\xfb\x14\x63\xa6\xf1\xf4\x4a\xeb\x45\xf6\xc5\xc4\x22\x42\x7f\x37\xf4\xd0",
        .decimals = 18,
    },
    {
        .name = "Fox Trading",
        .unit = "FOXT",
        .contract_address =
            "\xfb\xe8\x78\xce\xd0\x81\x32\xbd\x83\x96\x98\x86\x71\xb4\x50\x79\x3c\x44\xbc\x12",
        .decimals = 18,
    },
    {
        .name = "Freyrchain",
        .unit = "FREC",
        .contract_address =
            "\x17\xe6\x7d\x1c\xb4\xe3\x49\xb9\xca\x4b\xc3\xe1\x7c\x7d\xf2\xa3\x97\xa7\xbb\x64",
        .decimals = 18,
    },
    {
        .name = "FREE Coin",
        .unit = "FREE",
        .contract_address =
            "\x2f\x14\x1c\xe3\x66\xa2\x46\x2f\x02\xce\xa3\xd1\x2c\xf9\x3e\x4d\xca\x49\xe4\xfd",
        .decimals = 18,
    },
    {
        .name = "Ferrum Network",
        .unit = "FRM",
        .contract_address =
            "\xe5\xca\xef\x4a\xf8\x78\x0e\x59\xdf\x92\x54\x70\xb0\x50\xfb\x23\xc4\x3c\xa6\x8c",
        .decimals = 6,
    },
    {
        .name = "FSBT API Token",
        .unit = "FSBT",
        .contract_address =
            "\x1e\xd7\xae\x1f\x0e\x2f\xa4\x27\x6d\xd7\xdd\xc7\x86\x33\x4a\x3d\xf8\x1d\x50\xc0",
        .decimals = 18,
    },
    {
        .name = "FlashX Advance",
        .unit = "FSXA",
        .contract_address =
            "\xf0\xb0\xa1\x3d\x90\x82\x53\xd9\x54\xba\x03\x1a\x42\x5d\xfd\x54\xf9\x4a\x2e\x3d",
        .decimals = 8,
    },
    {
        .name = "FansTime",
        .unit = "FTI",
        .contract_address =
            "\x94\x3e\xd8\x52\xda\xdb\x5c\x39\x38\xec\xdc\x68\x83\x71\x8d\xf8\x14\x2d\xe4\xc8",
        .decimals = 18,
    },
    {
        .name = "Fountain",
        .unit = "FTN",
        .contract_address =
            "\x56\x32\x5d\x18\x0e\xc3\x87\x8a\x90\x28\xaf\xc7\xb0\xed\xce\xe7\x48\x6c\xc9\xdf",
        .decimals = 18,
    },
    {
        .name = "FarmaTrust",
        .unit = "FTT",
        .contract_address =
            "\x2a\xec\x18\xc5\x50\x0f\x21\x35\x9c\xe1\xbe\xa5\xdc\x17\x77\x34\x4d\xf4\xc0\xdc",
        .decimals = 18,
    },
    {
        .name = "FintruX Network",
        .unit = "FTX",
        .contract_address =
            "\xd5\x59\xf2\x02\x96\xff\x48\x95\xda\x39\xb5\xbd\x9a\xdd\x54\xb4\x42\x59\x6a\x61",
        .decimals = 18,
    },
    {
        .name = "FUTURAX",
        .unit = "FTXT",
        .contract_address =
            "\x41\x87\x5c\x23\x32\xb0\x87\x7c\xdf\xaa\x69\x9b\x64\x14\x02\xb7\xd4\x64\x2c\x32",
        .decimals = 8,
    },
    {
        .name = "FUZE Token",
        .unit = "FUZE",
        .contract_address =
            "\x18\x7d\x10\x18\xe8\xef\x87\x9b\xe4\x19\x4d\x6e\xd7\x59\x09\x87\x46\x3e\xad\x85",
        .decimals = 18,
    },
    {
        .name = "FANZY",
        .unit = "FX1",
        .contract_address =
            "\xed\x0e\x20\x41\xbf\xb5\xa4\x26\xe5\xed\x42\x6a\x73\x76\x56\x24\xe0\x8b\xbb\x75",
        .decimals = 18,
    },
    {
        .name = "FuzeX",
        .unit = "FXT",
        .contract_address =
            "\x18\x29\xaa\x04\x5e\x21\xe0\xd5\x95\x80\x02\x4a\x95\x1d\xb4\x80\x96\xe0\x17\x82",
        .decimals = 18,
    },
    {
        .name = "FlypMe",
        .unit = "FYP",
        .contract_address =
            "\x8f\x09\x21\xf3\x05\x55\x62\x41\x43\xd4\x27\xb3\x40\xb1\x15\x69\x14\x88\x2c\x10",
        .decimals = 18,
    },
    {
        .name = "GameCredits",
        .unit = "GAME",
        .contract_address =
            "\x63\xf8\x8a\x22\x98\xa5\xc4\xae\xe3\xc2\x16\xaa\x6d\x92\x6b\x18\x4a\x4b\x24\x37",
        .decimals = 18,
    },
    {
        .name = "Game Ark",
        .unit = "GARK",
        .contract_address =
            "\xff\xd6\xf6\x08\x90\x79\x14\x97\x5b\x37\x13\xc8\x92\x11\xfa\xf2\xc7\x0e\xce\x05",
        .decimals = 18,
    },
    {
        .name = "Galaxy Wallet",
        .unit = "GC",
        .contract_address =
            "\x48\x6a\x72\x81\x1a\xe6\x5c\x4c\x81\x4b\xa9\x29\xd6\xda\x35\x49\x7d\x21\x29\x6f",
        .decimals = 18,
    },
    {
        .name = "Gems ",
        .unit = "GEM",
        .contract_address =
            "\xc7\xbb\xa5\xb7\x65\x58\x1e\xfb\x2c\xdd\x26\x79\xdb\x5b\xea\x9e\xe7\x9b\x20\x1f",
        .decimals = 18,
    },
    {
        .name = "Gene Source Code Chain",
        .unit = "GENE",
        .contract_address =
            "\x88\x41\x81\x55\x4d\xfa\x9e\x57\x8d\x36\x37\x99\x19\xc0\x5c\x25\xdc\x4a\x15\xbb",
        .decimals = 18,
    },
    {
        .name = "Parkgene",
        .unit = "GENE",
        .contract_address =
            "\x6d\xd4\xe4\xaa\xd2\x9a\x40\xed\xd6\xa4\x09\xb9\xc1\x62\x51\x86\xc9\x85\x5b\x4d",
        .decimals = 8,
    },
    {
        .name = "GeoDB",
        .unit = "GEO",
        .contract_address =
            "\x14\x7f\xaf\x8d\xe9\xd8\xd8\xda\xae\x12\x9b\x18\x7f\x0d\x02\xd8\x19\x12\x67\x50",
        .decimals = 18,
    },
    {
        .name = "Themis",
        .unit = "GET",
        .contract_address =
            "\x60\xc6\x8a\x87\xbe\x1e\x8a\x84\x14\x4b\x54\x3a\xac\xfa\x77\x19\x9c\xd3\xd0\x24",
        .decimals = 18,
    },
    {
        .name = "Guaranteed Ethurance Token Extra",
        .unit = "GETX",
        .contract_address =
            "\x07\xa5\x86\x29\xaa\xf3\xe1\xa0\xd0\x7d\x8f\x43\x11\x4b\x76\xbd\x5e\xee\x3b\x91",
        .decimals = 18,
    },
    {
        .name = "GoldFund",
        .unit = "GFUN",
        .contract_address =
            "\x91\x9d\x3a\x36\x37\x76\xb1\xce\xec\x93\x52\x61\x0c\x82\xdf\xaf\x80\xed\xc3\x2d",
        .decimals = 18,
    },
    {
        .name = "GramGold Coin",
        .unit = "GGC",
        .contract_address =
            "\x1b\xe7\xcf\xd6\x1a\xa8\xda\xaa\x9f\xf2\xf3\xb8\x82\x08\x88\xf0\x94\x62\xd0\x37",
        .decimals = 8,
    },
    {
        .name = "GHOST",
        .unit = "GHOST",
        .contract_address =
            "\x4c\x32\x74\x71\xc4\x4b\x2d\xac\xd6\xe9\x05\x25\xf9\xd6\x29\xbd\x2e\x4f\x66\x2c",
        .decimals = 18,
    },
    {
        .name = "Krios",
        .unit = "GIG",
        .contract_address =
            "\x83\x8d\x8e\x11\xb1\x60\xde\xc8\x8f\xe6\x2b\xf0\xf7\x43\xfb\x70\x00\x94\x1e\x13",
        .decimals = 18,
    },
    {
        .name = "Buzzshow",
        .unit = "GLDY",
        .contract_address =
            "\x59\x42\x07\xc7\x91\xaf\xd0\x6a\x8d\x08\x7d\x84\xd9\x9d\x1d\xa5\x3c\xcb\xd4\x5f",
        .decimals = 3,
    },
    {
        .name = "Global Reserve System",
        .unit = "GLOB",
        .contract_address =
            "\x45\xf2\xab\x0c\xa2\x11\x6b\x2e\x1a\x70\xbf\x5e\x13\x29\x39\x47\xb2\x5d\x02\x72",
        .decimals = 18,
    },
    {
        .name = "GAMB",
        .unit = "GMB",
        .contract_address =
            "\xa0\x00\x8f\x51\x0f\xe9\xee\x69\x6e\x7e\x32\x0c\x9e\x5c\xbf\x61\xe2\x77\x91\xee",
        .decimals = 18,
    },
    {
        .name = "Digital Gold",
        .unit = "GOLD",
        .contract_address =
            "\x0d\x16\x45\x0d\x34\x7c\x12\xc0\x86\xd6\xc9\x4c\x76\xc5\xaa\xac\x35\xea\x07\xe0",
        .decimals = 3,
    },
    {
        .name = "Golden Token",
        .unit = "GOLD",
        .contract_address =
            "\x34\xd6\xa0\xf5\xc2\xf5\xd0\x08\x21\x41\xfe\x73\xd9\x3b\x9d\xd0\x0c\xa7\xce\x11",
        .decimals = 18,
    },
    {
        .name = "Gomics",
        .unit = "GOM",
        .contract_address =
            "\xb8\xc6\xad\x25\x86\xbb\x71\xd5\x18\xc2\xaa\xf5\x10\xef\xe9\x1f\x82\x02\x2f\x58",
        .decimals = 18,
    },
    {
        .name = "AnimalGo",
        .unit = "GOM2",
        .contract_address =
            "\x48\x78\x34\x86\xdd\xd7\xfa\x85\xec\xa6\xb0\xc4\xae\x89\x20\xbc\x25\xdf\xbc\xd7",
        .decimals = 0,
    },
    {
        .name = "GoNetwork",
        .unit = "GOT",
        .contract_address =
            "\x42\x3b\x5f\x62\xb3\x28\xd0\xd6\xd4\x48\x70\xf4\xee\xe3\x16\xbe\xfa\x0b\x2d\xf5",
        .decimals = 18,
    },
    {
        .name = "Galaxy Pool Coin",
        .unit = "GPO",
        .contract_address =
            "\x5c\xf5\x01\xe6\x47\x86\x44\x4e\x02\x5c\x5b\x24\x02\x5f\x98\x39\x95\x38\xea\x5d",
        .decimals = 18,
    },
    {
        .name = "GoPower",
        .unit = "GPT",
        .contract_address =
            "\xa0\x04\x25\xd3\xe2\xd3\xe9\xff\x74\xf3\xe1\x12\xb4\xd3\xa7\x97\x8d\x7d\x88\xc2",
        .decimals = 18,
    },
    {
        .name = "GoldenPyrex",
        .unit = "GPYX",
        .contract_address =
            "\xbc\x7f\x40\x2f\x3b\xc1\xc6\xd5\x6c\x80\x41\xf5\x51\xb4\x7a\x0a\xd7\x71\x4d\x1b",
        .decimals = 18,
    },
    {
        .name = "GSENetwork",
        .unit = "GSE",
        .contract_address =
            "\xe5\x30\x44\x1f\x4f\x73\xbd\xb6\xdc\x2f\xa5\xaf\x7c\x3f\xc5\xfd\x55\x1e\xc8\x38",
        .decimals = 4,
    },
    {
        .name = "GLOBALTRUSTFUND TOKEN",
        .unit = "GTF",
        .contract_address =
            "\x40\xf8\xb7\xa8\x2b\x63\x55\xd2\x65\x46\xd3\x63\xce\x9c\x12\xce\x10\x4c\xf0\xce",
        .decimals = 8,
    },
    {
        .name = "GoalTime N",
        .unit = "GTX",
        .contract_address =
            "\x91\x68\x85\x42\x62\x55\x23\x5d\xa7\xa0\xbd\x90\x44\x79\x86\xc0\x06\x75\xf9\xec",
        .decimals = 18,
    },
    {
        .name = "Peerguess",
        .unit = "GUESS",
        .contract_address =
            "\xbd\xcf\xbf\x5c\x4d\x91\xab\xc0\xbc\x97\x09\xc7\x28\x6d\x00\x06\x3c\x0e\x6f\x22",
        .decimals = 2,
    },
    {
        .name = "Matchpool",
        .unit = "GUP",
        .contract_address =
            "\xf7\xb0\x98\x29\x8f\x7c\x69\xfc\x14\x61\x0b\xf7\x1d\x5e\x02\xc6\x07\x92\x89\x4c",
        .decimals = 3,
    },
    {
        .name = "Globalvillage Ecosystem",
        .unit = "GVE",
        .contract_address =
            "\x81\x70\x50\x82\xef\x9f\x0d\x66\x0f\x07\xbe\x80\x09\x3d\x46\xd8\x26\xd4\x8b\x25",
        .decimals = 18,
    },
    {
        .name = "ShowHand",
        .unit = "HAND",
        .contract_address =
            "\x48\xc1\xb2\xf3\xef\xa8\x5f\xba\xfb\x2a\xb9\x51\xbf\x4b\xa8\x60\xa0\x8c\xdb\xb7",
        .decimals = 0,
    },
    {
        .name = "Havy",
        .unit = "HAVY",
        .contract_address =
            "\x7c\x2e\x5b\x7e\xc5\x72\x19\x9d\x38\x41\xf6\xa3\x8f\x7d\x48\x68\xbd\x07\x98\xf1",
        .decimals = 8,
    },
    {
        .name = "HeartBout",
        .unit = "HB",
        .contract_address =
            "\xe2\x49\x2f\x8d\x2a\x26\x18\xd8\x70\x9c\xa9\x9b\x1d\x8d\x75\x71\x3b\xd8\x40\x89",
        .decimals = 18,
    },
    {
        .name = "HashBX ",
        .unit = "HBX",
        .contract_address =
            "\x6f\xe3\x55\xc6\x2c\x6f\xaf\x69\x46\xce\x88\x8f\xfa\xba\x9f\xd1\x23\x55\xae\x27",
        .decimals = 18,
    },
    {
        .name = "HyperDAO",
        .unit = "HDAO",
        .contract_address =
            "\x74\xfa\xab\x69\x86\x56\x0f\xd1\x14\x05\x08\xe4\x26\x6d\x8a\x7b\x87\x27\x4f\xfd",
        .decimals = 18,
    },
    {
        .name = "HEIDI",
        .unit = "HDI",
        .contract_address =
            "\x58\xa3\x52\x0d\x73\x8b\x26\x8c\x23\x53\xec\xee\x51\x8a\x1a\xd8\xe2\x8e\x4a\xe5",
        .decimals = 2,
    },
    {
        .name = "1x Short Bitcoin Token",
        .unit = "HEDGE",
        .contract_address =
            "\x1f\xa3\xbc\x86\x0b\xf8\x23\xd7\x92\xf0\x4f\x66\x2f\x3a\xa3\xa5\x00\xa6\x88\x14",
        .decimals = 18,
    },
    {
        .name = "Hemelios",
        .unit = "HEM",
        .contract_address =
            "\x19\x74\x78\x16\xa0\x30\xfe\xcd\xa3\x39\x4c\x60\x62\xcd\xf6\xb9\xb4\xdb\x0e\x0b",
        .decimals = 8,
    },
    {
        .name = "HeroNode",
        .unit = "HER",
        .contract_address =
            "\x49\x1c\x9a\x23\xdb\x85\x62\x3e\xed\x45\x5a\x8e\xfd\xd6\xab\xa9\xb9\x11\xc5\xdf",
        .decimals = 18,
    },
    {
        .name = "Herbalist Token",
        .unit = "HERB",
        .contract_address =
            "\x04\xa0\x20\x32\x50\x24\xf1\x30\x98\x87\x82\xbd\x52\x76\xe5\x35\x95\xe8\xd1\x6e",
        .decimals = 8,
    },
    {
        .name = "HEX",
        .unit = "HEX",
        .contract_address =
            "\x2b\x59\x1e\x99\xaf\xe9\xf3\x2e\xaa\x62\x14\xf7\xb7\x62\x97\x68\xc4\x0e\xeb\x39",
        .decimals = 8,
    },
    {
        .name = "HelloGold",
        .unit = "HGT",
        .contract_address =
            "\xba\x21\x84\x52\x0a\x1c\xc4\x9a\x61\x59\xc5\x7e\x61\xe1\x84\x4e\x08\x56\x15\xb6",
        .decimals = 8,
    },
    {
        .name = "Hintchain",
        .unit = "HINT",
        .contract_address =
            "\x6c\xe2\x1e\x5f\x53\x83\xc9\x56\x91\xd2\x43\x87\x9a\x86\xa6\x02\x5e\x08\x70\xc0",
        .decimals = 18,
    },
    {
        .name = "HitChain",
        .unit = "HIT",
        .contract_address =
            "\x79\x95\xab\x36\xbb\x30\x7a\xfa\x6a\x68\x3c\x24\xa2\x5d\x90\xdc\x1e\xa8\x35\x66",
        .decimals = 6,
    },
    {
        .name = "HalalChain",
        .unit = "HLC",
        .contract_address =
            "\x58\xc6\x9e\xd6\xcd\x68\x87\xc0\x22\x5d\x1f\xcc\xec\xc0\x55\x12\x78\x43\xc6\x9b",
        .decimals = 9,
    },
    {
        .name = "Helex",
        .unit = "HLX",
        .contract_address =
            "\x8f\x8e\x78\x79\x89\xbc\x65\x2e\xea\x01\xa6\xc8\x8a\x19\xf0\xf3\x79\xbd\xf4\xfd",
        .decimals = 5,
    },
    {
        .name = "Hamebi Token",
        .unit = "HMB",
        .contract_address =
            "\xc3\xb2\x14\x0a\xc3\xe9\x5e\xdf\xea\x22\x06\x81\xee\xca\x12\x7f\xc8\x1e\x49\x29",
        .decimals = 18,
    },
    {
        .name = "Homeros",
        .unit = "HMR",
        .contract_address =
            "\xb1\xa3\x08\x51\xe3\xf7\xd8\x41\xb2\x31\xb0\x86\x47\x96\x08\xe1\x71\x98\x36\x3a",
        .decimals = 18,
    },
    {
        .name = "HashNet BitEco",
        .unit = "HNB",
        .contract_address =
            "\x9c\x19\x7c\x4b\x58\x52\x7f\xaa\xab\x67\xcb\x35\xe3\x14\x51\x66\xb2\x3d\x24\x2e",
        .decimals = 18,
    },
    {
        .name = "HOLD",
        .unit = "HOLD",
        .contract_address =
            "\xd6\xe1\x40\x1a\x07\x99\x22\x46\x9e\x9b\x96\x5c\xb0\x90\xea\x6f\xf6\x4c\x68\x39",
        .decimals = 18,
    },
    {
        .name = "HOMIHELP",
        .unit = "HOMI",
        .contract_address =
            "\xca\x20\x8b\xfd\x69\xae\x6d\x26\x67\xf1\xfc\xbe\x68\x1b\xae\x12\x76\x7c\x00\x78",
        .decimals = 0,
    },
    {
        .name = "Ethouse",
        .unit = "HORSE",
        .contract_address =
            "\x5b\x07\x51\x71\x3b\x25\x27\xd7\xf0\x02\xc0\xc4\xe2\xa3\x7e\x12\x19\x61\x0a\x6b",
        .decimals = 18,
    },
    {
        .name = "Healing Plus",
        .unit = "HP",
        .contract_address =
            "\xab\x55\xbd\xef\x70\x57\xb7\x64\x82\x91\x4e\x79\xf0\x37\x99\x9f\x4e\xbb\x6b\xf1",
        .decimals = 8,
    },
    {
        .name = "HyperQuant",
        .unit = "HQT",
        .contract_address =
            "\x3e\x1d\x5a\x85\x5a\xd9\xd9\x48\x37\x3a\xe6\x8e\x4f\xe1\xf0\x94\x61\x2b\x13\x22",
        .decimals = 18,
    },
    {
        .name = "HOQU",
        .unit = "HQX",
        .contract_address =
            "\x1b\x95\x7d\xc4\xae\xfe\xed\x3b\x4a\x23\x51\xa6\xa6\xd5\xcb\xfb\xba\x0c\xec\xfa",
        .decimals = 18,
    },
    {
        .name = "HashCoin",
        .unit = "HSC",
        .contract_address =
            "\x2b\xba\x3c\xf6\xde\x60\x58\xcc\x1b\x44\x57\xce\x00\xde\xb3\x59\xe2\x70\x3d\x7f",
        .decimals = 18,
    },
    {
        .name = "Hyper Speed Network",
        .unit = "HSN",
        .contract_address =
            "\x36\x55\x42\xdf\x3c\x8c\x9d\x09\x6c\x5f\x0d\xe2\x4a\x0d\x8c\xf3\x3c\x19\xc8\xfd",
        .decimals = 8,
    },
    {
        .name = "Helper Search Token",
        .unit = "HSN",
        .contract_address =
            "\x56\x73\x00\xe1\x4f\x8d\x67\xe1\xf6\x72\x0a\x95\x29\x1d\xce\x25\x11\xa8\x67\x23",
        .decimals = 18,
    },
    {
        .name = "Hubi Token",
        .unit = "HUB",
        .contract_address =
            "\xba\x51\x60\xba\x66\xb2\x86\xf1\xb9\xb6\xf3\xa5\x7a\x6a\xbc\xfa\x44\x0e\x7a\xa2",
        .decimals = 18,
    },
    {
        .name = "HUNT",
        .unit = "HUNT",
        .contract_address =
            "\x9a\xab\x07\x1b\x41\x29\xb0\x83\xb0\x1c\xb5\xa0\xcb\x51\x3c\xe7\xec\xa2\x6f\xa5",
        .decimals = 18,
    },
    {
        .name = "Hurify",
        .unit = "HUR",
        .contract_address =
            "\xcd\xb7\xec\xfd\x34\x03\xee\xf3\x88\x2c\x65\xb7\x61\xef\x9b\x50\x54\x89\x0a\x47",
        .decimals = 18,
    },
    {
        .name = "HUSD",
        .unit = "HUSD",
        .contract_address =
            "\xdf\x57\x4c\x24\x54\x5e\x5f\xfe\xcb\x9a\x65\x9c\x22\x92\x53\xd4\x11\x1d\x87\xe1",
        .decimals = 8,
    },
    {
        .name = "Hiveterminal Token",
        .unit = "HVN",
        .contract_address =
            "\xc0\xeb\x85\x28\x5d\x83\x21\x7c\xd7\xc8\x91\x70\x2b\xcb\xc0\xfc\x40\x1e\x2d\x9d",
        .decimals = 8,
    },
    {
        .name = "HYPNOXYS",
        .unit = "HYPX",
        .contract_address =
            "\xd3\x58\x33\xf9\x25\x5f\xb2\x8c\xc6\xb9\x1a\xcb\x8a\x66\xba\x64\x29\xd6\xef\x5a",
        .decimals = 18,
    },
    {
        .name = "HoryouToken",
        .unit = "HYT",
        .contract_address =
            "\xcf\xac\x29\x16\xec\x11\x8a\x02\x52\xa7\x76\x6c\x51\x3e\xe7\xc7\x1b\x38\x4b\x5e",
        .decimals = 18,
    },
    {
        .name = "Black Diamond Rating",
        .unit = "HZT",
        .contract_address =
            "\x78\xa5\xb3\x82\xb9\xa8\x3f\xe0\x42\xa4\xf7\xeb\x23\x99\xd5\x63\xfd\xa9\x31\xc3",
        .decimals = 2,
    },
    {
        .name = "IBStoken",
        .unit = "IBS",
        .contract_address =
            "\xf0\xe6\x01\x9c\x0f\x16\xd3\x12\x94\x93\x7b\x33\x34\x22\x99\x09\x34\x9e\x00\xf4",
        .decimals = 18,
    },
    {
        .name = "iBTC",
        .unit = "IBTC",
        .contract_address =
            "\xb7\xc4\xa8\x29\x36\x19\x4f\xee\x52\xa4\xe3\xd4\xce\xc3\x41\x5f\x74\x50\x75\x32",
        .decimals = 18,
    },
    {
        .name = "Inverse Bitcoin Volatility Token",
        .unit = "IBVOL",
        .contract_address =
            "\x62\x7e\x2e\xe3\xdb\xda\x54\x6e\x16\x8e\xaa\xff\x25\xa2\xc5\x21\x2e\x4a\x95\xa0",
        .decimals = 18,
    },
    {
        .name = "Idea Chain Coin",
        .unit = "ICH",
        .contract_address =
            "\xf8\x48\x3e\x2d\x65\x60\x58\x5c\x02\xd4\x6b\xf7\xb3\x18\x6b\xf1\x54\xa9\x61\x66",
        .decimals = 8,
    },
    {
        .name = "Iconic Token",
        .unit = "ICNQ",
        .contract_address =
            "\xb3\xe2\xcb\x7c\xcc\xfe\x13\x9f\x8f\xf8\x40\x13\x82\x3b\xf2\x2d\xa6\xb6\x39\x0a",
        .decimals = 18,
    },
    {
        .name = "ICOCalendar.Today",
        .unit = "ICT",
        .contract_address =
            "\x2d\x71\x98\x3e\x81\x0b\x9e\x95\x25\x89\x66\xb9\xc1\x64\xc4\xd6\x1a\x82\x9b\xa9",
        .decimals = 6,
    },
    {
        .name = "IDK",
        .unit = "IDK",
        .contract_address =
            "\x61\xfd\x1c\x62\x55\x18\x50\xd0\xc0\x4c\x76\xfc\xe6\x14\xcb\xce\xd0\x09\x44\x98",
        .decimals = 8,
    },
    {
        .name = "InvestDigital",
        .unit = "IDT",
        .contract_address =
            "\x02\xc4\xc7\x8c\x46\x2e\x32\xcc\xa4\xa9\x0b\xc4\x99\xbf\x41\x1f\xb7\xbc\x6a\xfb",
        .decimals = 18,
    },
    {
        .name = "IDEX Membership",
        .unit = "IDXM",
        .contract_address =
            "\xcc\x13\xfc\x62\x7e\xff\xd6\xe3\x5d\x2d\x27\x06\xea\x3c\x4d\x73\x96\xc6\x10\xea",
        .decimals = 8,
    },
    {
        .name = "iEthereum",
        .unit = "IETH",
        .contract_address =
            "\x85\x9a\x9c\x0b\x44\xcb\x70\x66\xd9\x56\xa9\x58\xb0\xb8\x2e\x54\xc9\xe4\x4b\x4b",
        .decimals = 8,
    },
    {
        .name = "Ifoods Chain",
        .unit = "IFOOD",
        .contract_address =
            "\x81\xe7\x4a\x3e\xa4\xba\xb2\x27\x7a\xa3\xb9\x41\xe9\xd9\xf3\x7b\x08\xac\x53\x74",
        .decimals = 18,
    },
    {
        .name = "InvestFeed",
        .unit = "IFT",
        .contract_address =
            "\x76\x54\x91\x5a\x1b\x82\xd6\xd2\xd0\xaf\xc3\x7c\x52\xaf\x55\x6e\xa8\x98\x3c\x7e",
        .decimals = 18,
    },
    {
        .name = "IFX24",
        .unit = "IFX24",
        .contract_address =
            "\xc9\x62\xad\x02\x1a\x69\xd4\x57\x56\x4e\x98\x57\x38\xc7\x19\xae\x3f\x79\xb7\x07",
        .decimals = 18,
    },
    {
        .name = "IGToken",
        .unit = "IG",
        .contract_address =
            "\x8a\x88\xf0\x4e\x0c\x90\x50\x54\xd2\xf3\x3b\x26\xbb\x3a\x46\xd7\x09\x1a\x03\x9a",
        .decimals = 18,
    },
    {
        .name = "Intelligent Investment Chain",
        .unit = "IIC",
        .contract_address =
            "\xb6\xf4\x30\x25\xb2\x91\x96\xaf\x2d\xdd\xd6\x9b\x0a\x58\xaf\xba\x07\x9c\xd6\x00",
        .decimals = 18,
    },
    {
        .name = "Ether Kingdoms Token",
        .unit = "IMP",
        .contract_address =
            "\x48\xff\x53\x77\x7f\x74\x7c\xfb\x69\x41\x01\x22\x2a\x94\x4d\xe0\x70\xc1\x5d\x36",
        .decimals = 7,
    },
    {
        .name = "Moneytoken",
        .unit = "IMT",
        .contract_address =
            "\x13\x11\x9e\x34\xe1\x40\x09\x7a\x50\x7b\x07\xa5\x56\x4b\xde\x1b\xc3\x75\xd9\xe6",
        .decimals = 18,
    },
    {
        .name = "Imsmart",
        .unit = "IMT",
        .contract_address =
            "\xbf\xe0\x37\x07\xad\xb7\x5b\x47\x8a\xdd\x9a\x01\x97\x80\x57\x80\x3f\x48\x0e\x44",
        .decimals = 8,
    },
    {
        .name = "InternationalCryptoX",
        .unit = "INCX",
        .contract_address =
            "\xa9\x84\xa9\x27\x31\xc0\x88\xf1\xea\x4d\x53\xb7\x1a\x25\x65\xa3\x99\xf7\xd8\xd5",
        .decimals = 18,
    },
    {
        .name = "Indorse Token",
        .unit = "IND",
        .contract_address =
            "\xf8\xe3\x86\xed\xa8\x57\x48\x4f\x5a\x12\xe4\xb5\xda\xa9\x98\x4e\x06\xe7\x37\x05",
        .decimals = 18,
    },
    {
        .name = "Infinitus Token",
        .unit = "INF",
        .contract_address =
            "\x00\xe1\x50\xd7\x41\xed\xa1\xd4\x9d\x34\x11\x89\xca\xe4\xc0\x8a\x73\xa4\x9c\x95",
        .decimals = 18,
    },
    {
        .name = "Iungo",
        .unit = "ING",
        .contract_address =
            "\x24\xdd\xff\x6d\x8b\x8a\x42\xd8\x35\xaf\x3b\x44\x0d\xe9\x1f\x33\x86\x55\x4a\xa4",
        .decimals = 18,
    },
    {
        .name = "Innovative Bioresearch Coin",
        .unit = "INNBC",
        .contract_address =
            "\xb6\x77\x18\xb9\x8d\x52\x31\x82\x40\xc5\x2e\x71\xa8\x98\x33\x5d\xa4\xa2\x8c\x42",
        .decimals = 6,
    },
    {
        .name = "Innovative Bioresearch Classic",
        .unit = "INNBCL",
        .contract_address =
            "\x0c\xc9\xfc\xcf\xf8\x12\x52\xf4\xbd\x8c\x5c\x6b\x35\x9b\x14\xae\x2e\xd8\x51\xcf",
        .decimals = 6,
    },
    {
        .name = "intexcoin",
        .unit = "INTX",
        .contract_address =
            "\x75\x33\xd6\x3a\x25\x58\x96\x54\x72\x39\x8e\xf4\x73\x90\x8e\x13\x20\x52\x0a\xe2",
        .decimals = 9,
    },
    {
        .name = "InterValue",
        .unit = "INVE",
        .contract_address =
            "\xda\xc4\xae\x18\x8a\xce\x3c\x89\x85\x76\x5e\xdc\x6c\x9b\x47\x39\xd4\x84\x5d\xdc",
        .decimals = 18,
    },
    {
        .name = "INMAX",
        .unit = "INX",
        .contract_address =
            "\x01\x8d\x7d\x17\x93\x50\xf1\xbb\x98\x53\xd0\x49\x82\x82\x0e\x37\xcc\xe1\x3a\x92",
        .decimals = 8,
    },
    {
        .name = "Insight Protocol",
        .unit = "INX",
        .contract_address =
            "\x84\xfe\x25\xf3\x92\x1f\x34\x26\x39\x5c\x88\x37\x07\x95\x0d\x0c\x00\x36\x75\x76",
        .decimals = 18,
    },
    {
        .name = "Internxt",
        .unit = "INXT",
        .contract_address =
            "\xa8\x00\x6c\x4c\xa5\x6f\x24\xd6\x83\x67\x27\xd1\x06\x34\x93\x20\xdb\x7f\xef\x82",
        .decimals = 8,
    },
    {
        .name = "Playgroundz",
        .unit = "IOG",
        .contract_address =
            "\x1c\x4b\x7d\x0e\x18\x85\xbd\x76\x67\xaf\x33\x78\xe0\xc5\x38\xf7\x4e\x71\x20\x06",
        .decimals = 18,
    },
    {
        .name = "IONChain",
        .unit = "IONC",
        .contract_address =
            "\xbc\x64\x7a\xad\x10\x11\x4b\x89\x56\x4c\x0a\x7a\xab\xe5\x42\xbd\x0c\xf2\xc5\xaf",
        .decimals = 18,
    },
    {
        .name = "IOOX System",
        .unit = "IOOX",
        .contract_address =
            "\xf6\x92\x3f\x7d\x96\xfc\x22\xc4\xb8\x01\x0a\x86\x5e\x41\xcf\x7e\xdf\xb6\x37\x9c",
        .decimals = 8,
    },
    {
        .name = "VouchForMe",
        .unit = "IPL",
        .contract_address =
            "\x64\xcd\xf8\x19\xd3\xe7\x5a\xc8\xec\x21\x7b\x34\x96\xd7\xce\x16\x7b\xe4\x2e\x80",
        .decimals = 18,
    },
    {
        .name = "IP Exchange",
        .unit = "IPSX",
        .contract_address =
            "\x00\x1f\x0a\xa5\xda\x15\x58\x5e\x5b\x23\x05\xdb\xab\x2b\xac\x42\x5e\xa7\x10\x07",
        .decimals = 18,
    },
    {
        .name = "Diligence",
        .unit = "IRA",
        .contract_address =
            "\xad\xe7\xb5\xf4\xa4\x21\xd8\x1d\xda\xd8\xce\x86\xf7\x7a\x0e\xfe\x89\x21\xe9\xcc",
        .decimals = 8,
    },
    {
        .name = "Isiklar Coin",
        .unit = "ISIKC",
        .contract_address =
            "\x42\x72\x6d\x07\x4b\xba\x68\xcc\xc1\x52\x00\x44\x2b\x72\xaf\xa2\xd4\x95\xa7\x83",
        .decimals = 4,
    },
    {
        .name = "Insula",
        .unit = "ISLA",
        .contract_address =
            "\x69\x7e\xf3\x2b\x4a\x3f\x5a\x4c\x39\xde\x1c\xb7\x56\x3f\x24\xca\x7b\xfc\x59\x47",
        .decimals = 18,
    },
    {
        .name = "Insureum",
        .unit = "ISR",
        .contract_address =
            "\xd4\xa2\x93\xae\x8b\xb9\xe0\xbe\x12\xe9\x9e\xb1\x9d\x48\x23\x9e\x8c\x83\xa1\x36",
        .decimals = 18,
    },
    {
        .name = "IDCM Token",
        .unit = "IT",
        .contract_address =
            "\x73\xd7\xe1\xdc\xfa\xc9\x42\x82\xdf\xda\x16\xc8\xf3\x69\xb4\x88\x58\x0f\x74\x08",
        .decimals = 18,
    },
    {
        .name = "Italian Lira",
        .unit = "ITL",
        .contract_address =
            "\x12\x2a\x86\xb5\xdf\xf2\xd0\x85\xaf\xb4\x96\x00\xb4\xcd\x73\x75\xd0\xd9\x4a\x5f",
        .decimals = 8,
    },
    {
        .name = "Intelligent Trading Foundation",
        .unit = "ITT",
        .contract_address =
            "\x0a\xef\x06\xdc\xcc\xc5\x31\xe5\x81\xf0\x44\x00\x59\xe6\xff\xcc\x20\x60\x39\xee",
        .decimals = 8,
    },
    {
        .name = "X-Block",
        .unit = "IX",
        .contract_address =
            "\x53\xf0\xc9\xf1\xb6\xe2\x83\xa5\x9b\xcd\x67\x2e\x80\xe2\x22\x2b\x97\xe5\x34\xcb",
        .decimals = 18,
    },
    {
        .name = "IXT",
        .unit = "IXT",
        .contract_address =
            "\xfc\xa4\x79\x62\xd4\x5a\xdf\xdf\xd1\xab\x2d\x97\x23\x15\xdb\x4c\xe7\xcc\xf0\x94",
        .decimals = 8,
    },
    {
        .name = "IZE",
        .unit = "IZE",
        .contract_address =
            "\x69\x44\xd3\xe3\x89\x73\xc4\x83\x1d\xa2\x4e\x95\x4f\xbd\x79\x0c\x7e\x68\x8b\xdd",
        .decimals = 18,
    },
    {
        .name = "JET8",
        .unit = "J8T",
        .contract_address =
            "\x0d\x26\x2e\x5d\xc4\xa0\x6a\x0f\x1c\x90\xce\x79\xc7\xa6\x0c\x09\xdf\xc8\x84\xe4",
        .decimals = 8,
    },
    {
        .name = "Jack Token",
        .unit = "JACK",
        .contract_address =
            "\x4e\x12\xeb\x8e\x50\x6c\xcd\x14\x27\xf6\xb8\xf7\xfa\xa3\xe8\x8f\xb6\x98\xeb\x28",
        .decimals = 18,
    },
    {
        .name = "Jade Currency",
        .unit = "JADE",
        .contract_address =
            "\x5a\xba\xff\x0b\x83\xf8\x1d\xc0\x61\xc5\x90\xaa\xdc\xba\x01\x3c\x69\x23\x7f\xd7",
        .decimals = 18,
    },
    {
        .name = "Jarvis+",
        .unit = "JAR",
        .contract_address =
            "\xa2\x49\xde\x69\x48\x02\x27\x83\x76\x5f\xee\x48\x50\xd7\xb8\x5e\x43\x11\x8f\xcc",
        .decimals = 18,
    },
    {
        .name = "Japan Content Token",
        .unit = "JCT",
        .contract_address =
            "\x7f\xe9\x2e\xc6\x00\xf1\x5c\xd2\x52\x53\xb4\x21\xbc\x15\x1c\x51\xb0\x27\x6b\x7d",
        .decimals = 8,
    },
    {
        .name = "Jetcoin",
        .unit = "JET",
        .contract_address =
            "\x87\x27\xc1\x12\xc7\x12\xc4\xa0\x33\x71\xac\x87\xa7\x4d\xd6\xab\x10\x4a\xf7\x68",
        .decimals = 18,
    },
    {
        .name = "Jinbi Token",
        .unit = "JNB",
        .contract_address =
            "\x21\xd5\xa1\x4e\x62\x5d\x76\x7c\xe6\xb7\xa1\x67\x49\x1c\x2d\x18\xe0\x78\x5f\xda",
        .decimals = 18,
    },
    {
        .name = "Jobchain",
        .unit = "JOB",
        .contract_address =
            "\xdf\xbc\x90\x50\xf5\xb0\x1d\xf5\x35\x12\xdc\xc3\x9b\x4f\x2b\x2b\xba\xcd\x51\x7a",
        .decimals = 8,
    },
    {
        .name = "Joint Ventures",
        .unit = "JOINT",
        .contract_address =
            "\x34\x7c\x09\x9f\x11\x0c\xa6\x76\x17\x79\x32\x9d\x28\x79\x95\x7b\x60\x6b\x6a\xce",
        .decimals = 18,
    },
    {
        .name = "Jarvis Network",
        .unit = "JRT",
        .contract_address =
            "\x8a\x9c\x67\xfe\xe6\x41\x57\x9d\xeb\xa0\x49\x28\xc4\xbc\x45\xf6\x6e\x26\x34\x3a",
        .decimals = 18,
    },
    {
        .name = "JavaScript Token",
        .unit = "JS",
        .contract_address =
            "\x50\x46\xe8\x60\xff\x27\x4f\xb8\xc6\x61\x06\xb0\xff\xb8\x15\x58\x49\xfb\x07\x87",
        .decimals = 8,
    },
    {
        .name = "JSECOIN",
        .unit = "JSE",
        .contract_address =
            "\x2d\x18\x40\x14\xb5\x65\x8c\x45\x34\x43\xaa\x87\xc8\xe9\xc4\xd5\x72\x85\x62\x0b",
        .decimals = 18,
    },
    {
        .name = "Jubi Token",
        .unit = "JT",
        .contract_address =
            "\xeb\x73\x55\xc2\xf2\x17\xb3\x48\x5a\x59\x13\x32\xfe\x13\xc8\xc5\xa7\x6a\x58\x1d",
        .decimals = 18,
    },
    {
        .name = "JUST NETWORK",
        .unit = "JUS",
        .contract_address =
            "\x14\xca\x41\xee\xcd\x7d\x81\xd5\xd1\x30\x98\x58\x6c\x0d\x23\x14\xeb\xa2\x85\xbe",
        .decimals = 18,
    },
    {
        .name = "KAASO",
        .unit = "KAASO",
        .contract_address =
            "\xf6\xbf\x74\xa9\x7d\x78\xf2\x24\x23\x76\x76\x9e\xf1\xe7\x98\x85\xcf\x1f\x0c\x1c",
        .decimals = 18,
    },
    {
        .name = "KardiaChain",
        .unit = "KAI",
        .contract_address =
            "\xbd\x64\x67\xa3\x18\x99\x59\x04\x74\xce\x1e\x84\xf7\x05\x94\xc5\x3d\x62\x8e\x46",
        .decimals = 18,
    },
    {
        .name = "BitKAM",
        .unit = "KAM",
        .contract_address =
            "\xbd\xbb\x0e\xe6\x14\x45\x44\xec\x81\x4d\x41\x7b\x0a\xd4\x1f\x16\xfc\x8b\x85\x8e",
        .decimals = 8,
    },
    {
        .name = "Kambria",
        .unit = "KAT",
        .contract_address =
            "\xa8\x58\xbc\x1b\x71\xa8\x95\xee\x83\xb9\x2f\x14\x96\x16\xf9\xb3\xf6\xaf\xa0\xfb",
        .decimals = 18,
    },
    {
        .name = "King DAG",
        .unit = "KDAG",
        .contract_address =
            "\x95\xe4\x0e\x06\x5a\xfb\x30\x59\xdc\xab\xe4\xaa\xf4\x04\xc1\xf9\x27\x56\x60\x3a",
        .decimals = 18,
    },
    {
        .name = "Keep Network",
        .unit = "KEEP",
        .contract_address =
            "\x85\xee\xe3\x0c\x52\xb0\xb3\x79\xb0\x46\xfb\x0f\x85\xf4\xf3\xdc\x30\x09\xaf\xec",
        .decimals = 18,
    },
    {
        .name = "KEY",
        .unit = "KEY",
        .contract_address =
            "\x4c\xd9\x88\xaf\xba\xd3\x72\x89\xba\xaf\x53\xc1\x3e\x98\xe2\xbd\x46\xaa\xea\x8c",
        .decimals = 18,
    },
    {
        .name = "REBIT",
        .unit = "KEYT",
        .contract_address =
            "\xce\x13\xab\xce\x0d\xb5\xa8\x22\x46\x16\xef\x24\xd3\x97\x9d\x46\x6f\x19\xcf\x90",
        .decimals = 18,
    },
    {
        .name = "Krypton Galaxy Coin",
        .unit = "KGC",
        .contract_address =
            "\xa8\x26\x2e\xb9\x13\xfc\xce\xa4\xc3\xf7\x7f\xc9\x5b\x8b\x40\x43\xb3\x84\xcf\xbb",
        .decimals = 18,
    },
    {
        .name = "Sessia",
        .unit = "KICKS",
        .contract_address =
            "\xd9\x1a\x61\x62\xf1\x46\xef\x85\x92\x2d\x9a\x15\xee\x6e\xb1\x4a\x00\x34\x45\x86",
        .decimals = 18,
    },
    {
        .name = "Kind Ads Token",
        .unit = "KIND",
        .contract_address =
            "\x46\x18\x51\x9d\xe4\xc3\x04\xf3\x44\x4f\xfa\x7f\x81\x2d\xdd\xc2\x97\x1c\xc6\x88",
        .decimals = 8,
    },
    {
        .name = "Khipu Token",
        .unit = "KIP",
        .contract_address =
            "\x64\xe6\x5d\x35\x2f\x6a\x29\x49\x46\x3b\x3a\x75\x95\x91\x1b\x61\xbb\xaf\xc6\x3e",
        .decimals = 18,
    },
    {
        .name = "KanadeCoin",
        .unit = "KNDC",
        .contract_address =
            "\x8e\x56\x10\xab\x5e\x39\xd2\x68\x28\x16\x76\x40\xea\x29\x82\x3f\xe1\xdd\x58\x43",
        .decimals = 8,
    },
    {
        .name = "KNOW",
        .unit = "KNOW",
        .contract_address =
            "\xb4\x1f\x09\xa9\x73\xa8\x5c\x7f\x49\x7c\x10\xb0\x0a\x93\x9d\xe6\x67\xb5\x5a\x78",
        .decimals = 10,
    },
    {
        .name = "Knekted",
        .unit = "KNT",
        .contract_address =
            "\x7c\xc6\x2d\x8e\x80\xbe\x9b\xea\x39\x47\xf3\x44\x3a\xd1\x36\xf5\x0f\x75\xb5\x05",
        .decimals = 18,
    },
    {
        .name = "Kora Network Token",
        .unit = "KNT",
        .contract_address =
            "\xff\x5c\x25\xd2\xf4\x0b\x47\xc4\xa3\x7f\x98\x9d\xe9\x33\xe2\x65\x62\xef\x0a\xc0",
        .decimals = 16,
    },
    {
        .name = "Keystone of Opportunity & Knowledge",
        .unit = "KOK",
        .contract_address =
            "\x7b\xd6\xa4\xe7\xdb\x3a\x34\xc4\x85\xa8\xdd\x02\xb3\x0b\x65\x65\xe3\xbb\xc6\x33",
        .decimals = 18,
    },
    {
        .name = "Darwinia Commitment Token",
        .unit = "KTON",
        .contract_address =
            "\x9f\x28\x4e\x13\x37\xa8\x15\xfe\x77\xd2\xff\x4a\xe4\x65\x44\x64\x5b\x20\xc5\xff",
        .decimals = 18,
    },
    {
        .name = "Kublaicoin",
        .unit = "KUB",
        .contract_address =
            "\xc5\x9c\xb2\x32\x95\xe2\xde\xeb\x66\xbd\x09\x0a\xcb\x6b\x02\xbe\x8d\x30\xa1\x1f",
        .decimals = 10,
    },
    {
        .name = "Kuende",
        .unit = "KUE",
        .contract_address =
            "\xdf\x13\x38\xfb\xaf\xe7\xaf\x17\x89\x15\x16\x27\xb8\x86\x78\x1b\xa5\x56\xef\x9a",
        .decimals = 18,
    },
    {
        .name = "Kuverit",
        .unit = "KUV",
        .contract_address =
            "\xf7\x0d\x16\x01\x02\xcf\x7a\x22\xc1\xe4\x32\xd6\x92\x8a\x9d\x62\x5d\xb9\x11\x70",
        .decimals = 18,
    },
    {
        .name = "KVI",
        .unit = "KVI",
        .contract_address =
            "\x88\x68\xff\x48\x93\x11\x31\x93\x31\x34\x65\xa0\xcc\xc5\xf1\xbd\x37\x0d\x77\x51",
        .decimals = 18,
    },
    {
        .name = "4NEW",
        .unit = "KWATT",
        .contract_address =
            "\x24\x1b\xa6\x72\x57\x4a\x78\xa3\xa6\x04\xcd\xd0\xa9\x44\x29\xa7\x3a\x84\xa3\x24",
        .decimals = 18,
    },
    {
        .name = "KWHCoin",
        .unit = "KWH",
        .contract_address =
            "\xb8\xdd\xc9\x30\xc2\xba\xb6\xc7\x16\x10\xa2\xbe\x63\x90\x36\xe8\x29\xf9\xc1\x0b",
        .decimals = 18,
    },
    {
        .name = "KYSC Token",
        .unit = "KYSC",
        .contract_address =
            "\x7e\x1a\x6f\xb2\x67\x02\xec\xb0\x43\x9a\x64\x1c\x5c\x28\x5f\x7e\xec\x43\x04\x19",
        .decimals = 18,
    },
    {
        .name = "LALA World",
        .unit = "LALA",
        .contract_address =
            "\xfd\x10\x7b\x47\x3a\xb9\x0e\x8f\xbd\x89\x87\x21\x44\xa3\xdc\x92\xc4\x0f\xa8\xc9",
        .decimals = 18,
    },
    {
        .name = "LinkArt",
        .unit = "LAR",
        .contract_address =
            "\x62\x26\xca\xa1\x85\x7a\xfb\xc6\xdf\xb6\xca\x66\x07\x1e\xb2\x41\x22\x80\x31\xa1",
        .decimals = 18,
    },
    {
        .name = "LBK",
        .unit = "LBK",
        .contract_address =
            "\x9c\xb1\xae\xaf\xcc\x8a\x94\x06\x63\x2c\x5b\x08\x42\x46\xea\x72\xf6\x2d\x37\xb6",
        .decimals = 8,
    },
    {
        .name = "LegalBlock",
        .unit = "LBK",
        .contract_address =
            "\xd9\xaf\x2d\x11\xd7\x88\xda\x00\x97\x07\x6f\x4e\xb2\x1b\xd1\xc5\x53\x37\x43\xd9",
        .decimals = 18,
    },
    {
        .name = "Lux Bio Cell",
        .unit = "LBXC",
        .contract_address =
            "\xff\xe5\x10\xa9\x24\x34\xa0\xdf\x34\x6c\x5e\x72\xa3\x49\x4b\x04\x3c\xf2\x49\xeb",
        .decimals = 18,
    },
    {
        .name = "LEOcoin",
        .unit = "LC4",
        .contract_address =
            "\xa8\x3a\xf8\x09\x97\x56\x19\x47\x7a\xf7\x3b\x17\x9e\x05\xe0\x4a\x1c\xce\xa9\x53",
        .decimals = 8,
    },
    {
        .name = "LocalCoinSwap",
        .unit = "LCS",
        .contract_address =
            "\xaa\x19\x96\x1b\x6b\x85\x8d\x9f\x18\xa1\x15\xf2\x5a\xa1\xd9\x8a\xbc\x1f\xdb\xa8",
        .decimals = 18,
    },
    {
        .name = "LCX",
        .unit = "LCX",
        .contract_address =
            "\x03\x7a\x54\xaa\xb0\x62\x62\x8c\x9b\xba\xe1\xfd\xb1\x58\x3c\x19\x55\x85\xfe\x41",
        .decimals = 18,
    },
    {
        .name = "Leadcoin",
        .unit = "LDC",
        .contract_address =
            "\x51\x02\x79\x1c\xa0\x2f\xc3\x59\x53\x98\x40\x0b\xfe\x0e\x33\xd7\xb6\xc8\x22\x67",
        .decimals = 18,
    },
    {
        .name = "Education Ecosystem",
        .unit = "LEDU",
        .contract_address =
            "\xc7\x41\xf0\x60\x82\xaa\x47\xf9\x37\x29\x07\x0a\xd0\xdd\x95\xe2\x23\xbd\xa0\x91",
        .decimals = 8,
    },
    {
        .name = "Linfinity",
        .unit = "LFC",
        .contract_address =
            "\x95\xc9\xbd\x1f\x81\xce\xe7\x39\x1d\xa3\xea\xc8\x16\x93\xe6\x0f\x32\x92\xc1\xe0",
        .decimals = 18,
    },
    {
        .name = "Libertas Token",
        .unit = "LIBERTAS",
        .contract_address =
            "\x49\x18\x4e\x6d\xae\x8c\x8e\xcd\x89\xd8\xbd\xc1\xb9\x50\xc5\x97\xb8\x16\x7c\x90",
        .decimals = 2,
    },
    {
        .name = "Liquidity Dividends Protocol",
        .unit = "LID",
        .contract_address =
            "\x04\x17\x91\x2b\x3a\x7a\xf7\x68\x05\x17\x65\x04\x0a\x55\xbb\x09\x25\xd4\xdd\xcf",
        .decimals = 18,
    },
    {
        .name = "Limestone Network",
        .unit = "LIMEX",
        .contract_address =
            "\x40\x0b\x1d\x8a\x7d\xd8\xc4\x71\x02\x6b\x2c\x8c\xbe\x10\x62\xb2\x7d\x12\x05\x38",
        .decimals = 8,
    },
    {
        .name = "3X Long Chainlink Token",
        .unit = "LINKBULL",
        .contract_address =
            "\x83\xad\x87\xc9\x88\xac\x0c\x62\x77\xc0\xc6\x23\x4c\xc8\x10\x8b\x20\xbb\x5d\x9b",
        .decimals = 18,
    },
    {
        .name = "Coin Lion",
        .unit = "LION",
        .contract_address =
            "\x21\x67\xfb\x82\x30\x9c\xf7\x65\x13\xe8\x3b\x25\x12\x3f\x8b\x05\x59\xd6\xb4\x8f",
        .decimals = 18,
    },
    {
        .name = "LinkCoin Token",
        .unit = "LKN",
        .contract_address =
            "\x9f\x54\x9e\xbf\xd4\x97\x4c\xd4\xed\x4a\x15\x50\xd4\x03\x94\xb4\x4a\x73\x82\xaa",
        .decimals = 18,
    },
    {
        .name = "Latamcash",
        .unit = "LMCH",
        .contract_address =
            "\x92\x05\xc0\x49\xc2\x31\xdd\xa5\x1b\xac\xe0\xba\x56\x9f\x04\x7e\x3e\x1e\x99\x79",
        .decimals = 18,
    },
    {
        .name = "Lisk Machine Learning",
        .unit = "LML",
        .contract_address =
            "\x25\xb6\x32\x5f\x5b\xb1\xc1\xe0\x3c\xfb\xc3\xe5\x3f\x47\x0e\x1f\x1c\xa0\x22\xe3",
        .decimals = 18,
    },
    {
        .name = "LunchMoney",
        .unit = "LMY",
        .contract_address =
            "\x66\xfd\x97\xa7\x8d\x88\x54\xfe\xc4\x45\xcd\x1c\x80\xa0\x78\x96\xb0\xb4\x85\x1f",
        .decimals = 18,
    },
    {
        .name = "Blocklancer",
        .unit = "LNC",
        .contract_address =
            "\x63\xe6\x34\x33\x0a\x20\x15\x0d\xbb\x61\xb1\x56\x48\xbc\x73\x85\x5d\x6c\xcf\x07",
        .decimals = 18,
    },
    {
        .name = "LNX Protocol",
        .unit = "LNX",
        .contract_address =
            "\x5e\x38\x45\xa1\xd7\x8d\xb5\x44\x61\x3e\xdb\xe4\x3d\xc1\xea\x49\x72\x66\xd3\xb8",
        .decimals = 18,
    },
    {
        .name = "LOA Protocol",
        .unit = "LOA",
        .contract_address =
            "\x74\x58\xfd\x78\x6b\x2f\xe8\xcd\x80\x1c\x03\x81\xf8\x8b\x61\xc5\x07\x1a\x00\x6f",
        .decimals = 18,
    },
    {
        .name = "LOCIcoin",
        .unit = "LOCI",
        .contract_address =
            "\x9c\x23\xd6\x7a\xea\x7b\x95\xd8\x09\x42\xe3\x83\x6b\xcd\xf7\xe7\x08\xa7\x47\xc2",
        .decimals = 18,
    },
    {
        .name = "Lukki Operating Token",
        .unit = "LOT",
        .contract_address =
            "\x65\x56\xd2\xec\x4d\x96\xda\x39\xcf\x75\xcb\xe5\x0d\x58\xfa\xe9\x00\x79\x80\x0a",
        .decimals = 18,
    },
    {
        .name = "Lapis Chain",
        .unit = "LPS",
        .contract_address =
            "\x97\xbd\xd9\xfd\xfa\x0b\x16\x77\xa2\xa3\x53\x84\x85\x14\xd9\x3c\x10\x8b\xec\x85",
        .decimals = 10,
    },
    {
        .name = "Livepeer",
        .unit = "LPT",
        .contract_address =
            "\x58\xb6\xa8\xa3\x30\x23\x69\xda\xec\x38\x33\x34\x67\x24\x04\xee\x73\x3a\xb2\x39",
        .decimals = 18,
    },
    {
        .name = "Liquidity Network",
        .unit = "LQD",
        .contract_address =
            "\xd2\x9f\x0b\x5b\x3f\x50\xb0\x7f\xe9\xa9\x51\x1f\x7d\x86\xf4\xf4\xba\xc3\xf8\xc4",
        .decimals = 18,
    },
    {
        .name = "3x Short Litecoin Token",
        .unit = "LTCBEAR",
        .contract_address =
            "\xb4\x22\xe6\x05\xfb\xd7\x65\xb8\x0d\x2c\x4b\x5d\x81\x96\xc2\xf9\x41\x44\x43\x8b",
        .decimals = 18,
    },
    {
        .name = "3x Long Litecoin Token",
        .unit = "LTCBULL",
        .contract_address =
            "\xdb\x61\x35\x4e\x9c\xf2\x21\x7a\x29\x77\x0e\x98\x11\x83\x2b\x36\x0a\x8d\xaa\xd3",
        .decimals = 18,
    },
    {
        .name = "LitecoinToken",
        .unit = "LTK",
        .contract_address =
            "\x8a\x73\x2b\xc9\x1c\x33\xc1\x67\xf8\x68\xe0\xaf\x7e\x6f\x31\xe0\x77\x6d\x0f\x71",
        .decimals = 18,
    },
    {
        .name = "Level Up Coin",
        .unit = "LUC",
        .contract_address =
            "\x5d\xbe\x29\x6f\x97\xb2\x3c\x4a\x6a\xa6\x18\x3d\x73\xe5\x74\xd0\x2b\xa5\xc7\x19",
        .decimals = 18,
    },
    {
        .name = "LivenPay",
        .unit = "LVN",
        .contract_address =
            "\xc8\xca\xc7\x67\x2f\x46\x69\x68\x58\x17\xcf\x33\x2a\x33\xeb\x24\x9f\x08\x54\x75",
        .decimals = 18,
    },
    {
        .name = "Level01",
        .unit = "LVX",
        .contract_address =
            "\x26\x16\x38\xec\x8e\xe8\x10\x04\x84\x13\x0e\xbd\x2f\xeb\xfd\xad\xc0\xd8\x74\x2a",
        .decimals = 18,
    },
    {
        .name = "LUKSO",
        .unit = "LYXe",
        .contract_address =
            "\xa8\xb9\x19\x68\x02\x58\xd3\x69\x11\x49\x10\x51\x1c\xc8\x75\x95\xae\xc0\xbe\x6d",
        .decimals = 18,
    },
    {
        .name = "Matrexcoin",
        .unit = "MAC",
        .contract_address =
            "\xc3\xe2\xde\x0b\x66\x1c\xf5\x8f\x66\xbd\xe8\xe8\x96\x90\x53\x99\xde\xd5\x8a\xf5",
        .decimals = 0,
    },
    {
        .name = "MACH Project",
        .unit = "MACH",
        .contract_address =
            "\xb1\x19\xce\x94\xd0\x98\xc1\x8f\xe3\x80\x90\x4c\x24\xe3\x58\xbd\x88\x7f\x00\xbe",
        .decimals = 18,
    },
    {
        .name = "Master Coin Point",
        .unit = "MACPO",
        .contract_address =
            "\x63\xbf\x01\x26\xc6\xc4\xd1\x7b\xb3\x3c\x36\x21\x51\x75\x9e\xc2\x1b\x36\x53\x7b",
        .decimals = 18,
    },
    {
        .name = "MarcoPolo Protocol",
        .unit = "MAP",
        .contract_address =
            "\x49\x22\x9c\x39\x02\xd4\x9b\xe6\x44\x3e\x01\xc0\x25\x1b\x02\x78\x03\x97\xab\x1a",
        .decimals = 18,
    },
    {
        .name = "MidasProtocol",
        .unit = "MAS",
        .contract_address =
            "\x23\xcc\xc4\x33\x65\xd9\xdd\x38\x82\xea\xb8\x8f\x43\xd5\x15\x20\x8f\x83\x24\x30",
        .decimals = 18,
    },
    {
        .name = "MASTERNET",
        .unit = "MASH",
        .contract_address =
            "\xa0\xd4\x40\xc6\xda\x37\x89\x2d\xc0\x6e\xe7\x93\x0b\x2e\xed\xe0\x63\x4f\xd6\x81",
        .decimals = 8,
    },
    {
        .name = "MATH",
        .unit = "MATH",
        .contract_address =
            "\x08\xd9\x67\xbb\x01\x34\xf2\xd0\x7f\x7c\xfb\x6e\x24\x66\x80\xc5\x39\x27\xdd\x30",
        .decimals = 18,
    },
    {
        .name = "3X Short Matic Token",
        .unit = "MATICBEAR",
        .contract_address =
            "\xbe\x89\x3b\x4c\x21\x4d\xbf\xfc\x17\xef\x1e\x33\x8f\xbd\xb7\x06\x1f\xf0\x92\x37",
        .decimals = 18,
    },
    {
        .name = "3X Long Matic Token",
        .unit = "MATICBULL",
        .contract_address =
            "\x7e\x03\x52\x1b\x9d\xa8\x91\xca\x3f\x79\xa8\x72\x8e\x2e\xae\xb2\x48\x86\xc5\xf9",
        .decimals = 18,
    },
    {
        .name = "MAX Exchange Token",
        .unit = "MAX",
        .contract_address =
            "\xe7\x97\x6c\x4e\xfc\x60\xd9\xf4\xc2\x00\xcc\x1b\xce\xf1\xa1\xe3\xb0\x2c\x73\xe7",
        .decimals = 18,
    },
    {
        .name = "Membrana",
        .unit = "MBN",
        .contract_address =
            "\x4e\xee\xa7\xb4\x8b\x9c\x3a\xc8\xf7\x0a\x9c\x93\x2a\x8b\x1e\x8a\x5c\xb6\x24\xc7",
        .decimals = 18,
    },
    {
        .name = "MCDEX",
        .unit = "MCB",
        .contract_address =
            "\x4e\x35\x2c\xf1\x64\xe6\x4a\xdc\xba\xd3\x18\xc3\xa1\xe2\x22\xe9\xeb\xa4\xce\x42",
        .decimals = 18,
    },
    {
        .name = "Medium",
        .unit = "MDM",
        .contract_address =
            "\xd2\x4d\xff\x61\x17\x93\x6b\x6f\xf9\x71\x08\xcf\x26\xc1\xdd\x88\x65\x74\x3d\x87",
        .decimals = 18,
    },
    {
        .name = "All.me",
        .unit = "ME",
        .contract_address =
            "\x47\x14\x0a\x76\x7a\x86\x1f\x7a\x1f\x3b\x0d\xd2\x2a\x2f\x46\x34\x21\xc2\x88\x14",
        .decimals = 18,
    },
    {
        .name = "CoinMeet",
        .unit = "MEET",
        .contract_address =
            "\x7f\x12\x1d\x4e\xc6\xc2\xc0\x7e\xb6\xbc\x79\x89\xd9\x1d\x2d\x4f\xf6\x54\xc0\x68",
        .decimals = 18,
    },
    {
        .name = "MesChain",
        .unit = "MES",
        .contract_address =
            "\x32\x2f\x4f\x6a\x48\x32\x96\x90\x95\x7a\x3b\xcb\xd1\x30\x15\x16\xc2\xb8\x3c\x1f",
        .decimals = 8,
    },
    {
        .name = "MESG",
        .unit = "MESG",
        .contract_address =
            "\x42\x01\x67\xd8\x7d\x35\xc3\xa2\x49\xb3\x2e\xf6\x22\x58\x72\xfb\xd9\xab\x85\xd2",
        .decimals = 18,
    },
    {
        .name = "MetaMorph",
        .unit = "METM",
        .contract_address =
            "\xfe\xf3\x88\x4b\x60\x3c\x33\xef\x8e\xd4\x18\x33\x46\xe0\x93\xa1\x73\xc9\x4d\xa6",
        .decimals = 18,
    },
    {
        .name = "MEX",
        .unit = "MEX",
        .contract_address =
            "\x2b\xa6\xb1\xe4\x42\x4e\x19\x81\x63\x82\xd1\x59\x37\x73\x99\x59\xf7\xda\x5f\xd8",
        .decimals = 18,
    },
    {
        .name = "SyncFab",
        .unit = "MFG",
        .contract_address =
            "\x67\x10\xc6\x34\x32\xa2\xde\x02\x95\x4f\xc0\xf8\x51\xdb\x07\x14\x6a\x6c\x03\x12",
        .decimals = 18,
    },
    {
        .name = "Mainstream For The Underground",
        .unit = "MFTU",
        .contract_address =
            "\x05\xd4\x12\xce\x18\xf2\x40\x40\xbb\x3f\xa4\x5c\xf2\xc6\x9e\x50\x65\x86\xd8\xe8",
        .decimals = 18,
    },
    {
        .name = "MGC Token",
        .unit = "MGC",
        .contract_address =
            "\x17\x4b\xfa\x66\x00\xbf\x90\xc8\x85\xc7\xc0\x1c\x70\x31\x38\x9e\xd1\x46\x1a\xb9",
        .decimals = 18,
    },
    {
        .name = "MobileGo",
        .unit = "MGO",
        .contract_address =
            "\x40\x39\x50\x44\xac\x3c\x0c\x57\x05\x19\x06\xda\x93\x8b\x54\xbd\x65\x57\xf2\x12",
        .decimals = 8,
    },
    {
        .name = "Micromines",
        .unit = "MICRO",
        .contract_address =
            "\xbe\x6c\x8f\x28\x10\xef\x39\x42\x0d\x2d\xc2\x90\x1b\x84\x14\xc8\xc4\x5f\xee\x6d",
        .decimals = 18,
    },
    {
        .name = "MiniSwap",
        .unit = "MINI",
        .contract_address =
            "\x4d\x95\x3c\xf0\x77\xc0\xc9\x5b\xa0\x90\x22\x6e\x59\xa1\x8f\xcf\x97\xdb\x44\xec",
        .decimals = 18,
    },
    {
        .name = "MixMarvel",
        .unit = "MIX",
        .contract_address =
            "\x5d\x28\x5f\x73\x59\x98\xf3\x66\x31\xf6\x78\xff\x41\xfb\x56\xa1\x0a\x4d\x04\x29",
        .decimals = 18,
    },
    {
        .name = "Mallcoin",
        .unit = "MLC",
        .contract_address =
            "\xc7\x2e\xd4\x44\x5b\x3f\xe9\xf0\x86\x31\x06\xe3\x44\xe2\x41\x53\x0d\x33\x89\x06",
        .decimals = 18,
    },
    {
        .name = "Mega Lottery Services Global",
        .unit = "MLR",
        .contract_address =
            "\xf2\x68\x93\xf8\x9b\x23\x08\x4c\x4c\x62\x16\x03\x8d\x6e\xbd\xbe\x9e\x96\xc5\xcb",
        .decimals = 18,
    },
    {
        .name = "Maincoin",
        .unit = "MNC",
        .contract_address =
            "\x9f\x0f\x1b\xe0\x85\x91\xab\x7d\x99\x0f\xaf\x91\x0b\x38\xed\x5d\x60\xe4\xd5\xbf",
        .decimals = 18,
    },
    {
        .name = "Moneynet",
        .unit = "MNC",
        .contract_address =
            "\xba\xc7\xa1\x79\x83\x50\xcd\xf2\xdb\xfe\x0c\x21\x0c\x2c\x98\x61\x22\x3f\x4b\x31",
        .decimals = 18,
    },
    {
        .name = "Minereum",
        .unit = "MNE",
        .contract_address =
            "\x1a\x95\xb2\x71\xb0\x53\x5d\x15\xfa\x49\x93\x2d\xab\xa3\x1b\xa6\x12\xb5\x29\x46",
        .decimals = 8,
    },
    {
        .name = "Money Token",
        .unit = "MNT",
        .contract_address =
            "\x31\x0d\xa5\xe1\xe6\x1c\xd9\xd6\xec\xed\x09\x2f\x08\x59\x41\x08\x92\x67\xe7\x1e",
        .decimals = 18,
    },
    {
        .name = "MODEL-X-coin",
        .unit = "MODX",
        .contract_address =
            "\x3c\x6d\xa7\x76\x3c\xaa\x0e\x4b\x68\x4b\xbc\x73\x3f\x04\xa8\xec\x08\xaf\x37\x62",
        .decimals = 8,
    },
    {
        .name = "Mogu",
        .unit = "MOGX",
        .contract_address =
            "\xbd\xec\x45\x95\x2b\x5e\x23\x4e\xdd\xc2\x98\x1b\x43\xee\xd3\x60\x82\x6d\x50\x87",
        .decimals = 18,
    },
    {
        .name = "MorCrypto Coin",
        .unit = "MOR",
        .contract_address =
            "\xae\x74\x65\x20\xff\xdb\x15\xd0\x50\x5e\x32\xf1\xd6\xe9\xa2\xb4\xab\x86\x65\x72",
        .decimals = 18,
    },
    {
        .name = "More Coin",
        .unit = "MORE",
        .contract_address =
            "\x59\x06\x1b\x6f\x26\xbb\x4a\x9c\xe5\x82\x8a\x19\xd3\x5c\xfd\x5a\x4b\x80\xf0\x56",
        .decimals = 8,
    },
    {
        .name = "MARK.SPACE",
        .unit = "MRK",
        .contract_address =
            "\xf4\x53\xb5\xb9\xd4\xe0\xb5\xc6\x2f\xfb\x25\x6b\xb2\x37\x8c\xc2\xbc\x8e\x8a\x89",
        .decimals = 8,
    },
    {
        .name = "Monarch",
        .unit = "MT",
        .contract_address =
            "\x44\x42\x55\x6a\x08\xa8\x41\x22\x7b\xef\x04\xc6\x7a\x7b\xa7\xac\xf0\x1b\x6f\xc8",
        .decimals = 18,
    },
    {
        .name = "MyToken",
        .unit = "MT",
        .contract_address =
            "\x9b\x4e\x2b\x4b\x13\xd1\x25\x23\x8a\xa0\x48\x0d\xd4\x2b\x4f\x6f\xc7\x1b\x37\xcc",
        .decimals = 18,
    },
    {
        .name = "Meta",
        .unit = "MTA",
        .contract_address =
            "\xa3\xbe\xd4\xe1\xc7\x5d\x00\xfa\x6f\x4e\x5e\x69\x22\xdb\x72\x61\xb5\xe9\xac\xd2",
        .decimals = 18,
    },
    {
        .name = "MTC Mesh Network",
        .unit = "MTC",
        .contract_address =
            "\xdf\xdc\x0d\x82\xd9\x6f\x8f\xd4\x0c\xa0\xcf\xb4\xa2\x88\x95\x5b\xec\xec\x20\x88",
        .decimals = 18,
    },
    {
        .name = "Medicalchain",
        .unit = "MTN",
        .contract_address =
            "\x41\xdb\xec\xc1\xcd\xc5\x51\x7c\x6f\x76\xf6\xa6\xe8\x36\xad\xbe\xe2\x75\x4d\xe3",
        .decimals = 18,
    },
    {
        .name = "Meter",
        .unit = "MTRG",
        .contract_address =
            "\xaa\x8d\x0e\x9a\x26\x85\x3d\x51\x61\x3c\xa7\x57\x29\xcd\xe2\x56\x49\x13\xbc\xfb",
        .decimals = 18,
    },
    {
        .name = "Matryx",
        .unit = "MTX",
        .contract_address =
            "\x0a\xf4\x4e\x27\x84\x63\x72\x18\xdd\x1d\x32\xa3\x22\xd4\x4e\x60\x3a\x8f\x0c\x6a",
        .decimals = 18,
    },
    {
        .name = "mStable USD",
        .unit = "MUSD",
        .contract_address =
            "\xe2\xf2\xa5\xc2\x87\x99\x33\x45\xa8\x40\xdb\x3b\x08\x45\xfb\xc7\x0f\x59\x35\xa5",
        .decimals = 18,
    },
    {
        .name = "Maverick Chain",
        .unit = "MVC",
        .contract_address =
            "\xb1\x7d\xf9\xa3\xb0\x95\x83\xa9\xbd\xcf\x75\x7d\x63\x67\x17\x14\x76\xd4\xd8\xa3",
        .decimals = 18,
    },
    {
        .name = "Merculet",
        .unit = "MVP",
        .contract_address =
            "\x8a\x77\xe4\x09\x36\xbb\xc2\x7e\x80\xe9\xa3\xf5\x26\x36\x8c\x96\x78\x69\xc8\x6d",
        .decimals = 18,
    },
    {
        .name = "MyBit",
        .unit = "MYB",
        .contract_address =
            "\x5d\x60\xd8\xd7\xef\x6d\x37\xe1\x6e\xba\xbc\x32\x4d\xe3\xbe\x57\xf1\x35\xe0\xbc",
        .decimals = 18,
    },
    {
        .name = "Mysterium",
        .unit = "MYST",
        .contract_address =
            "\xa6\x45\x26\x4c\x56\x03\xe9\x6c\x3b\x0b\x07\x8c\xda\xb6\x87\x33\x79\x4b\x0a\x71",
        .decimals = 8,
    },
    {
        .name = "MoCo Token",
        .unit = "MoCo",
        .contract_address =
            "\x06\xa8\xf2\xbc\xc6\x22\xac\x55\xd5\x96\xea\x02\xce\x5b\xb5\xf3\x18\xf4\x85\xe9",
        .decimals = 18,
    },
    {
        .name = "NANJCOIN",
        .unit = "NANJ",
        .contract_address =
            "\xff\xe0\x2e\xe4\xc6\x9e\xdf\x1b\x34\x0f\xca\xd6\x4f\xbd\x6b\x37\xa7\xb9\xe2\x65",
        .decimals = 8,
    },
    {
        .name = "Natmin Pure Escrow",
        .unit = "NAT",
        .contract_address =
            "\x90\xd4\x6a\x96\x36\xb9\x73\xf1\x81\x86\x54\x1d\x1b\x04\xed\x36\x21\xa4\x9c\xb0",
        .decimals = 18,
    },
    {
        .name = "Naviaddress",
        .unit = "NAVI",
        .contract_address =
            "\x58\x80\x47\x36\x5d\xf5\xba\x58\x9f\x92\x36\x04\xaa\xc2\x3d\x67\x35\x55\xc6\x23",
        .decimals = 18,
    },
    {
        .name = "BoatPilot Token",
        .unit = "NAVY",
        .contract_address =
            "\xc1\x5a\x39\x9c\x4e\xa7\x81\x5f\xe3\x68\x57\xc9\xe2\x90\xee\x45\x2a\x5d\x6b\x21",
        .decimals = 18,
    },
    {
        .name = "Naka Bodhi Token",
        .unit = "NBOT",
        .contract_address =
            "\x09\xcc\xd2\xda\x5d\xcd\xd0\x51\x02\x68\xd4\x97\x9e\x79\x23\x81\x33\x71\x38\xb8",
        .decimals = 18,
    },
    {
        .name = "NeuroChain",
        .unit = "NCC",
        .contract_address =
            "\x5d\x48\xf2\x93\xba\xed\x24\x7a\x2d\x01\x89\x05\x8b\xa3\x7a\xa2\x38\xbd\x47\x25",
        .decimals = 18,
    },
    {
        .name = "NDN Link",
        .unit = "NDN",
        .contract_address =
            "\x6e\xc4\x7a\x17\x8a\x9d\x50\xd4\xec\x46\x83\x00\x3d\x83\x24\xf1\x9c\xa3\x53\x82",
        .decimals = 18,
    },
    {
        .name = "nDEX",
        .unit = "NDX",
        .contract_address =
            "\x19\x66\xd7\x18\xa5\x65\x56\x6e\x8e\x20\x27\x92\x65\x8d\x7b\x5f\xf4\xec\xe4\x69",
        .decimals = 18,
    },
    {
        .name = "Coineal Token",
        .unit = "NEAL",
        .contract_address =
            "\xac\xce\x88\xf5\xa6\x3a\x5e\x65\xdb\x9a\xa7\x30\x37\x20\xbe\x16\xb5\x56\xe7\x51",
        .decimals = 18,
    },
    {
        .name = "NEST Protocol",
        .unit = "NEST",
        .contract_address =
            "\x04\xab\xed\xa2\x01\x85\x0a\xc0\x12\x41\x61\xf0\x37\xef\xd7\x0c\x74\xdd\xc7\x4c",
        .decimals = 18,
    },
    {
        .name = "NewsToken",
        .unit = "NEWOS",
        .contract_address =
            "\x29\x53\x6b\x7c\xa7\x02\x9b\x5c\xdd\xeb\x03\xc0\x45\x17\x15\x61\x5a\xca\x35\xba",
        .decimals = 8,
    },
    {
        .name = "Nexxo",
        .unit = "NEXXO",
        .contract_address =
            "\x27\x8a\x83\xb6\x4c\x3e\x3e\x11\x39\xf8\xe8\xa5\x2d\x96\x36\x0c\xa3\xc6\x9a\x3d",
        .decimals = 18,
    },
    {
        .name = "NFX Coin",
        .unit = "NFXC",
        .contract_address =
            "\x2d\x39\xec\x4d\xa5\x43\x29\xd2\x8d\x23\x0b\x49\x73\xf5\xaa\x27\x88\x6c\x3a\xee",
        .decimals = 18,
    },
    {
        .name = "Autonio",
        .unit = "NIO",
        .contract_address =
            "\x55\x54\xe0\x4e\x76\x53\x3e\x1d\x14\xc5\x2f\x05\xbe\xef\x6c\x9d\x32\x9e\x1e\x30",
        .decimals = 0,
    },
    {
        .name = "Nework",
        .unit = "NKC",
        .contract_address =
            "\x5a\x1a\x29\xdb\xb6\xad\x61\x53\xdb\x76\x45\x68\xc1\x28\x90\x76\xbc\x87\x6d\xf6",
        .decimals = 18,
    },
    {
        .name = "Neuromorphic.io",
        .unit = "NMP",
        .contract_address =
            "\x4d\x6b\x9f\x28\x1a\xf3\x19\x16\xa0\xf1\x6d\x1c\xea\x2e\xc7\x38\x48\x51\xea\xab",
        .decimals = 18,
    },
    {
        .name = "NNB Token",
        .unit = "NNB",
        .contract_address =
            "\xb6\x6a\x21\x31\xa6\xb8\x40\xdd\x02\x01\x51\xf8\x07\x23\xca\xed\x60\x3e\xfb\x51",
        .decimals = 18,
    },
    {
        .name = "No BS Crypto",
        .unit = "NOBS",
        .contract_address =
            "\xf4\xfa\xea\x45\x55\x75\x35\x4d\x26\x99\xbc\x20\x9b\x0a\x65\xca\x99\xf6\x99\x82",
        .decimals = 18,
    },
    {
        .name = "Whole Network",
        .unit = "NODE",
        .contract_address =
            "\x0c\x3e\xf3\x2f\x80\x29\x67\xdb\x75\xb9\xd4\x9f\xe1\xe7\x66\x20\x15\x1c\xcb\x81",
        .decimals = 5,
    },
    {
        .name = "NOIA Network",
        .unit = "NOIA",
        .contract_address =
            "\xfc\x85\x81\x54\xc0\xb2\xc4\xa3\x32\x30\x46\xfb\x50\x58\x11\xf1\x10\xeb\xda\x57",
        .decimals = 18,
    },
    {
        .name = "Noku",
        .unit = "NOKU",
        .contract_address =
            "\x1f\xc5\x2f\x1a\xba\xde\x45\x2d\xd4\x67\x44\x77\xd4\x71\x19\x51\x70\x0b\x3d\x27",
        .decimals = 18,
    },
    {
        .name = "Plus-Coin",
        .unit = "NPLC",
        .contract_address =
            "\x97\xfb\x6f\xc2\xad\x53\x20\x33\xaf\x97\x04\x3b\x56\x31\x31\xc5\x20\x4f\x8a\x35",
        .decimals = 18,
    },
    {
        .name = "Neural Protocol",
        .unit = "NRP",
        .contract_address =
            "\x39\x18\xc4\x2f\x14\xf2\xeb\x11\x68\x36\x5f\x91\x1f\x63\xe5\x40\xe5\xa3\x06\xb5",
        .decimals = 8,
    },
    {
        .name = "Neurotoken",
        .unit = "NTK",
        .contract_address =
            "\x69\xbe\xab\x40\x34\x38\x25\x3f\x13\xb6\xe9\x2d\xb9\x1f\x7f\xb8\x49\x25\x82\x63",
        .decimals = 18,
    },
    {
        .name = "NetKoin",
        .unit = "NTK",
        .contract_address =
            "\x5d\x4d\x57\xcd\x06\xfa\x7f\xe9\x9e\x26\xfd\xc4\x81\xb4\x68\xf7\x7f\x05\x07\x3c",
        .decimals = 18,
    },
    {
        .name = "Nuggets",
        .unit = "NUG",
        .contract_address =
            "\x24\x5e\xf4\x7d\x4d\x05\x05\xec\xf3\xac\x46\x3f\x4d\x81\xf4\x1a\xde\x8f\x1f\xd1",
        .decimals = 18,
    },
    {
        .name = "Neutral Dollar ",
        .unit = "NUSD",
        .contract_address =
            "\x0c\x61\x44\xc1\x6a\xf2\x88\x94\x8c\x8f\xdb\x37\xfd\x8f\xec\x94\xbf\xf3\xd1\xd9",
        .decimals = 6,
    },
    {
        .name = "NXM",
        .unit = "NXM",
        .contract_address =
            "\xd7\xc4\x9c\xee\x7e\x91\x88\xcc\xa6\xad\x8f\xf2\x64\xc1\xda\x2e\x69\xd4\xcf\x3b",
        .decimals = 18,
    },
    {
        .name = "Origin Protocol",
        .unit = "OGN",
        .contract_address =
            "\x82\x07\xc1\xff\xc5\xb6\x80\x4f\x60\x24\x32\x2c\xcf\x34\xf2\x9c\x35\x41\xae\x26",
        .decimals = 18,
    },
    {
        .name = "Okschain",
        .unit = "OKS",
        .contract_address =
            "\x7b\x68\xd2\x72\xed\xa2\x18\x5e\xa2\xf9\x28\x3f\x24\x1b\x1c\x44\xc5\x1e\x71\x2a",
        .decimals = 18,
    },
    {
        .name = "Olive",
        .unit = "OLE",
        .contract_address =
            "\x9d\x92\x23\x43\x6d\xdd\x46\x6f\xc2\x47\xe9\xdb\xbd\x20\x20\x7e\x64\x0f\xef\x58",
        .decimals = 18,
    },
    {
        .name = "OLXA",
        .unit = "OLXA",
        .contract_address =
            "\x59\x25\xf6\x7d\x27\x67\xd9\x37\xf4\x71\x41\xda\xc2\x41\x66\xb4\x69\x55\x82\x22",
        .decimals = 2,
    },
    {
        .name = "Ormeus Cash",
        .unit = "OMC",
        .contract_address =
            "\xd6\xbd\x97\xa2\x62\x32\xba\x02\x17\x2f\xf8\x6b\x05\x5d\x5d\x7b\xe7\x89\x33\x5b",
        .decimals = 18,
    },
    {
        .name = "Shivom",
        .unit = "OMX",
        .contract_address =
            "\xb5\xdb\xc6\xd3\xcf\x38\x00\x79\xdf\x3b\x27\x13\x56\x64\xb6\xbc\xf4\x5d\x18\x69",
        .decimals = 8,
    },
    {
        .name = "Menlo One",
        .unit = "ONE",
        .contract_address =
            "\x4d\x80\x75\x09\xae\xce\x24\xc0\xfa\x5a\x10\x2b\x6a\x3b\x05\x9e\xc6\xe1\x43\x92",
        .decimals = 18,
    },
    {
        .name = "SoMee.Social",
        .unit = "ONG",
        .contract_address =
            "\xd3\x41\xd1\x68\x0e\xee\xe3\x25\x5b\x8c\x4c\x75\xbc\xce\x7e\xb5\x7f\x14\x4d\xae",
        .decimals = 18,
    },
    {
        .name = "On.Live",
        .unit = "ONL",
        .contract_address =
            "\x68\x63\xbe\x0e\x7c\xf7\xce\x86\x0a\x57\x47\x60\xe9\x02\x0d\x51\x9a\x8b\xdc\x47",
        .decimals = 18,
    },
    {
        .name = "ONOToken",
        .unit = "ONOT",
        .contract_address =
            "\xb3\x1c\x21\x99\x59\xe0\x6f\x9a\xfb\xeb\x36\xb3\x88\xa4\xba\xd1\x3e\x80\x27\x25",
        .decimals = 18,
    },
    {
        .name = "Open Platform",
        .unit = "OPEN",
        .contract_address =
            "\x9d\x86\xb1\xb2\x55\x4e\xc4\x10\xec\xcf\xfb\xf1\x11\xa6\x99\x49\x10\x11\x13\x40",
        .decimals = 8,
    },
    {
        .name = "Opennity",
        .unit = "OPNN",
        .contract_address =
            "\xa8\x29\xf9\x73\x73\x06\x9e\xe5\xd2\x31\x75\xe4\x10\x5d\xf8\xfd\x49\x23\x8b\xe7",
        .decimals = 18,
    },
    {
        .name = "Opus",
        .unit = "OPT",
        .contract_address =
            "\x43\x55\xfc\x16\x0f\x74\x32\x8f\x9b\x38\x3d\xf2\xec\x58\x9b\xb3\xdf\xd8\x2b\xa0",
        .decimals = 18,
    },
    {
        .name = "OptiToken",
        .unit = "OPTI",
        .contract_address =
            "\x83\x29\x04\x86\x39\x78\xb9\x48\x02\x12\x31\x06\xe6\xeb\x49\x1b\xdf\x0d\xf9\x28",
        .decimals = 18,
    },
    {
        .name = "Originate Coin",
        .unit = "ORC",
        .contract_address =
            "\x1c\x09\xef\x44\x93\x46\x55\x69\xf6\xd7\x04\xa5\xcc\x4f\x98\x64\xbc\xd2\xe5\x6a",
        .decimals = 18,
    },
    {
        .name = "Origami",
        .unit = "ORI",
        .contract_address =
            "\xd2\xfa\x8f\x92\xea\x72\xab\xb3\x5d\xbd\x6d\xec\xa5\x71\x73\xd2\x2d\xb2\xba\x49",
        .decimals = 18,
    },
    {
        .name = "Ormeus Coin",
        .unit = "ORMEUS",
        .contract_address =
            "\xc9\x6d\xf9\x21\x00\x9b\x79\x0d\xff\xca\x41\x23\x75\x25\x1e\xd1\xa2\xb7\x5c\x60",
        .decimals = 8,
    },
    {
        .name = "Orion Protocol",
        .unit = "ORN",
        .contract_address =
            "\x8f\xb0\x0f\xde\xbb\x4e\x83\xf2\xc5\x8b\x3b\xcd\x67\x32\xac\x1b\x6a\x7b\x72\x21",
        .decimals = 8,
    },
    {
        .name = "Cointorox",
        .unit = "OROX",
        .contract_address =
            "\x1c\x5b\x76\x0f\x13\x32\x20\x85\x53\x40\x00\x3b\x43\xcc\x91\x13\xec\x49\x48\x23",
        .decimals = 18,
    },
    {
        .name = "OSA Token",
        .unit = "OSA",
        .contract_address =
            "\xc6\xab\xf3\xc0\x93\x41\x74\x1a\xc6\x04\x1b\x0b\x08\x19\x57\x01\xbd\xfd\x46\x0c",
        .decimals = 18,
    },
    {
        .name = "OTCBTC Token",
        .unit = "OTB",
        .contract_address =
            "\xa8\x6a\x0d\xa9\xd0\x5d\x07\x71\x95\x5d\xf0\x5b\x44\xca\x12\x06\x61\xaf\x16\xde",
        .decimals = 18,
    },
    {
        .name = "Open Trading Network",
        .unit = "OTN",
        .contract_address =
            "\x88\x1e\xf4\x82\x11\x98\x2d\x01\xe2\xcb\x70\x92\xc9\x15\xe6\x47\xcd\x40\xd8\x5c",
        .decimals = 18,
    },
    {
        .name = "OWNDATA",
        .unit = "OWN",
        .contract_address =
            "\x17\x0b\x27\x5c\xed\x08\x9f\xff\xae\xbf\xe9\x27\xf4\x45\xa3\x50\xed\x91\x60\xdc",
        .decimals = 8,
    },
    {
        .name = "Orchid",
        .unit = "OXT",
        .contract_address =
            "\x45\x75\xf4\x13\x08\xec\x14\x83\xf3\xd3\x99\xaa\x9a\x28\x26\xd7\x4d\xa1\x3d\xeb",
        .decimals = 18,
    },
    {
        .name = "Oxycoin",
        .unit = "OXY",
        .contract_address =
            "\x86\x9b\x1f\x57\x38\x0a\xe5\x01\xd3\x87\xb1\x92\x62\xef\xd3\xc0\xeb\x75\x01\xb0",
        .decimals = 18,
    },
    {
        .name = "P2P Global Network",
        .unit = "P2PX",
        .contract_address =
            "\xce\xce\xde\x5a\x20\x64\x5e\xac\x6c\xa2\x03\x2e\xee\xb1\x06\x35\x72\xd6\x3c\x29",
        .decimals = 18,
    },
    {
        .name = "Pamp Network",
        .unit = "PAMP",
        .contract_address =
            "\xf0\xfa\xc7\x10\x4a\xac\x54\x4e\x4a\x7c\xe1\xa5\x5a\xdf\x2b\x5a\x25\xc6\x5b\xd1",
        .decimals = 18,
    },
    {
        .name = "Pantos",
        .unit = "PAN",
        .contract_address =
            "\x53\x63\x81\xa8\x62\x8d\xbc\xc8\xc7\x0a\xc9\xa3\x0a\x72\x58\x44\x2e\xab\x4c\x92",
        .decimals = 8,
    },
    {
        .name = "Parachute",
        .unit = "PAR",
        .contract_address =
            "\x1b\xee\xf3\x19\x46\xfb\xbb\x40\xb8\x77\xa7\x2e\x4a\xe0\x4a\x8d\x1a\x5c\xee\x06",
        .decimals = 18,
    },
    {
        .name = "PARETO Rewards",
        .unit = "PARETO",
        .contract_address =
            "\xea\x5f\x88\xe5\x4d\x98\x2c\xbb\x0c\x44\x1c\xde\x4e\x79\xbc\x30\x5e\x5b\x43\xbc",
        .decimals = 18,
    },
    {
        .name = "Blockpass",
        .unit = "PASS",
        .contract_address =
            "\xee\x44\x58\xe0\x52\xb5\x33\xb1\xaa\xbd\x49\x3b\x5f\x8c\x4d\x85\xd7\xb2\x63\xdc",
        .decimals = 6,
    },
    {
        .name = "Patron",
        .unit = "PAT",
        .contract_address =
            "\xf3\xb3\xca\xd0\x94\xb8\x93\x92\xfc\xe5\xfa\xfd\x40\xbc\x03\xb8\x0f\x2b\xc6\x24",
        .decimals = 18,
    },
    {
        .name = "Promotion Coin",
        .unit = "PC",
        .contract_address =
            "\xa6\x71\x4a\x2e\x5f\x0b\x1b\xdb\x97\xb8\x95\xb0\x91\x3b\x4f\xcd\x3a\x77\x5e\x4d",
        .decimals = 5,
    },
    {
        .name = "POPCHAIN",
        .unit = "PCH",
        .contract_address =
            "\xe3\xf4\xb4\xa5\xd9\x1e\x5c\xb9\x43\x5b\x94\x7f\x09\x0a\x31\x97\x37\x03\x63\x12",
        .decimals = 18,
    },
    {
        .name = "Precium",
        .unit = "PCM",
        .contract_address =
            "\x60\x96\xd2\x46\x0c\xf5\x17\x7e\x40\xb5\x15\x22\x34\x28\xdc\x00\x5a\xd3\x51\x23",
        .decimals = 18,
    },
    {
        .name = "PDATA",
        .unit = "PDATA",
        .contract_address =
            "\x0d\xb0\x3b\x6c\xde\x0b\x2d\x42\x7c\x64\xa0\x4f\xea\xfd\x82\x59\x38\x36\x8f\x1f",
        .decimals = 18,
    },
    {
        .name = "MarketPeak",
        .unit = "PEAK",
        .contract_address =
            "\x63\x3e\xe3\xfb\xe5\xff\xc0\x5b\xd4\x4e\xcd\x82\x40\x73\x2f\xf9\xef\x9d\xee\x1d",
        .decimals = 8,
    },
    {
        .name = "PeerEx",
        .unit = "PERX",
        .contract_address =
            "\x3c\x6f\xf5\x0c\x9e\xc3\x62\xef\xa3\x59\x31\x70\x09\x42\x8d\x52\x11\x5f\xe6\x43",
        .decimals = 18,
    },
    {
        .name = "Payfair",
        .unit = "PFR",
        .contract_address =
            "\xb4\x14\x22\xd5\xa1\xd5\xd5\xc7\x3c\x22\x96\x86\x93\x5b\x40\xf8\x81\x50\x27\x85",
        .decimals = 8,
    },
    {
        .name = "PHI Token",
        .unit = "PHI",
        .contract_address =
            "\x13\xc2\xfa\xb6\x35\x4d\x37\x90\xd8\xec\xe4\xf0\xf1\xa3\x28\x0b\x4a\x25\xad\x96",
        .decimals = 18,
    },
    {
        .name = "PATHHIVE ",
        .unit = "PHV",
        .contract_address =
            "\x25\x20\x02\x35\xca\x71\x13\xc2\x54\x1e\x70\xde\x73\x7c\x41\xf5\xe9\xac\xd1\xf6",
        .decimals = 18,
    },
    {
        .name = "PIBBLE",
        .unit = "PIB",
        .contract_address =
            "\x18\x64\xce\x27\xe9\xf7\x51\x70\x47\x93\x3c\xaa\xe5\x30\x67\x4e\x8c\x70\xb8\xa7",
        .decimals = 18,
    },
    {
        .name = "DeFiPie",
        .unit = "PIE",
        .contract_address =
            "\x60\x7c\x79\x4c\xda\x77\xef\xb2\x1f\x88\x48\xb7\x91\x0e\xcf\x27\x45\x1a\xe8\x42",
        .decimals = 18,
    },
    {
        .name = "PiplCoin",
        .unit = "PIPL",
        .contract_address =
            "\xe6\x45\x09\xf0\xbf\x07\xce\x2d\x29\xa7\xef\x19\xa8\xa9\xbc\x06\x54\x77\xc1\xb4",
        .decimals = 8,
    },
    {
        .name = "Playkey",
        .unit = "PKT",
        .contract_address =
            "\x26\x04\xfa\x40\x6b\xe9\x57\xe5\x42\xbe\xb8\x9e\x67\x54\xfc\xde\x68\x15\xe8\x3f",
        .decimals = 18,
    },
    {
        .name = "PLAAS FARMERS TOKEN",
        .unit = "PLAAS",
        .contract_address =
            "\x60\x57\x1e\x95\xe1\x2c\x78\xcb\xa5\x22\x30\x42\x69\x29\x08\xf0\x64\x94\x35\xa5",
        .decimals = 18,
    },
    {
        .name = "HEROcoin",
        .unit = "PLAY",
        .contract_address =
            "\xe4\x77\x29\x2f\x1b\x32\x68\x68\x7a\x29\x37\x61\x16\xb0\xed\x27\xa9\xc7\x61\x70",
        .decimals = 18,
    },
    {
        .name = "PlayFuel",
        .unit = "PLF",
        .contract_address =
            "\xad\xa6\x2f\x7c\xcd\x6a\xf6\xca\xcf\xf0\x4a\xcc\xbc\x4f\x56\xf3\xd4\xff\xd4\xef",
        .decimals = 18,
    },
    {
        .name = "PlutusDeFi",
        .unit = "PLT",
        .contract_address =
            "\x9f\xbf\xed\x65\x89\x19\xa8\x96\xb5\xdc\x7b\x00\x45\x6c\xe2\x2d\x78\x0f\x9b\x65",
        .decimals = 18,
    },
    {
        .name = "PlatonCoin",
        .unit = "PLTC",
        .contract_address =
            "\x42\x9d\x83\xbb\x0d\xcb\x8c\xdd\x53\x11\xe3\x46\x80\xad\xc8\xb1\x20\x70\xa0\x7f",
        .decimals = 18,
    },
    {
        .name = "Perth Mint Gold Token",
        .unit = "PMGT",
        .contract_address =
            "\xaf\xfc\xdd\x96\x53\x1b\xcd\x66\xfa\xed\x95\xfc\x61\xe4\x43\xd0\x8f\x79\xef\xef",
        .decimals = 5,
    },
    {
        .name = "Paymon",
        .unit = "PMNT",
        .contract_address =
            "\x81\xb4\xd0\x86\x45\xda\x11\x37\x4a\x03\x74\x9a\xb1\x70\x83\x6e\x4e\x53\x97\x67",
        .decimals = 9,
    },
    {
        .name = "pNetwork",
        .unit = "PNT",
        .contract_address =
            "\x89\xab\x32\x15\x6e\x46\xf4\x6d\x02\xad\xe3\xfe\xcb\xe5\xfc\x42\x43\xb9\xaa\xed",
        .decimals = 18,
    },
    {
        .name = "ClearPoll",
        .unit = "POLL",
        .contract_address =
            "\x70\x5e\xe9\x6c\x1c\x16\x08\x42\xc9\x2c\x1a\xec\xfc\xff\xcc\xc9\xc4\x12\xe3\xd9",
        .decimals = 18,
    },
    {
        .name = "Portal",
        .unit = "PORTAL",
        .contract_address =
            "\x8d\xb9\x0e\x3e\x7d\x04\xc8\x75\xa5\x19\x97\x09\x2f\x91\x78\xfc\xac\x9d\xef\xdb",
        .decimals = 18,
    },
    {
        .name = "Posscoin",
        .unit = "POSS",
        .contract_address =
            "\x6b\x19\x3e\x10\x7a\x77\x39\x67\xbd\x82\x1b\xcf\x82\x18\xf3\x54\x8c\xfa\x25\x03",
        .decimals = 18,
    },
    {
        .name = "UniPower",
        .unit = "POWER",
        .contract_address =
            "\xf2\xf9\xa7\xe9\x3f\x84\x5b\x3c\xe1\x54\xef\xbe\xb6\x4f\xb9\x34\x6f\xcc\xe5\x09",
        .decimals = 18,
    },
    {
        .name = "PHILLIPS PAY COIN",
        .unit = "PPC",
        .contract_address =
            "\x84\xf7\x10\xba\xe3\x31\x6a\x74\xfb\x0f\xcb\x01\x90\x4d\x25\x78\xa4\xcc\x6a\x26",
        .decimals = 1,
    },
    {
        .name = "Paragon",
        .unit = "PRG",
        .contract_address =
            "\x77\x28\xdf\xef\x5a\xbd\x46\x86\x69\xeb\x7f\x9b\x48\xa7\xf7\x0a\x50\x1e\xd2\x9d",
        .decimals = 6,
    },
    {
        .name = "Privatix",
        .unit = "PRIX",
        .contract_address =
            "\x3a\xdf\xc4\x99\x9f\x77\xd0\x4c\x83\x41\xba\xc5\xf3\xa7\x6f\x58\xdf\xf5\xb3\x7a",
        .decimals = 8,
    },
    {
        .name = "ProBit Token",
        .unit = "PROB",
        .contract_address =
            "\xfb\x55\x9c\xe6\x7f\xf5\x22\xec\x0b\x9b\xa7\xf5\xdc\x9d\xc7\xef\x6c\x13\x98\x03",
        .decimals = 18,
    },
    {
        .name = "Props Token",
        .unit = "PROPS",
        .contract_address =
            "\x6f\xe5\x6c\x0b\xcd\xd4\x71\x35\x90\x19\xfc\xbc\x48\x86\x3d\x6c\x3e\x9d\x4f\x41",
        .decimals = 18,
    },
    {
        .name = "PRASM",
        .unit = "PSM",
        .contract_address =
            "\x1a\x66\xe0\x9f\x7d\xcc\xc1\x0e\xae\x46\xe2\x7c\xfa\x6b\x8d\x44\xa5\x0d\xf1\xe7",
        .decimals = 18,
    },
    {
        .name = "Primas",
        .unit = "PST",
        .contract_address =
            "\x5d\x4a\xbc\x77\xb8\x40\x5a\xd1\x77\xd8\xac\x66\x82\xd5\x84\xec\xbf\xd4\x6c\xec",
        .decimals = 18,
    },
    {
        .name = "PalletOne",
        .unit = "PTN",
        .contract_address =
            "\xfe\x76\xbe\x9c\xec\x46\x5e\xd3\x21\x9a\x99\x72\xc2\x16\x55\xd5\x7d\x21\xae\xc6",
        .decimals = 18,
    },
    {
        .name = "PTON",
        .unit = "PTON",
        .contract_address =
            "\x49\x46\x58\x3c\x5b\x86\xe0\x1c\xcd\x30\xc7\x1a\x05\x61\x7d\x06\xe3\xe7\x30\x60",
        .decimals = 18,
    },
    {
        .name = "Patientory",
        .unit = "PTOY",
        .contract_address =
            "\x8a\xe4\xbf\x2c\x33\xa8\xe6\x67\xde\x34\xb5\x49\x38\xb0\xcc\xd0\x3e\xb8\xcc\x06",
        .decimals = 8,
    },
    {
        .name = "Proton Token",
        .unit = "PTT",
        .contract_address =
            "\x46\x89\xa4\xe1\x69\xeb\x39\xcc\x90\x78\xc0\x94\x0e\x21\xff\x1a\xa8\xa3\x9b\x9c",
        .decimals = 18,
    },
    {
        .name = "PolypuX",
        .unit = "PUX",
        .contract_address =
            "\xe2\x77\xac\x35\xf9\xd3\x27\xa6\x70\xc1\xa3\xf3\xee\xc8\x0a\x83\x02\x24\x31\xe4",
        .decimals = 8,
    },
    {
        .name = "Pixie Coin",
        .unit = "PXC",
        .contract_address =
            "\xc2\x7c\x95\x35\x0e\xcd\x63\x4c\x80\xdf\x89\xdb\x0f\x10\xcd\x5c\x24\xb7\xb1\x1f",
        .decimals = 2,
    },
    {
        .name = "PlayGame",
        .unit = "PXG",
        .contract_address =
            "\x47\xe6\x7b\xa6\x6b\x06\x99\x50\x0f\x18\xa5\x3f\x94\xe2\xb9\xdb\x3d\x47\x43\x7e",
        .decimals = 18,
    },
    {
        .name = "PIXEL",
        .unit = "PXL",
        .contract_address =
            "\xf8\x89\x51\xd7\xb6\x76\x79\x87\x05\xfd\x3a\x36\x2b\xa5\xb1\xdb\xca\x2b\x23\x3b",
        .decimals = 18,
    },
    {
        .name = "PointPay",
        .unit = "PXP",
        .contract_address =
            "\x8f\x17\x91\x14\x23\x58\x42\x97\x8d\x89\x17\xe0\x87\x21\x54\x10\x72\xc4\x65\x84",
        .decimals = 3,
    },
    {
        .name = "Pylon Network",
        .unit = "PYLNT",
        .contract_address =
            "\x77\x03\xc3\x5c\xff\xdc\x5c\xda\x8d\x27\xaa\x3d\xf2\xf9\xba\x69\x64\x54\x4b\x6e",
        .decimals = 18,
    },
    {
        .name = "PYRO Network",
        .unit = "PYRO",
        .contract_address =
            "\x14\x40\x9b\x0f\xc5\xc7\xf8\x7b\x5d\xad\x20\x75\x4f\xe2\x2d\x29\xa3\xde\x82\x17",
        .decimals = 18,
    },
    {
        .name = "qiibee",
        .unit = "QBX",
        .contract_address =
            "\x24\x67\xaa\x6b\x5a\x23\x51\x41\x6f\xd4\xc3\xde\xf8\x46\x2d\x84\x1f\xee\xec\xec",
        .decimals = 18,
    },
    {
        .name = "QUEENBEE",
        .unit = "QBZ",
        .contract_address =
            "\x9b\xbc\x92\x86\xcd\xf6\xee\xfe\xbf\x21\xdf\x19\xba\xc7\x1c\x6b\xdd\x77\x59\xd4",
        .decimals = 18,
    },
    {
        .name = "QChi",
        .unit = "QCH",
        .contract_address =
            "\x68\x7b\xfc\x3e\x73\xf6\xaf\x55\xf0\xcc\xca\x84\x50\x11\x4d\x10\x7e\x78\x1a\x0e",
        .decimals = 18,
    },
    {
        .name = "Q DAO Governance token v1.0",
        .unit = "QDAO",
        .contract_address =
            "\x31\x66\xc5\x70\x93\x5a\x7d\x85\x54\xc8\xf4\xea\x79\x2f\xf9\x65\xd2\xef\xe1\xf2",
        .decimals = 18,
    },
    {
        .name = "Quiztok",
        .unit = "QTCON",
        .contract_address =
            "\xa0\x0a\x4d\x57\x86\xa6\xe9\x55\xe9\x53\x9d\x01\xd7\x8b\xf6\x8f\x32\x71\xc0\x50",
        .decimals = 18,
    },
    {
        .name = "QUINADS",
        .unit = "QUIN",
        .contract_address =
            "\x86\xe4\x45\x43\x16\x4d\x9b\x97\xb1\x4e\xf7\xf6\xf3\xab\x7b\xa6\x70\xca\xb3\x46",
        .decimals = 18,
    },
    {
        .name = "Raise",
        .unit = "RAISE",
        .contract_address =
            "\x10\xba\x8c\x42\x0e\x91\x2b\xf0\x7b\xed\xac\x03\xaa\x69\x08\x72\x0d\xb0\x4e\x0c",
        .decimals = 18,
    },
    {
        .name = "RAKUN",
        .unit = "RAKU",
        .contract_address =
            "\x51\xbc\x0d\xea\xf7\xbb\xe8\x2b\xc9\x00\x6b\x0c\x35\x31\x66\x8a\x42\x06\xd2\x7f",
        .decimals = 18,
    },
    {
        .name = "Rarible",
        .unit = "RARI",
        .contract_address =
            "\xfc\xa5\x9c\xd8\x16\xab\x1e\xad\x66\x53\x4d\x82\xbc\x21\xe7\x51\x5c\xe4\x41\xcf",
        .decimals = 18,
    },
    {
        .name = "DPRating",
        .unit = "RATING",
        .contract_address =
            "\xe8\x66\x3a\x64\xa9\x61\x69\xff\x4d\x95\xb4\x29\x9e\x7a\xe9\xa7\x6b\x90\x5b\x31",
        .decimals = 8,
    },
    {
        .name = "Red Box Dapp Token",
        .unit = "RBD",
        .contract_address =
            "\x71\x05\xec\x15\x99\x5a\x97\x49\x6e\xc2\x5d\xe3\x6c\xf7\xee\xc4\x7b\x70\x33\x75",
        .decimals = 18,
    },
    {
        .name = "RealChain",
        .unit = "RCT",
        .contract_address =
            "\x13\xf2\x5c\xd5\x2b\x21\x65\x0c\xaa\x82\x25\xc9\x94\x23\x37\xd9\x14\xc9\xb0\x30",
        .decimals = 18,
    },
    {
        .name = "REAL",
        .unit = "REAL",
        .contract_address =
            "\x92\x14\xec\x02\xcb\x71\xcb\xa0\xad\xa6\x89\x6b\x8d\xa2\x60\x73\x6a\x67\xab\x10",
        .decimals = 18,
    },
    {
        .name = "RED",
        .unit = "RED",
        .contract_address =
            "\x76\x96\x0d\xcc\xd5\xa1\xfe\x79\x9f\x7c\x29\xbe\x9f\x19\xce\xb4\x62\x7a\xeb\x2f",
        .decimals = 18,
    },
    {
        .name = "RefToken",
        .unit = "REF",
        .contract_address =
            "\x89\x30\x35\x00\xa7\xab\xfb\x17\x8b\x27\x4f\xd8\x9f\x24\x69\xc2\x64\x95\x1e\x1f",
        .decimals = 8,
    },
    {
        .name = "Release Project",
        .unit = "REL",
        .contract_address =
            "\x61\xbf\xc9\x79\xea\x81\x60\xed\xe9\xb8\x62\x79\x8b\x78\x33\xa9\x7b\xaf\xa0\x2a",
        .decimals = 18,
    },
    {
        .name = "renBTC",
        .unit = "RENBTC",
        .contract_address =
            "\xeb\x4c\x27\x81\xe4\xeb\xa8\x04\xce\x9a\x98\x03\xc6\x7d\x08\x93\x43\x6b\xb2\x7d",
        .decimals = 8,
    },
    {
        .name = "Revain",
        .unit = "REV",
        .contract_address =
            "\x2e\xf5\x2e\xd7\xde\x8c\x5c\xe0\x3a\x4e\xf0\xef\xbe\x9b\x74\x50\xf2\xd7\xed\xc9",
        .decimals = 6,
    },
    {
        .name = "Rewardiqa",
        .unit = "REW",
        .contract_address =
            "\x3f\xff\xfa\x8f\x3c\xc9\x43\xe4\x3f\x9f\x17\xa8\x3c\xbb\x18\xf4\xbb\xb9\xf4\xac",
        .decimals = 18,
    },
    {
        .name = "imbrex",
        .unit = "REX",
        .contract_address =
            "\xf0\x5a\x93\x82\xa4\xc3\xf2\x9e\x27\x84\x50\x27\x54\x29\x3d\x88\xb8\x35\x10\x9c",
        .decimals = 18,
    },
    {
        .name = "Darwinia Network",
        .unit = "RING",
        .contract_address =
            "\x94\x69\xd0\x13\x80\x5b\xff\xb7\xd3\xde\xbe\x5e\x78\x39\x23\x7e\x53\x5e\xc4\x83",
        .decimals = 18,
    },
    {
        .name = "Rakon",
        .unit = "RKN",
        .contract_address =
            "\x6e\x5a\x43\xdb\x10\xb0\x47\x01\x38\x5a\x34\xaf\xb6\x70\xe4\x04\xbc\x7e\xa5\x97",
        .decimals = 12,
    },
    {
        .name = "Relex",
        .unit = "RLX",
        .contract_address =
            "\x4a\x42\xd2\xc5\x80\xf8\x3d\xce\x40\x4a\xca\xd1\x8d\xab\x26\xdb\x11\xa1\x75\x0e",
        .decimals = 18,
    },
    {
        .name = "Rivermount",
        .unit = "RM",
        .contract_address =
            "\x5a\xb5\x5e\xc2\x90\xbe\xac\xae\x98\xf5\x4c\x3e\xb7\x08\x60\x46\x0b\x16\x7c\x3c",
        .decimals = 18,
    },
    {
        .name = "RightMesh",
        .unit = "RMESH",
        .contract_address =
            "\x8d\x56\x82\x94\x1c\xe4\x56\x90\x0b\x12\xd4\x7a\xc0\x6a\x88\xb4\x7c\x76\x4c\xe1",
        .decimals = 18,
    },
    {
        .name = "RMPL",
        .unit = "RMPL",
        .contract_address =
            "\xe1\x7f\x01\x74\x75\xa7\x09\xde\x58\xe9\x76\x08\x1e\xb9\x16\x08\x1f\xf4\xc9\xd5",
        .decimals = 9,
    },
    {
        .name = "Render Token",
        .unit = "RNDR",
        .contract_address =
            "\x6d\xe0\x37\xef\x9a\xd2\x72\x5e\xb4\x01\x18\xbb\x17\x02\xeb\xb2\x7e\x4a\xeb\x24",
        .decimals = 18,
    },
    {
        .name = "BitRent",
        .unit = "RNTB",
        .contract_address =
            "\x1f\xe7\x0b\xe7\x34\xe4\x73\xe5\x72\x1e\xa5\x7c\x8b\x5b\x01\xe6\xca\xa5\x26\x86",
        .decimals = 18,
    },
    {
        .name = "RoBET",
        .unit = "ROBET",
        .contract_address =
            "\x23\x44\x87\x1f\x52\x3c\xbb\x28\xa4\xf6\x00\x45\x53\x11\x84\xcf\x1f\x03\xad\x24",
        .decimals = 18,
    },
    {
        .name = "ICE ROCK MINING",
        .unit = "ROCK2",
        .contract_address =
            "\xc1\x6b\x54\x2f\xf4\x90\xe0\x1f\xcc\x0d\xc5\x8a\x60\xe1\xef\xdc\x3e\x35\x7c\xa6",
        .decimals = 0,
    },
    {
        .name = "Rozeus",
        .unit = "ROZ",
        .contract_address =
            "\xe5\x5c\xc4\x4c\x0c\xf9\xce\xde\x2d\x68\xf9\x43\x2c\xbe\xea\xfa\x63\x57\xed\x92",
        .decimals = 8,
    },
    {
        .name = "Rapidz",
        .unit = "RPZX",
        .contract_address =
            "\x68\x35\x0d\x30\xd9\xf5\x8c\x81\xaa\xaa\x41\x92\x9f\x1b\xfc\x52\xff\xf4\xea\x49",
        .decimals = 18,
    },
    {
        .name = "Rate3",
        .unit = "RTE",
        .contract_address =
            "\x43\x6f\x0f\x3a\x98\x20\x74\xc4\xa0\x50\x84\x48\x5d\x42\x14\x66\xa9\x94\xfe\x53",
        .decimals = 18,
    },
    {
        .name = "Rivetz",
        .unit = "RVT",
        .contract_address =
            "\x3d\x1b\xa9\xbe\x9f\x66\xb8\xee\x10\x19\x11\xbc\x36\xd3\xfb\x56\x2e\xac\x22\x44",
        .decimals = 18,
    },
    {
        .name = "Robonomics Web Services",
        .unit = "RWS",
        .contract_address =
            "\x08\xad\x83\xd7\x79\xbd\xf2\xbb\xe1\xad\x9c\xc0\xf7\x8a\xa0\xd2\x4a\xb9\x78\x02",
        .decimals = 18,
    },
    {
        .name = "Sharpay",
        .unit = "S",
        .contract_address =
            "\x96\xb0\xbf\x93\x9d\x94\x60\x09\x5c\x15\x25\x1f\x71\xfd\xa1\x1e\x41\xdc\xbd\xdb",
        .decimals = 18,
    },
    {
        .name = "Social Activity Token",
        .unit = "SAT",
        .contract_address =
            "\xc5\x6b\x13\xeb\xbc\xff\xa6\x7c\xfb\x79\x79\xb9\x00\xb7\x36\xb3\xfb\x48\x0d\x78",
        .decimals = 8,
    },
    {
        .name = "SatoExchange Token",
        .unit = "SATX",
        .contract_address =
            "\xe9\x6f\x2c\x38\x1e\x26\x7a\x96\xc2\x9b\xbb\x8a\xb0\x5a\xb7\xd3\x52\x7b\x45\xab",
        .decimals = 8,
    },
    {
        .name = "CBDAO",
        .unit = "SBREE",
        .contract_address =
            "\x25\x37\x7d\xdb\x16\xc7\x9c\x93\xb0\xcb\xf4\x68\x09\xc8\xde\x87\x65\xf0\x3f\xcd",
        .decimals = 18,
    },
    {
        .name = "SiaCashCoin",
        .unit = "SCC",
        .contract_address =
            "\x74\xfd\x51\xa9\x8a\x4a\x1e\xcb\xef\x8c\xc4\x3b\xe8\x01\xcc\xe6\x30\xe2\x60\xbd",
        .decimals = 18,
    },
    {
        .name = "Sociall",
        .unit = "SCL",
        .contract_address =
            "\xd7\x63\x17\x87\xb4\xdc\xc8\x7b\x12\x54\xcf\xd1\xe5\xce\x48\xe9\x68\x23\xde\xe8",
        .decimals = 8,
    },
    {
        .name = "Seal Network",
        .unit = "SEAL",
        .contract_address =
            "\xd7\xb3\x66\x9c\x7d\x3e\x38\xab\x5a\x44\x13\x83\xd4\x1f\x25\xe0\x03\xe0\x21\x48",
        .decimals = 18,
    },
    {
        .name = "MESEFA",
        .unit = "SEFA",
        .contract_address =
            "\x27\x20\x12\x32\x57\x94\x91\xce\x9b\x11\x6a\xc6\xf3\x7d\x35\x4c\xc7\x23\xa2\xf3",
        .decimals = 8,
    },
    {
        .name = "Sentinel Chain",
        .unit = "SENC",
        .contract_address =
            "\xa1\x3f\x07\x43\x95\x1b\x4f\x6e\x3e\x3a\xa0\x39\xf6\x82\xe1\x72\x79\xf5\x2b\xc3",
        .decimals = 18,
    },
    {
        .name = "Sensorium",
        .unit = "SENSO",
        .contract_address =
            "\xba\x6d\xb1\x3a\xea\xe3\x60\x7d\x40\x0d\xdf\xfd\x67\x5a\xa4\xe8\x8e\xcc\x9a\x69",
        .decimals = 0,
    },
    {
        .name = "Save Environment Token",
        .unit = "SET",
        .contract_address =
            "\x0a\x2d\x93\x70\xcf\x74\xda\x3f\xd3\xdf\x5d\x76\x4e\x39\x4c\xa8\x20\x5c\x50\xb6",
        .decimals = 18,
    },
    {
        .name = "sETH",
        .unit = "SETH",
        .contract_address =
            "\x5e\x74\xc9\x03\x6f\xb8\x6b\xd7\xec\xdc\xb0\x84\xa0\x67\x3e\xfc\x32\xea\x31\xcb",
        .decimals = 18,
    },
    {
        .name = "ShareX",
        .unit = "SEXC",
        .contract_address =
            "\x25\x67\xc6\x77\x47\x3d\x11\x0d\x75\xa8\x36\x0c\x35\x30\x9e\x63\xb1\xd5\x24\x29",
        .decimals = 8,
    },
    {
        .name = "SF Capital",
        .unit = "SFCP",
        .contract_address =
            "\x8b\x6c\xda\x5c\xc5\x18\xc9\x04\xe8\x84\x4f\x44\x5e\x1a\x7c\x7d\x2d\xb0\xff\x16",
        .decimals = 18,
    },
    {
        .name = "SocialGood",
        .unit = "SG",
        .contract_address =
            "\xdd\xf7\xfd\x34\x5d\x54\xff\x4b\x40\x07\x95\x79\xd4\xc4\x67\x04\x15\xdb\xfd\x0a",
        .decimals = 18,
    },
    {
        .name = "Saga",
        .unit = "SGA",
        .contract_address =
            "\xed\x08\x49\xbf\x46\xcf\xb9\x84\x5a\x2d\x90\x0a\x0a\x4e\x59\x3f\x2d\xd3\x67\x3c",
        .decimals = 18,
    },
    {
        .name = "Sudan Gold Coin",
        .unit = "SGC",
        .contract_address =
            "\x80\xbd\x0c\xc6\x89\xc2\x06\xe3\xf6\x42\x91\x92\x44\xc4\x25\x1c\x7e\xf1\x98\x52",
        .decimals = 18,
    },
    {
        .name = "Signals Network",
        .unit = "SGN",
        .contract_address =
            "\xb2\x13\x5a\xb9\x69\x5a\x76\x78\xdd\x59\x0b\x1a\x99\x6c\xb0\xf3\x7b\xcb\x07\x18",
        .decimals = 9,
    },
    {
        .name = "snglsDAO",
        .unit = "SGT",
        .contract_address =
            "\xc4\x19\x9f\xb6\xff\xdb\x30\xa8\x29\x61\x4b\xec\xa0\x30\xf9\x04\x2f\x1c\x39\x92",
        .decimals = 18,
    },
    {
        .name = "ShineChain",
        .unit = "SHE",
        .contract_address =
            "\x90\x64\xc9\x1e\x51\xd7\x02\x1a\x85\xad\x96\x81\x7e\x14\x32\xab\xf6\x62\x44\x70",
        .decimals = 18,
    },
    {
        .name = "SHENG",
        .unit = "SHENG",
        .contract_address =
            "\x22\xef\x37\x53\xe3\x65\x8e\x81\xd5\xa0\xd0\x88\x9c\xe0\x78\x17\x8f\xe6\x65\x95",
        .decimals = 18,
    },
    {
        .name = "ShipChain",
        .unit = "SHIP",
        .contract_address =
            "\xe2\x5b\x0b\xba\x01\xdc\x56\x30\x31\x2b\x6a\x21\x92\x7e\x57\x80\x61\xa1\x3f\x55",
        .decimals = 18,
    },
    {
        .name = "SHPING",
        .unit = "SHPING",
        .contract_address =
            "\x7c\x84\xe6\x28\x59\xd0\x71\x5e\xb7\x7d\x1b\x1c\x41\x54\xec\xd6\xab\xb2\x1b\xec",
        .decimals = 18,
    },
    {
        .name = "Shivers",
        .unit = "SHVR",
        .contract_address =
            "\xd5\xf7\x88\xca\x0d\xe8\xf1\x7c\xbd\xe1\xd1\xe3\x5a\xa8\xf0\x05\xa8\x7f\xa0\x0b",
        .decimals = 8,
    },
    {
        .name = "Spectiv",
        .unit = "SIG",
        .contract_address =
            "\x68\x88\xa1\x6e\xa9\x79\x2c\x15\xa4\xdc\xf2\xf6\xc6\x23\xd0\x55\xc8\xed\xe7\x92",
        .decimals = 18,
    },
    {
        .name = "Simmitri",
        .unit = "SIM",
        .contract_address =
            "\x75\x28\xe3\x04\x03\x76\xed\xd5\xdb\x82\x63\xdb\x2f\x5b\xd1\xbe\xd9\x14\x67\xfb",
        .decimals = 18,
    },
    {
        .name = "Sakura Bloom",
        .unit = "SKB",
        .contract_address =
            "\x4a\xf3\x28\xc5\x29\x21\x70\x6d\xcb\x73\x9f\x25\x78\x62\x10\x49\x91\x69\xaf\xe6",
        .decimals = 8,
    },
    {
        .name = "Skychain",
        .unit = "SKCH",
        .contract_address =
            "\x70\xc6\x21\xf9\x49\xb6\x55\x6c\x45\x45\x70\x7a\x2d\x5d\x73\xa7\x76\xb9\x83\x59",
        .decimals = 6,
    },
    {
        .name = "Skillchain",
        .unit = "SKI",
        .contract_address =
            "\x99\x6d\xc5\xdf\xc8\x19\x40\x8d\xd9\x8c\xd9\x2c\x9a\x76\xf6\x4b\x07\x38\xdc\x3d",
        .decimals = 18,
    },
    {
        .name = "SkinCoin",
        .unit = "SKIN",
        .contract_address =
            "\x2b\xdc\x0d\x42\x99\x60\x17\xfc\xe2\x14\xb2\x16\x07\xa5\x15\xda\x41\xa9\xe0\xc5",
        .decimals = 6,
    },
    {
        .name = "Small Love Potion",
        .unit = "SLP",
        .contract_address =
            "\x37\x23\x6c\xd0\x5b\x34\xcc\x79\xd3\x71\x5a\xf2\x38\x3e\x96\xdd\x74\x43\xdc\xf1",
        .decimals = 0,
    },
    {
        .name = "SynchroBitcoin",
        .unit = "SNB",
        .contract_address =
            "\x17\x9e\x31\xfb\x25\xe4\x33\x44\x1a\x28\x39\x38\x9a\x7b\x8e\xc9\xc4\x65\x4b\x7b",
        .decimals = 18,
    },
    {
        .name = "SeChain",
        .unit = "SNN",
        .contract_address =
            "\xf5\x71\x7f\x5d\xf4\x1e\xa6\x7e\xf6\x7d\xfd\x3c\x1d\x02\xf9\x94\x0b\xcf\x5d\x08",
        .decimals = 3,
    },
    {
        .name = "Snovian.Space",
        .unit = "SNOV",
        .contract_address =
            "\xbd\xc5\xba\xc3\x9d\xbe\x13\x2b\x1e\x03\x0e\x89\x8a\xe3\x83\x00\x17\xd7\xd9\x69",
        .decimals = 18,
    },
    {
        .name = "SONDER",
        .unit = "SNR",
        .contract_address =
            "\x47\xd1\xa5\x9c\xbd\xd1\x9a\xee\x06\x0c\x85\x9c\x00\x09\x27\x7e\x24\x53\x28\xae",
        .decimals = 18,
    },
    {
        .name = "Silent Notary",
        .unit = "SNTR",
        .contract_address =
            "\x28\x59\x02\x1e\xe7\xf2\xcb\x10\x16\x2e\x67\xf3\x3a\xf2\xd2\x27\x64\xb3\x1a\xff",
        .decimals = 4,
    },
    {
        .name = "Synthetix Network Token",
        .unit = "SNX",
        .contract_address =
            "\xc0\x11\xa7\x3e\xe8\x57\x6f\xb4\x6f\x5e\x1c\x57\x51\xca\x3b\x9f\xe0\xaf\x2a\x6f",
        .decimals = 18,
    },
    {
        .name = "Soda Coin",
        .unit = "SOC",
        .contract_address =
            "\xca\xd4\x9c\x39\xb7\x2c\x37\xb3\x2c\xee\x8b\x14\xf3\x3f\x31\x6d\x3a\x8b\xc3\x35",
        .decimals = 18,
    },
    {
        .name = "CryptoSoul",
        .unit = "SOUL",
        .contract_address =
            "\xbb\x1f\x24\xc0\xc1\x55\x4b\x99\x90\x22\x2f\x03\x6b\x0a\xad\x6e\xe4\xca\xec\x29",
        .decimals = 18,
    },
    {
        .name = "ChainZ Arena",
        .unit = "SOUL",
        .contract_address =
            "\x72\xdc\x3d\x52\xb7\xef\x10\x7a\x7c\xff\xb6\x95\x3e\xaa\x8a\x2a\xd6\xa2\x04\xcd",
        .decimals = 6,
    },
    {
        .name = "Secrets of Zurich",
        .unit = "SOZ",
        .contract_address =
            "\x3a\x10\xb7\xa2\x2a\xe9\x8e\x0f\x53\x27\x69\x23\xf1\x9f\x99\xb2\x59\xf6\x17\x78",
        .decimals = 18,
    },
    {
        .name = "SpankChain",
        .unit = "SPANK",
        .contract_address =
            "\x42\xd6\x62\x2d\xec\xe3\x94\xb5\x49\x99\xfb\xd7\x3d\x10\x81\x23\x80\x6f\x6a\x18",
        .decimals = 18,
    },
    {
        .name = "Swapcoinz",
        .unit = "SPAZ",
        .contract_address =
            "\x81\x09\x08\xb2\x85\xf8\x5a\xf6\x68\xf6\x34\x8c\xd8\xb2\x6d\x76\xb3\xec\x12\xe1",
        .decimals = 8,
    },
    {
        .name = "SPINDLE",
        .unit = "SPD",
        .contract_address =
            "\x1d\xea\x97\x9a\xe7\x6f\x26\x07\x18\x70\xf8\x24\x08\x8d\xa7\x89\x79\xeb\x91\xc8",
        .decimals = 18,
    },
    {
        .name = "Spiking",
        .unit = "SPIKE",
        .contract_address =
            "\xa7\xfc\x5d\x24\x53\xe3\xf6\x8a\xf0\xcc\x1b\x78\xbc\xfe\xe9\x4a\x1b\x29\x36\x50",
        .decimals = 10,
    },
    {
        .name = "Sapien",
        .unit = "SPN",
        .contract_address =
            "\x20\xf7\xa3\xdd\xf2\x44\xdc\x92\x99\x97\x5b\x4d\xa1\xc3\x9f\x8d\x5d\x75\xf0\x5a",
        .decimals = 6,
    },
    {
        .name = "Sparkle",
        .unit = "SPRKL",
        .contract_address =
            "\x4b\x7a\xd3\xa5\x68\x10\x03\x27\x82\xaf\xce\x12\xd7\xd2\x71\x22\xbd\xb9\x6e\xff",
        .decimals = 8,
    },
    {
        .name = "Spectrum",
        .unit = "SPT",
        .contract_address =
            "\x01\xcc\x41\x51\xfe\x5f\x00\xef\xb8\xdf\x2f\x90\xff\x83\x37\x25\xd3\xa4\x82\xa3",
        .decimals = 8,
    },
    {
        .name = "Super Running Coin",
        .unit = "SRC",
        .contract_address =
            "\x22\x1f\x7d\x0f\x2f\xa0\xbf\xbd\x5f\x8b\x0d\x03\x40\x42\x59\x06\xf2\xf9\x96\x8c",
        .decimals = 18,
    },
    {
        .name = "SRCOIN",
        .unit = "SRCOIN",
        .contract_address =
            "\xef\x8c\xf7\x9c\x21\x63\x7f\xc6\xf9\x51\xbc\xac\x34\x89\x15\x50\x8a\x63\x9a\x41",
        .decimals = 18,
    },
    {
        .name = "Sparkpoint",
        .unit = "SRK",
        .contract_address =
            "\x04\x88\x40\x1c\x3f\x53\x51\x93\xfa\x8d\xf0\x29\xd9\xff\xe6\x15\xa0\x6e\x74\xe6",
        .decimals = 18,
    },
    {
        .name = "Sharder",
        .unit = "SS",
        .contract_address =
            "\xbb\xff\x86\x2d\x90\x6e\x34\x8e\x99\x46\xbf\xb2\x13\x2e\xcb\x15\x7d\xa3\xd4\xb4",
        .decimals = 18,
    },
    {
        .name = "Smartshare",
        .unit = "SSP",
        .contract_address =
            "\x62\x4d\x52\x0b\xab\x2e\x4a\xd8\x39\x35\xfa\x50\x3f\xb1\x30\x61\x43\x74\xe8\x50",
        .decimals = 4,
    },
    {
        .name = "SIMBA Storage Token",
        .unit = "SST",
        .contract_address =
            "\x28\x63\x91\x6c\x6e\xbd\xbb\xf0\xc6\xf0\x2f\x87\xb7\xeb\x47\x85\x09\x29\x98\x68",
        .decimals = 18,
    },
    {
        .name = "STATERA",
        .unit = "STA",
        .contract_address =
            "\xa7\xde\x08\x73\x29\xbf\xcd\xa5\x63\x92\x47\xf9\x61\x40\xf9\xda\xbe\x3d\xee\xd1",
        .decimals = 18,
    },
    {
        .name = "StarterCoin",
        .unit = "STAC",
        .contract_address =
            "\x9a\x00\x5c\x9a\x89\xbd\x72\xa4\xbd\x27\x72\x1e\x7a\x09\xa3\xc1\x1d\x2b\x03\xc4",
        .decimals = 18,
    },
    {
        .name = "xDai",
        .unit = "STAKE",
        .contract_address =
            "\x0a\xe0\x55\x09\x7c\x6d\x15\x98\x79\x52\x1c\x38\x4f\x1d\x21\x23\xd1\xf1\x95\xe6",
        .decimals = 18,
    },
    {
        .name = "SafePost",
        .unit = "STAMP",
        .contract_address =
            "\x43\xaf\xc9\x05\x8a\x3d\xeb\xf3\x7e\xad\xf9\x91\x38\xe4\x49\xce\x8a\x48\x0a\x8a",
        .decimals = 18,
    },
    {
        .name = "Starbase",
        .unit = "STAR",
        .contract_address =
            "\xf7\x0a\x64\x2b\xd3\x87\xf9\x43\x80\xff\xb9\x04\x51\xc2\xc8\x1d\x4e\xb8\x2c\xbc",
        .decimals = 18,
    },
    {
        .name = "BitStash",
        .unit = "STASH",
        .contract_address =
            "\x96\x5f\x10\x9d\x31\xcc\xb7\x70\x05\x85\x8d\xef\xae\x0e\xba\xf7\xb4\x38\x16\x52",
        .decimals = 18,
    },
    {
        .name = "STK",
        .unit = "STK",
        .contract_address =
            "\xae\x73\xb3\x8d\x1c\x9a\x8b\x27\x41\x27\xec\x30\x16\x0a\x49\x27\xc4\xd7\x18\x24",
        .decimals = 18,
    },
    {
        .name = "STK Coin",
        .unit = "STK",
        .contract_address =
            "\x5c\x58\x87\xe5\x5b\xbe\x41\x47\x2a\xcd\xba\x5f\xae\x98\x97\x88\xc6\xf7\xab\x59",
        .decimals = 18,
    },
    {
        .name = "Streamity",
        .unit = "STM",
        .contract_address =
            "\x0e\x22\x73\x4e\x07\x8d\x6e\x39\x9b\xce\xe4\x0a\x54\x9d\xb5\x91\xc4\xea\x46\xcb",
        .decimals = 18,
    },
    {
        .name = "StormX",
        .unit = "STMX",
        .contract_address =
            "\xbe\x93\x75\xc6\xa4\x20\xd2\xee\xb2\x58\x96\x2e\xfb\x95\x55\x1a\x5b\x72\x28\x03",
        .decimals = 18,
    },
    {
        .name = "Storeum",
        .unit = "STO",
        .contract_address =
            "\xcb\x39\xc3\x50\x24\x15\x15\x2b\x2e\xc9\x0f\xf0\x7e\xe1\x8c\xc9\x4f\x68\x1a\x72",
        .decimals = 18,
    },
    {
        .name = "STONK",
        .unit = "STONK",
        .contract_address =
            "\xb4\x05\x84\x11\x96\x7d\x50\x46\xf3\x51\x09\x43\x10\x38\x05\xbe\x61\xf0\x60\x0e",
        .decimals = 18,
    },
    {
        .name = "STPAY",
        .unit = "STP",
        .contract_address =
            "\x5c\x25\x0f\xf9\xb9\x93\xc6\x99\x1c\xc4\xa3\xcc\x54\x37\x16\xe5\x3b\x47\x80\x18",
        .decimals = 18,
    },
    {
        .name = "Storiqa",
        .unit = "STQ",
        .contract_address =
            "\x5c\x3a\x22\x85\x10\xd2\x46\xb7\x8a\x37\x65\xc2\x02\x21\xcb\xf3\x08\x2b\x44\xa4",
        .decimals = 18,
    },
    {
        .name = "Staker",
        .unit = "STR",
        .contract_address =
            "\xba\xe2\x35\x82\x3d\x72\x55\xd9\xd4\x86\x35\xce\xd4\x73\x52\x27\x24\x4c\xd5\x83",
        .decimals = 18,
    },
    {
        .name = "Strong",
        .unit = "STRONG",
        .contract_address =
            "\x99\x0f\x34\x19\x46\xa3\xfd\xb5\x07\xae\x7e\x52\xd1\x78\x51\xb8\x71\x68\x01\x7c",
        .decimals = 18,
    },
    {
        .name = "SBank",
        .unit = "STS",
        .contract_address =
            "\x4c\x14\x11\x4c\x10\x7d\x63\x74\xec\x31\x98\x1f\x5f\x6c\xc2\x7a\x13\xe2\x2f\x9a",
        .decimals = 18,
    },
    {
        .name = "bitJob",
        .unit = "STU",
        .contract_address =
            "\x03\x71\xa8\x2e\x4a\x9d\x0a\x43\x12\xf3\xee\x2a\xc9\xc6\x95\x85\x12\x89\x13\x72",
        .decimals = 18,
    },
    {
        .name = "Stox",
        .unit = "STX",
        .contract_address =
            "\x00\x6b\xea\x43\xba\xa3\xf7\xa6\xf7\x65\xf1\x4f\x10\xa1\xa1\xb0\x83\x34\xef\x45",
        .decimals = 18,
    },
    {
        .name = "SUKU",
        .unit = "SUKU",
        .contract_address =
            "\x07\x63\xfd\xcc\xf1\xae\x54\x1a\x59\x61\x81\x5c\x08\x72\xa8\xc5\xbc\x6d\xe4\xd7",
        .decimals = 18,
    },
    {
        .name = "Suretly",
        .unit = "SUR",
        .contract_address =
            "\xe1\x20\xc1\xec\xbf\xdf\xea\x7f\x0a\x8f\x0e\xe3\x00\x63\x49\x1e\x8c\x26\xfe\xdf",
        .decimals = 8,
    },
    {
        .name = "inSure",
        .unit = "SURE",
        .contract_address =
            "\xb5\xa4\xac\x5b\x04\xe7\x77\x23\x0b\xa3\x38\x11\x95\xef\xf6\xa6\x0c\x39\x34\xf2",
        .decimals = 18,
    },
    {
        .name = "suterusu",
        .unit = "SUTER",
        .contract_address =
            "\xba\x8c\x02\x44\xfb\xde\xb1\x0f\x19\xf6\x73\x87\x50\xda\xee\xdf\x7a\x50\x81\xeb",
        .decimals = 18,
    },
    {
        .name = "Satoshivisioncoin",
        .unit = "SVC",
        .contract_address =
            "\x64\xea\x2c\x61\x04\xf1\xcf\x30\x35\xe2\x8b\xe0\xf7\x81\xb6\x28\x6d\x50\x93\x4d",
        .decimals = 18,
    },
    {
        .name = "savedroid",
        .unit = "SVD",
        .contract_address =
            "\xbd\xeb\x4b\x83\x25\x1f\xb1\x46\x68\x7f\xa1\x9d\x1c\x66\x0f\x99\x41\x1e\xef\xe3",
        .decimals = 18,
    },
    {
        .name = "TrustSwap",
        .unit = "SWAP",
        .contract_address =
            "\xcc\x43\x04\xa3\x1d\x09\x25\x8b\x00\x29\xea\x7f\xe6\x3d\x03\x2f\x52\xe4\x4e\xfe",
        .decimals = 18,
    },
    {
        .name = "Scanetchain",
        .unit = "SWC",
        .contract_address =
            "\xad\xf8\xb8\x05\x06\x39\xb6\x23\x69\x15\xf7\x51\x6d\x69\xde\x71\x46\x72\xf0\xbf",
        .decimals = 18,
    },
    {
        .name = "Swarm City",
        .unit = "SWT",
        .contract_address =
            "\xb9\xe7\xf8\x56\x8e\x08\xd5\x65\x9f\x5d\x29\xc4\x99\x71\x73\xd8\x4c\xdf\x26\x07",
        .decimals = 18,
    },
    {
        .name = "SWYFT",
        .unit = "SWYFTT",
        .contract_address =
            "\xa1\x24\x8c\x71\x8d\x52\x75\x2b\x2c\xc2\x57\xee\xb0\xeb\xa9\x00\x40\x8d\xae\xb8",
        .decimals = 18,
    },
    {
        .name = "SymVerse",
        .unit = "SYM",
        .contract_address =
            "\x79\xb4\xd1\x2f\xa6\x3a\x8d\x12\x02\xb2\x6c\x5b\xa6\xd6\x21\x36\xa4\xa0\x9d\xda",
        .decimals = 18,
    },
    {
        .name = "Travel1Click",
        .unit = "T1C",
        .contract_address =
            "\xa7\xc7\x1d\x44\x4b\xf9\xaf\x4b\xfe\xd2\xad\xe7\x55\x95\xd7\x51\x2e\xb4\xdd\x39",
        .decimals = 16,
    },
    {
        .name = "Tokenbox",
        .unit = "TBX",
        .contract_address =
            "\x3a\x92\xbd\x39\x6a\xef\x82\xaf\x98\xeb\xc0\xaa\x90\x30\xd2\x5a\x23\xb1\x1c\x6b",
        .decimals = 18,
    },
    {
        .name = "TCASH",
        .unit = "TCASH",
        .contract_address =
            "\x70\x51\x62\x0d\x11\x04\x2c\x43\x35\x06\x9a\xaa\x4f\x10\xcd\x3b\x42\x90\xc6\x81",
        .decimals = 8,
    },
    {
        .name = "The Currency Analytics",
        .unit = "TCAT",
        .contract_address =
            "\xaf\xf8\x4e\x86\xd7\x2e\xdb\x97\x13\x41\xa6\xa6\x6e\xb2\xda\x20\x94\x46\xfa\x14",
        .decimals = 18,
    },
    {
        .name = "TigerCash",
        .unit = "TCH",
        .contract_address =
            "\x9b\x39\xa0\xb9\x73\x19\xa9\xbd\x5f\xed\x21\x7c\x1d\xb7\xb0\x30\x45\x3b\xac\x91",
        .decimals = 18,
    },
    {
        .name = "Thore Cash",
        .unit = "TCH",
        .contract_address =
            "\x99\x72\xa0\xf2\x41\x94\x44\x7e\x73\xa7\xe8\xb6\xcd\x26\xa5\x2e\x02\xdd\xfa\xd5",
        .decimals = 0,
    },
    {
        .name = "THECASH",
        .unit = "TCH",
        .contract_address =
            "\xcd\x47\x53\x71\xe3\x9c\x0d\x94\xe8\x2f\xcc\xc9\xdd\x0e\xa7\x10\xd0\xdc\x0c\x0b",
        .decimals = 18,
    },
    {
        .name = "TrueDeck",
        .unit = "TDP",
        .contract_address =
            "\x5b\x11\xaa\xcb\x6b\xdd\xb9\xff\xab\x90\x8f\xdc\xe7\x39\xbf\x4a\xed\x55\x43\x27",
        .decimals = 18,
    },
    {
        .name = "TokenDesk",
        .unit = "TDS",
        .contract_address =
            "\x62\x95\xab\x2b\xe0\x4a\x61\x77\x47\x48\x1b\x29\x2c\x39\x0b\xfc\xa5\x92\xcf\x28",
        .decimals = 18,
    },
    {
        .name = "TEAM (TokenStars)",
        .unit = "TEAM",
        .contract_address =
            "\x1c\x79\xab\x32\xc6\x6a\xca\xa1\xe9\xe8\x19\x52\xb8\xaa\xa5\x81\xb4\x3e\x54\xe7",
        .decimals = 4,
    },
    {
        .name = "TENA",
        .unit = "TENA",
        .contract_address =
            "\xe1\x4a\x60\x3f\x7c\x77\xd4\x10\x1a\x87\x85\x9b\x87\x36\xa0\x4c\xfd\x85\xc6\x88",
        .decimals = 18,
    },
    {
        .name = "Tendies",
        .unit = "TEND",
        .contract_address =
            "\x14\x53\xdb\xb8\xa2\x95\x51\xad\xe1\x1d\x89\x82\x5c\xa8\x12\xe0\x53\x17\xea\xeb",
        .decimals = 18,
    },
    {
        .name = "Tepleton",
        .unit = "TEP",
        .contract_address =
            "\x2e\x65\xe1\x2b\x5f\x0f\xd1\xd5\x87\x38\xc6\xf3\x8d\xa7\xd5\x7f\x5f\x18\x3d\x1c",
        .decimals = 8,
    },
    {
        .name = "TrueFeedBack",
        .unit = "TFB",
        .contract_address =
            "\x79\xcd\xfa\x04\xe3\xc4\xeb\x58\xc4\xf4\x9d\xae\x78\xb3\x22\xe5\xb0\xd3\x87\x88",
        .decimals = 18,
    },
    {
        .name = "Truegame",
        .unit = "TGAME",
        .contract_address =
            "\xf8\xe0\x6e\x4e\x4a\x80\x28\x7f\xdc\xa5\xb0\x2d\xcc\xec\xaa\x9d\x09\x54\x84\x0f",
        .decimals = 18,
    },
    {
        .name = "Thar Token",
        .unit = "THAR",
        .contract_address =
            "\x75\x77\x03\xbd\x5b\x2c\x4b\xbc\xfd\xe0\xbe\x2c\x0b\x0e\x7c\x2f\x31\xfc\xf4\xe9",
        .decimals = 18,
    },
    {
        .name = "Thrive Token",
        .unit = "THRT",
        .contract_address =
            "\x4f\x27\x05\x3f\x32\xed\xa8\xaf\x84\x95\x64\x37\xbc\x00\xe5\xff\xa7\x00\x32\x87",
        .decimals = 18,
    },
    {
        .name = "Thingschain",
        .unit = "TIC",
        .contract_address =
            "\x72\x43\x0a\x61\x2a\xdc\x00\x7c\x50\xe3\xb6\x94\x6d\xbb\x1b\xb0\xfd\x31\x01\xd1",
        .decimals = 8,
    },
    {
        .name = "Ties.DB",
        .unit = "TIE",
        .contract_address =
            "\x99\x99\x67\xe2\xec\x8a\x74\xb7\xc8\xe9\xdb\x19\xe0\x39\xd9\x20\xb3\x1d\x39\xd0",
        .decimals = 18,
    },
    {
        .name = "Chrono.tech",
        .unit = "TIME",
        .contract_address =
            "\x65\x31\xf1\x33\xe6\xde\xeb\xe7\xf2\xdc\xe5\xa0\x44\x1a\xa7\xef\x33\x0b\x4e\x53",
        .decimals = 8,
    },
    {
        .name = "Blocktix",
        .unit = "TIX",
        .contract_address =
            "\xea\x1f\x34\x6f\xaf\x02\x3f\x97\x4e\xb5\xad\xaf\x08\x8b\xbc\xdf\x02\xd7\x61\xf4",
        .decimals = 18,
    },
    {
        .name = "TOKPIE",
        .unit = "TKP",
        .contract_address =
            "\xd3\x16\x95\xa1\xd3\x5e\x48\x92\x52\xce\x57\xb1\x29\xfd\x4b\x1b\x05\xe6\xac\xac",
        .decimals = 18,
    },
    {
        .name = "MDsquare",
        .unit = "TMED",
        .contract_address =
            "\xd3\x26\x41\x19\x15\x78\xea\x9b\x20\x81\x25\xdd\xd4\xec\x5e\x7b\x84\xfc\xab\x4c",
        .decimals = 18,
    },
    {
        .name = "The Midas Touch Gold",
        .unit = "TMTG",
        .contract_address =
            "\x10\x08\x63\x99\xdd\x8c\x1e\x3d\xe7\x36\x72\x4a\xf5\x25\x87\xa2\x04\x4c\x9f\xa2",
        .decimals = 18,
    },
    {
        .name = "TNC Coin",
        .unit = "TNC",
        .contract_address =
            "\x39\xe7\x43\xfe\xe4\x00\xa5\xd9\xb3\x6f\x11\x67\xb7\x0c\x10\xe8\xf0\x64\x40\xe5",
        .decimals = 18,
    },
    {
        .name = "Transcodium",
        .unit = "TNS",
        .contract_address =
            "\xb0\x28\x07\x43\xb4\x4b\xf7\xdb\x4b\x6b\xe4\x82\xb2\xba\x7b\x75\xe5\xda\x09\x6c",
        .decimals = 18,
    },
    {
        .name = "TouchCon",
        .unit = "TOC",
        .contract_address =
            "\xe0\x27\x84\x17\x5c\x3b\xe0\xde\xa7\xcc\x0f\x28\x40\x41\xb6\x45\x03\x63\x9e\x66",
        .decimals = 18,
    },
    {
        .name = "Tokoin",
        .unit = "TOKO",
        .contract_address =
            "\x0c\x96\x3a\x1b\x52\xeb\x97\xc5\xe4\x57\xc7\xd7\x66\x96\xf8\xb9\x5c\x30\x87\xed",
        .decimals = 18,
    },
    {
        .name = "Tolar",
        .unit = "TOL",
        .contract_address =
            "\xd0\x7d\x9f\xe2\xd2\xcc\x06\x70\x15\xe2\xb4\x91\x7d\x24\x93\x38\x04\xf4\x2c\xfa",
        .decimals = 18,
    },
    {
        .name = "3X Long TomoChain Token",
        .unit = "TOMOBULL",
        .contract_address =
            "\xa3\x89\x20\xc0\x0d\x1a\x53\x03\xdb\x53\x8a\x3e\xa0\x8d\xa7\xa7\x79\xe1\xf7\x51",
        .decimals = 18,
    },
    {
        .name = "TopChain",
        .unit = "TOPC",
        .contract_address =
            "\x1b\x6c\x58\x64\x37\x5b\x34\xaf\x3f\xf5\xbd\x2e\x5f\x40\xbc\x42\x5b\x4a\x8d\x79",
        .decimals = 6,
    },
    {
        .name = "Thorium",
        .unit = "TORM",
        .contract_address =
            "\x8c\xea\x63\xf6\x38\x3c\x1c\x13\x63\x3f\x17\x9f\x1a\xf7\x0e\xf7\x57\x01\xa9\x79",
        .decimals = 18,
    },
    {
        .name = "ThingsOperatingSystem",
        .unit = "TOS",
        .contract_address =
            "\xfb\x5a\x55\x13\x74\xb6\x56\xc6\xe3\x97\x87\xb1\xd3\xa0\x3f\xea\xb7\xf3\xa9\x8e",
        .decimals = 18,
    },
    {
        .name = "Tourist Token",
        .unit = "TOTO",
        .contract_address =
            "\xe3\x27\x8d\xf3\xeb\x20\x85\xba\x9b\x68\x99\x81\x2a\x99\xa1\x0f\x9c\xa5\xe0\xdf",
        .decimals = 8,
    },
    {
        .name = "TokenPocket",
        .unit = "TPT",
        .contract_address =
            "\x41\x61\x72\x5d\x01\x96\x90\xa3\xe0\xde\x50\xf6\xbe\x67\xb0\x7a\x86\xa9\xfa\xe1",
        .decimals = 4,
    },
    {
        .name = "Treecle",
        .unit = "TRCL",
        .contract_address =
            "\x0a\x9d\x68\x88\x6a\x0d\x7d\xb8\x3a\x30\xec\x00\xd6\x25\x12\x48\x3e\x5a\xd4\x37",
        .decimals = 0,
    },
    {
        .name = "WeTrust",
        .unit = "TRST",
        .contract_address =
            "\xcb\x94\xbe\x6f\x13\xa1\x18\x2e\x4a\x4b\x61\x40\xcb\x7b\xf2\x02\x5d\x28\xe4\x1b",
        .decimals = 6,
    },
    {
        .name = "3X Short TRX Token",
        .unit = "TRXBEAR",
        .contract_address =
            "\x86\x80\x7d\xa5\xb9\x2d\x31\xf6\x7e\x12\x87\x71\xca\xcb\x85\xf3\x57\x96\x46\xea",
        .decimals = 18,
    },
    {
        .name = "3X Long TRX Token",
        .unit = "TRXBULL",
        .contract_address =
            "\xc1\x75\xe7\x7b\x04\xf2\x34\x15\x17\x33\x4e\xa3\xed\x0b\x19\x8a\x01\xa9\x73\x83",
        .decimals = 18,
    },
    {
        .name = "TRONCLASSIC",
        .unit = "TRXC",
        .contract_address =
            "\xad\x5f\xe5\xb0\xb8\xec\x8f\xf4\x56\x52\x04\x99\x0e\x44\x05\xb2\xda\x11\x7d\x8e",
        .decimals = 0,
    },
    {
        .name = "Trias",
        .unit = "TRY",
        .contract_address =
            "\xe4\x31\xa4\xc5\xdb\x8b\x73\xc7\x73\xe0\x6c\xf2\x58\x7d\xa1\xeb\x53\xc4\x13\x73",
        .decimals = 18,
    },
    {
        .name = "12Ships",
        .unit = "TSHP",
        .contract_address =
            "\x52\x57\x94\x47\x3f\x7a\xb5\x71\x5c\x81\xd0\x6d\x10\xf5\x2d\x11\xcc\x05\x28\x04",
        .decimals = 18,
    },
    {
        .name = "Tesra",
        .unit = "TSR",
        .contract_address =
            "\x58\x95\x9e\x0c\x71\x08\x04\x34\xf2\x37\xbd\x42\xd0\x7c\xd8\x4b\x74\xce\xf4\x38",
        .decimals = 5,
    },
    {
        .name = "The Transfer Token",
        .unit = "TTT",
        .contract_address =
            "\x24\x94\xa6\x8c\x14\x84\x37\x6f\xef\x88\x0b\x4c\x24\xd9\x1f\x04\x9d\x29\xb0\x2a",
        .decimals = 18,
    },
    {
        .name = "TV-TWO",
        .unit = "TTV",
        .contract_address =
            "\xa8\x38\xbe\x6e\x4b\x76\x0e\x60\x61\xd4\x73\x2d\x6b\x9f\x11\xbf\x57\x8f\x9a\x76",
        .decimals = 18,
    },
    {
        .name = "TUNE TOKEN",
        .unit = "TUNE",
        .contract_address =
            "\x6b\x4e\x06\x84\x80\x6f\xe5\x39\x02\x46\x9b\x62\x86\x02\x4d\xb9\xc6\x27\x1f\x53",
        .decimals = 18,
    },
    {
        .name = "TravelNote",
        .unit = "TVNT",
        .contract_address =
            "\x56\x35\xdd\xea\xbf\x9c\xdd\xa6\x86\x99\x5f\xe9\x0b\xeb\x54\x11\x83\x15\x63\xfc",
        .decimals = 8,
    },
    {
        .name = "Tweebaa",
        .unit = "TWEE",
        .contract_address =
            "\x2b\x6f\xf5\x3f\xc2\x49\x3c\xcd\x52\x02\xd8\x0a\x6c\x43\x97\x41\x41\x4c\x5f\xf2",
        .decimals = 18,
    },
    {
        .name = "Typerium",
        .unit = "TYPE",
        .contract_address =
            "\xea\xf6\x1f\xc1\x50\xcd\x5c\x3b\xea\x75\x74\x4e\x83\x0d\x91\x6e\x60\xea\x5a\x9f",
        .decimals = 4,
    },
    {
        .name = "UltrAlpha",
        .unit = "UAT",
        .contract_address =
            "\x01\xc0\x98\x7e\x88\xf7\x78\xdf\x66\x40\x78\x72\x26\xbc\x96\x35\x4e\x1a\x97\x66",
        .decimals = 18,
    },
    {
        .name = "Ubricoin",
        .unit = "UBN",
        .contract_address =
            "\xdb\x13\x02\x5b\x21\x9d\xb5\xe4\x52\x9f\x48\xb6\x5f\xf0\x09\xa2\x6b\x6a\xe7\x33",
        .decimals = 18,
    },
    {
        .name = "Unibomb",
        .unit = "UBOMB",
        .contract_address =
            "\x26\x5b\xa4\x2d\xaf\x2d\x20\xf3\xf3\x58\xa7\x36\x1d\x9f\x69\xcb\x4e\x28\xf0\xe6",
        .decimals = 18,
    },
    {
        .name = "UBU",
        .unit = "UBU",
        .contract_address =
            "\x6b\x74\xdd\x5d\x01\xf8\x32\x00\x81\x24\x7f\x5c\xf1\xf7\xa4\x83\x24\x70\x0d\xb6",
        .decimals = 8,
    },
    {
        .name = "YouLive Coin",
        .unit = "UC",
        .contract_address =
            "\xf8\x4d\xf2\xdb\x2c\x87\xdd\x65\x06\x41\xf8\x90\x4a\xf7\x1e\xbf\xc3\xdd\xe0\xea",
        .decimals = 18,
    },
    {
        .name = "UChain",
        .unit = "UCN",
        .contract_address =
            "\xaa\xf3\x70\x55\x18\x8f\xee\xe4\x86\x9d\xe6\x34\x64\x93\x7e\x68\x3d\x61\xb2\xa1",
        .decimals = 18,
    },
    {
        .name = "Ubique Chain Of Things",
        .unit = "UCT",
        .contract_address =
            "\x3c\x4b\xea\x62\x70\x39\xf0\xb7\xe7\xd2\x1e\x34\xbb\x9c\x9f\xe9\x62\x97\x75\x18",
        .decimals = 18,
    },
    {
        .name = "Hyprr (Howdoo)",
        .unit = "UDOO",
        .contract_address =
            "\x12\xf6\x49\xa9\xe8\x21\xf9\x0b\xb1\x43\x08\x9a\x6e\x56\x84\x69\x45\x89\x2f\xfb",
        .decimals = 18,
    },
    {
        .name = "Union Fair Coin",
        .unit = "UFC",
        .contract_address =
            "\x99\x5d\xe3\xd9\x61\xb4\x0e\xc6\xcd\xee\x00\x09\x05\x9d\x48\x76\x8c\xcb\xdd\x48",
        .decimals = 8,
    },
    {
        .name = "Upfiring",
        .unit = "UFR",
        .contract_address =
            "\xea\x09\x7a\x2b\x1d\xb0\x06\x27\xb2\xfa\x17\x46\x0a\xd2\x60\xc0\x16\x01\x69\x77",
        .decimals = 18,
    },
    {
        .name = "Ulgen Hash Power",
        .unit = "UHP",
        .contract_address =
            "\x91\x35\xd9\x2e\x3a\x34\xe2\xa9\x4e\x44\x74\xb7\x4b\x9d\xc2\xd5\x11\x18\xee\xd5",
        .decimals = 18,
    },
    {
        .name = "UNICORN Token",
        .unit = "UNI",
        .contract_address =
            "\x27\x30\xd6\xfd\xc8\x6c\x95\xa7\x42\x53\xbe\xff\xaa\x83\x06\xb4\x0f\xed\xec\xbb",
        .decimals = 8,
    },
    {
        .name = "Uniswap",
        .unit = "UNI",
        .contract_address =
            "\x1f\x98\x40\xa8\x5d\x5a\xf5\xbf\x1d\x17\x62\xf9\x25\xbd\xad\xdc\x42\x01\xf9\x84",
        .decimals = 18,
    },
    {
        .name = "UniDollar",
        .unit = "UNIUSD",
        .contract_address =
            "\x25\x68\x45\xe7\x21\xc0\xc4\x6d\x54\xe6\xaf\xbd\x4f\xa3\xb5\x2c\xb7\x23\x53\xea",
        .decimals = 18,
    },
    {
        .name = "UOS Network",
        .unit = "UOS",
        .contract_address =
            "\x43\x0b\xd0\x77\x26\x42\x3a\x54\xf6\xd8\x2a\xb0\xf5\x78\xce\x62\xa3\xb8\x05\x4d",
        .decimals = 4,
    },
    {
        .name = "UpToken",
        .unit = "UP",
        .contract_address =
            "\x6b\xa4\x60\xab\x75\xcd\x2c\x56\x34\x3b\x35\x17\xff\xeb\xa6\x07\x48\x65\x4d\x26",
        .decimals = 8,
    },
    {
        .name = "Pawtocol",
        .unit = "UPI",
        .contract_address =
            "\x70\xd2\xb7\xc1\x93\x52\xbb\x76\xe4\x40\x98\x58\xff\x57\x46\xe5\x00\xf2\xb6\x7c",
        .decimals = 18,
    },
    {
        .name = "Universal Protocol Token",
        .unit = "UPT",
        .contract_address =
            "\x6c\xa8\x8c\xc8\xd9\x28\x8f\x5c\xad\x82\x50\x53\xb6\xa1\xb1\x79\xb0\x5c\x76\xfc",
        .decimals = 18,
    },
    {
        .name = "HonestCoin",
        .unit = "USDH",
        .contract_address =
            "\x20\x1a\x59\x27\x0d\xd8\x5d\xa2\x66\x15\xa3\x7b\xba\x3e\xed\x86\x65\x15\x3a\xbb",
        .decimals = 2,
    },
    {
        .name = "StableUSD",
        .unit = "USDS",
        .contract_address =
            "\xa4\xbd\xb1\x1d\xc0\xa2\xbe\xc8\x8d\x24\xa3\xaa\x1e\x6b\xb1\x72\x01\x11\x2e\xbe",
        .decimals = 6,
    },
    {
        .name = "USDx stablecoin",
        .unit = "USDX",
        .contract_address =
            "\xeb\x26\x97\x32\xab\x75\xa6\xfd\x61\xea\x60\xb0\x6f\xe9\x94\xcd\x32\xa8\x35\x49",
        .decimals = 18,
    },
    {
        .name = "VEHICLE DATA ARTIFICIAL INTELLIGENCE PLATFORM",
        .unit = "VAIP",
        .contract_address =
            "\x44\x57\xdc\x5a\x9e\x71\xb9\x75\xa8\xe0\xf8\x55\xbb\xe7\x95\xf5\xcb\xdc\xc1\x0f",
        .decimals = 18,
    },
    {
        .name = "Vanta Network",
        .unit = "VANTA",
        .contract_address =
            "\xfd\xf5\x74\x76\x6b\xa1\xa9\x6a\x55\x3e\x17\x5a\xef\xfa\x85\xad\x78\x06\x3f\x0b",
        .decimals = 18,
    },
    {
        .name = "Vanywhere",
        .unit = "VANY",
        .contract_address =
            "\x4e\xdd\x66\x23\x53\x49\xe3\x53\xeb\x8c\xb8\xe4\x05\x96\x59\x96\x44\xbf\xe9\x1c",
        .decimals = 18,
    },
    {
        .name = "VARC",
        .unit = "VARC",
        .contract_address =
            "\x3f\x69\x46\x35\xab\x69\xb1\xb5\xe7\xf0\x01\xde\x26\x89\x2c\xc6\x3b\xa9\x4b\xad",
        .decimals = 18,
    },
    {
        .name = "Vether",
        .unit = "VETH",
        .contract_address =
            "\x4b\xa6\xdd\xd7\xb8\x9e\xd8\x38\xfe\xd2\x5d\x20\x8d\x4f\x64\x41\x06\xe3\x42\x79",
        .decimals = 18,
    },
    {
        .name = "VegaWallet Token",
        .unit = "VGW",
        .contract_address =
            "\x94\x23\x65\x91\x12\x5e\x93\x5f\x5a\xc1\x28\xbb\x3d\x50\x62\x94\x4c\x24\x95\x8c",
        .decimals = 5,
    },
    {
        .name = "Vid",
        .unit = "VI",
        .contract_address =
            "\xd3\x21\xca\x7c\xd7\xa2\x33\x48\x3b\x8c\xd5\xa1\x1a\x89\xe9\x33\x7e\x70\xdf\x84",
        .decimals = 18,
    },
    {
        .name = "View",
        .unit = "VIEW",
        .contract_address =
            "\xf0\x3f\x8d\x65\xba\xfa\x59\x86\x11\xc3\x49\x51\x24\x09\x3c\x56\xe8\xf6\x38\xf0",
        .decimals = 18,
    },
    {
        .name = "VikkyToken",
        .unit = "VIKKY",
        .contract_address =
            "\xd2\x94\x6b\xe7\x86\xf3\x5c\x3c\xc4\x02\xc2\x9b\x32\x36\x47\xab\xda\x79\x90\x71",
        .decimals = 8,
    },
    {
        .name = "Vinci",
        .unit = "VINCI",
        .contract_address =
            "\x3d\xb9\x9a\xb0\x80\x06\xae\xfc\xc9\x60\x09\x72\xec\xa8\xc2\x02\x39\x6b\x43\x00",
        .decimals = 18,
    },
    {
        .name = "ValueChain",
        .unit = "VLC",
        .contract_address =
            "\x8f\x7b\x0b\x40\xe2\x7e\x35\x75\x40\xf9\x0f\x18\x7d\x90\xce\x06\x36\x6a\xc5\xa5",
        .decimals = 18,
    },
    {
        .name = "Vetri",
        .unit = "VLD",
        .contract_address =
            "\x92\x2a\xc4\x73\xa3\xcc\x24\x1f\xd3\xa0\x04\x9e\xd1\x45\x36\x45\x2d\x58\xd7\x3c",
        .decimals = 18,
    },
    {
        .name = "Bankroll Vault",
        .unit = "VLT",
        .contract_address =
            "\x6b\x78\x5a\x03\x22\x12\x68\x26\xd8\x22\x6d\x77\xe1\x73\xd7\x5d\xaf\xb8\x4d\x11",
        .decimals = 18,
    },
    {
        .name = "TrueVett",
        .unit = "VME",
        .contract_address =
            "\xc3\x43\xf0\x99\xd3\xe4\x1a\xa5\xc1\xb5\x94\x70\x45\x0e\x21\xe9\x2e\x2d\x84\x0b",
        .decimals = 18,
    },
    {
        .name = "VNX Exchange",
        .unit = "VNXLU",
        .contract_address =
            "\x00\xfc\x27\x0c\x9c\xc1\x3e\x87\x8a\xb5\x36\x3d\x00\x35\x4b\xeb\xf6\xf0\x5c\x15",
        .decimals = 18,
    },
    {
        .name = "Provoco Token",
        .unit = "VOCO",
        .contract_address =
            "\xb5\xca\x46\xcf\x1d\xa0\x92\x48\x12\x66\x82\xa7\xbd\x72\x40\x1f\xd7\xa6\xb1\x51",
        .decimals = 18,
    },
    {
        .name = "Voise",
        .unit = "VOISE",
        .contract_address =
            "\x83\xee\xa0\x0d\x83\x8f\x92\xde\xc4\xd1\x47\x56\x97\xb9\xf4\xd3\x53\x7b\x56\xe3",
        .decimals = 8,
    },
    {
        .name = "VeraOne",
        .unit = "VRO",
        .contract_address =
            "\x10\xbc\x51\x8c\x32\xfb\xae\x5e\x38\xec\xb5\x0a\x61\x21\x60\x57\x1b\xd8\x1e\x44",
        .decimals = 8,
    },
    {
        .name = "Veros",
        .unit = "VRS",
        .contract_address =
            "\xab\xc4\x30\x13\x6a\x4d\xe7\x1c\x99\x98\x24\x2d\xe8\xc1\xb4\xb9\x7d\x2b\x90\x45",
        .decimals = 6,
    },
    {
        .name = "vSportCoin",
        .unit = "VSC",
        .contract_address =
            "\x36\xb4\xb5\x8d\xe0\x30\xe9\x37\x75\xe1\x51\xa7\x8d\x79\x60\x39\xa1\x1a\x25\x48",
        .decimals = 8,
    },
    {
        .name = "VeriSafe",
        .unit = "VSF",
        .contract_address =
            "\xba\x3a\x79\xd7\x58\xf1\x9e\xfe\x58\x82\x47\x38\x87\x54\xb8\xe4\xd6\xed\xda\x81",
        .decimals = 18,
    },
    {
        .name = "vSlice",
        .unit = "VSL",
        .contract_address =
            "\x5c\x54\x3e\x7a\xe0\xa1\x10\x4f\x78\x40\x6c\x34\x0e\x9c\x64\xfd\x9f\xce\x51\x70",
        .decimals = 18,
    },
    {
        .name = "Vision Network",
        .unit = "VSN",
        .contract_address =
            "\x45\x6a\xe4\x5c\x0c\xe9\x01\xe2\xe7\xc9\x9c\x07\x18\x03\x1c\xec\x0a\x7a\x59\xff",
        .decimals = 18,
    },
    {
        .name = "Vectorspace AI",
        .unit = "VXV",
        .contract_address =
            "\x7d\x29\xa6\x45\x04\x62\x91\x72\xa4\x29\xe6\x41\x83\xd6\x67\x3b\x9d\xac\xbf\xce",
        .decimals = 18,
    },
    {
        .name = "WABnetwork",
        .unit = "WAB",
        .contract_address =
            "\x4b\xbb\xc5\x7a\xf2\x70\x13\x8e\xf2\xff\x2c\x50\xdb\xfa\xd6\x84\xe9\xe0\xe6\x04",
        .decimals = 18,
    },
    {
        .name = "WandX",
        .unit = "WAND",
        .contract_address =
            "\x27\xf6\x10\xbf\x36\xec\xa0\x93\x90\x93\x34\x3a\xc2\x8b\x15\x34\xa7\x21\xdb\xb4",
        .decimals = 18,
    },
    {
        .name = "WiBX",
        .unit = "WBX",
        .contract_address =
            "\xbb\x97\xe3\x81\xf1\xd1\xe9\x4f\xfa\x2a\x58\x44\xf6\x87\x5e\x61\x46\x98\x10\x09",
        .decimals = 18,
    },
    {
        .name = "Webcoin",
        .unit = "WEB",
        .contract_address =
            "\x84\x0f\xe7\x5a\xbf\xad\xc0\xf2\xd5\x40\x37\x82\x95\x71\xb2\x78\x2e\x91\x9c\xe4",
        .decimals = 18,
    },
    {
        .name = "WEBN token",
        .unit = "WEBN",
        .contract_address =
            "\x15\xa6\x64\x41\x6e\x42\x76\x6a\x6c\xc0\xa1\x22\x1d\x9c\x08\x85\x48\xa6\xe7\x31",
        .decimals = 8,
    },
    {
        .name = "WeShow Token",
        .unit = "WET",
        .contract_address =
            "\x36\xd1\x0c\x68\x00\xd5\x69\xbb\x8c\x4f\xe2\x84\xa0\x5f\xfe\x3b\x75\x2f\x97\x2c",
        .decimals = 18,
    },
    {
        .name = "WETH",
        .unit = "WETH",
        .contract_address =
            "\xc0\x2a\xaa\x39\xb2\x23\xfe\x8d\x0a\x0e\x5c\x4f\x27\xea\xd9\x08\x3c\x75\x6c\xc2",
        .decimals = 18,
    },
    {
        .name = "Webflix Token",
        .unit = "WFX",
        .contract_address =
            "\xd1\x11\xbc\xb8\xc3\x0a\x60\x0c\x12\xf4\xaf\x83\x14\x23\x5f\x62\x8e\xa2\xcb\x3c",
        .decimals = 18,
    },
    {
        .name = "W Green Pay",
        .unit = "WGP",
        .contract_address =
            "\xdd\x94\x84\x2c\x15\xab\xfe\x4c\x9b\xaf\xe4\x22\x2a\xde\x02\x89\x6b\xeb\x06\x4c",
        .decimals = 18,
    },
    {
        .name = "WHEN Token",
        .unit = "WHEN",
        .contract_address =
            "\xf4\xfe\x95\x60\x38\x81\xd0\xe0\x79\x54\xfd\x76\x05\xe0\xe9\xa9\x16\xe4\x2c\x44",
        .decimals = 18,
    },
    {
        .name = "Project WITH",
        .unit = "WIKEN",
        .contract_address =
            "\xb7\xe7\x7a\xeb\xbe\x06\x87\xd2\xef\xf2\x4c\xc9\x0c\x41\xa3\xb6\xea\x74\xbd\xab",
        .decimals = 18,
    },
    {
        .name = "WITChain",
        .unit = "WIT",
        .contract_address =
            "\xe1\x3e\xf2\x57\xcf\x4d\x5d\xf9\x28\xca\x11\xd2\x30\x42\x7c\x03\x76\x66\xd4\x66",
        .decimals = 6,
    },
    {
        .name = "CrowdWiz",
        .unit = "WIZ",
        .contract_address =
            "\x2f\x9b\x67\x79\xc3\x7d\xf5\x70\x72\x49\xee\xb3\x73\x4b\xbf\xc9\x47\x63\xfb\xe2",
        .decimals = 18,
    },
    {
        .name = "WinStars.live",
        .unit = "WNL",
        .contract_address =
            "\xcf\xbf\x70\xe3\x3d\x51\x63\xe2\x5b\x0d\xad\x73\x95\x5c\x1b\xd9\xe8\xcd\x8b\xa2",
        .decimals = 18,
    },
    {
        .name = "Wrapped NXM",
        .unit = "WNXM",
        .contract_address =
            "\x0d\x43\x8f\x3b\x51\x75\xbe\xbc\x26\x2b\xf2\x37\x53\xc1\xe5\x3d\x03\x43\x2b\xde",
        .decimals = 18,
    },
    {
        .name = "WOM Protocol",
        .unit = "WOM",
        .contract_address =
            "\xa9\x82\xb2\xe1\x9e\x90\xb2\xd9\xf7\x94\x8e\x9c\x1b\x65\xd1\x19\xf1\xce\x88\xd6",
        .decimals = 18,
    },
    {
        .name = "WPP TOKEN",
        .unit = "WPP",
        .contract_address =
            "\x05\x6d\xd2\x0b\x01\x79\x9e\x9c\x19\x52\xc7\xc9\xa5\xff\x44\x09\xa6\x11\x00\x85",
        .decimals = 18,
    },
    {
        .name = "WeSing Coin",
        .unit = "WSC",
        .contract_address =
            "\x2d\xcd\x9b\x1a\x7e\xd4\x08\xff\x48\xbd\x49\x18\xa1\xf9\xc0\x53\x5d\xc5\x4e\xad",
        .decimals = 6,
    },
    {
        .name = "Waletoken",
        .unit = "WTN",
        .contract_address =
            "\x0e\xa9\x84\xe7\x89\x30\x2b\x7b\x61\x21\x47\xe4\xe4\x14\x4e\x64\xf2\x14\x25\xeb",
        .decimals = 8,
    },
    {
        .name = "WXCOINS",
        .unit = "WXC",
        .contract_address =
            "\x0e\xe1\x15\x00\xe7\xcf\xe6\x12\x4e\x37\x16\xcd\x77\x55\xa0\xf0\xf2\x11\x62\x44",
        .decimals = 0,
    },
    {
        .name = "wys Token",
        .unit = "WYS",
        .contract_address =
            "\xd8\x95\x0f\xde\xaa\x10\x30\x4b\x7a\x7f\xd0\x3a\x2f\xc6\x6b\xc3\x9f\x3c\x71\x1a",
        .decimals = 18,
    },
    {
        .name = "X8X Token",
        .unit = "X8X",
        .contract_address =
            "\x91\x0d\xfc\x18\xd6\xea\x3d\x6a\x71\x24\xa6\xf8\xb5\x45\x8f\x28\x10\x60\xfa\x4c",
        .decimals = 18,
    },
    {
        .name = "Xank",
        .unit = "XANK",
        .contract_address =
            "\x0e\x7f\x79\xe8\x9b\xa8\xc4\xa1\x34\x31\x12\x9f\xb2\xdb\x0d\x4f\x44\x4b\x5b\x9a",
        .decimals = 16,
    },
    {
        .name = "Tether Gold",
        .unit = "XAUT",
        .contract_address =
            "\x49\x22\xa0\x15\xc4\x40\x7f\x87\x43\x2b\x17\x9b\xb2\x09\xe1\x25\x43\x2e\x4a\x2a",
        .decimals = 6,
    },
    {
        .name = "BlitzPredict",
        .unit = "XBP",
        .contract_address =
            "\x28\xde\xe0\x1d\x53\xfe\xd0\xed\xf5\xf6\xe3\x10\xbf\x8e\xf9\x31\x15\x13\xae\x40",
        .decimals = 18,
    },
};

const app_eth_erc20_params_t* app_eth_erc20_params_get(
    ETHCoin coin,
    const uint8_t* contract_address)
{
    const app_eth_erc20_params_t* erc20_params;
    size_t len;
    switch (coin) {
    case ETHCoin_ETH:
        erc20_params = _ethereum_erc20_params;
        len = sizeof(_ethereum_erc20_params) / sizeof(app_eth_erc20_params_t);
        break;
    case ETHCoin_RopstenETH:
        erc20_params = _ropsten_erc20_params;
        len = sizeof(_ropsten_erc20_params) / sizeof(app_eth_erc20_params_t);
        break;
    default:
        return NULL;
    }
    for (size_t index = 0; index < len; index++) {
        const app_eth_erc20_params_t* params = &erc20_params[index];
        if (MEMEQ(contract_address, params->contract_address, sizeof(params->contract_address))) {
            return params;
        }
    }
    return NULL;
}
