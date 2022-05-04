#!/usr/bin/env python3
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
"""Script for interacting with bitbox v2"""

# pylint: disable=too-many-lines

import argparse
import pprint
import sys
from typing import List, Any, Optional, Callable, Union, Tuple, Sequence
import base64
import binascii
import textwrap

import requests  # type: ignore
import hid
from tzlocal import get_localzone  # type: ignore

from bitbox02 import util
from bitbox02 import bitbox02
from bitbox02.communication import (
    devices,
    HARDENED,
    Bitbox02Exception,
    UserAbortException,
    FirmwareVersionOutdatedException,
    u2fhid,
    bitbox_api_protocol,
)

import u2f
import u2f.bitbox02


def eprint(*args: Any, **kwargs: Any) -> None:
    """
    Like print, but defaults to stderr.
    """
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


def ask_user(
    choices: Sequence[Tuple[str, Callable[[], None]]]
) -> Union[Callable[[], None], bool, None]:
    """Ask user to choose one of the choices, q quits"""
    print("What would you like to do?")
    for (idx, choice) in enumerate(choices):
        print(f"- ({idx+1}) {choice[0]}")
    print("- (q) Quit")
    ans_str = input("")
    if ans_str == "q":
        return False
    try:
        ans = int(ans_str)
        if ans < 1 or ans > len(choices):
            raise ValueError("Out of range")
    except ValueError:
        print("Invalid input")
        return None
    return choices[ans - 1][1]


def _btc_demo_inputs_outputs(
    bip44_account: int,
) -> Tuple[List[bitbox02.BTCInputType], List[bitbox02.BTCOutputType]]:
    """
    Returns a sample btc tx.
    """
    inputs: List[bitbox02.BTCInputType] = [
        {
            "prev_out_hash": binascii.unhexlify(
                "c58b7e3f1200e0c0ec9a5e81e925baface2cc1d4715514f2d8205be2508b48ee"
            ),
            "prev_out_index": 0,
            "prev_out_value": int(1e8 * 0.60005),
            "sequence": 0xFFFFFFFF,
            "keypath": [84 + HARDENED, 0 + HARDENED, bip44_account, 0, 0],
            "script_config_index": 0,
            "prev_tx": {
                "version": 1,
                "locktime": 0,
                "inputs": [
                    {
                        "prev_out_hash": b"11111111111111111111111111111111",
                        "prev_out_index": 0,
                        "signature_script": b"some signature script",
                        "sequence": 0xFFFFFFFF,
                    }
                ],
                "outputs": [
                    {
                        "value": int(1e8 * 0.60005),
                        "pubkey_script": b"some pubkey script",
                    }
                ],
            },
        },
        {
            "prev_out_hash": binascii.unhexlify(
                "c58b7e3f1200e0c0ec9a5e81e925baface2cc1d4715514f2d8205be2508b48ee"
            ),
            "prev_out_index": 1,
            "prev_out_value": int(1e8 * 0.60005),
            "sequence": 0xFFFFFFFF,
            "keypath": [49 + HARDENED, 0 + HARDENED, bip44_account, 0, 1],
            "script_config_index": 1,
            "prev_tx": {
                "version": 1,
                "locktime": 0,
                "inputs": [
                    {
                        "prev_out_hash": b"11111111111111111111111111111111",
                        "prev_out_index": 0,
                        "signature_script": b"some signature script",
                        "sequence": 0xFFFFFFFF,
                    }
                ],
                "outputs": [
                    {
                        "value": int(1e8 * 0.60005),
                        "pubkey_script": b"some pubkey script",
                    }
                ],
            },
        },
    ]
    outputs: List[bitbox02.BTCOutputType] = [
        bitbox02.BTCOutputInternal(
            keypath=[84 + HARDENED, 0 + HARDENED, bip44_account, 1, 0],
            value=int(1e8 * 1),
            script_config_index=0,
        ),
        bitbox02.BTCOutputExternal(
            output_type=bitbox02.btc.P2WSH,
            output_payload=b"11111111111111111111111111111111",
            value=int(1e8 * 0.2),
        ),
    ]
    return inputs, outputs


class SendMessage:
    """SendMessage"""

    def __init__(self, device: bitbox02.BitBox02, debug: bool):
        self._device = device
        self._debug = debug
        self._stop = False

    def _change_name_workflow(self, name: Optional[str] = None) -> None:
        """
        Invoke change name workfow.
        """
        if name is None:
            name = input("Enter a name [Mia] (max 64 bytes): ")
            if not name:
                name = "Mia"
        info = self._device.device_info()
        print(f"Old device name: {info['name']}")
        try:
            self._device.set_device_name(name)
        except UserAbortException:
            eprint("Aborted by user")
        else:
            print("Setting new device name.")
            info = self._device.device_info()
            print(f"New device name: {info['name']}")

    def _setup_workflow(self) -> None:
        """TODO: Document"""
        self._device.insert_sdcard()
        print("SD Card Inserted")
        self._change_name_workflow("Shifty")
        print(
            "Please choose a password of the BitBox02. "
            + "This password will be used to unlock your BitBox02."
        )
        while not self._device.set_password():
            eprint("Passwords did not match. please try again")

        print("Your BitBox02 will now create a backup of your wallet...")
        print("Please confirm the date on your device.")
        if not self._device.create_backup():
            eprint("Creating the backup failed")
            return
        print("Backup created sucessfully")

        print("Please Remove SD Card")
        self._device.remove_sdcard()

    def _print_backups(self, backups: Optional[Sequence[bitbox02.Backup]] = None) -> None:
        local_timezone = get_localzone()
        if backups is None:
            backups = list(self._device.list_backups())
        if not backups:
            print("No backups found.")
            return
        fmt = "%Y-%m-%d %H:%M:%S %z"
        for (i, (backup_id, backup_name, date)) in enumerate(backups):
            date = local_timezone.localize(date)
            date_str = date.strftime(fmt)
            print(f"[{i+1}] Backup Name: {backup_name}, Time: {date_str}, ID: {backup_id}")

    def _restore_backup_workflow(self) -> None:
        """TODO: Document"""
        backups = list(self._device.list_backups())
        self._print_backups(backups)
        if not backups:
            return
        ans = input(f"Choose a backup [1-{len(backups)}]: ")
        try:
            item = int(ans)
            if item < 1 or item > len(backups):
                raise ValueError("Out of range")
        except ValueError:
            eprint("Invalid input")
            return
        backup_id, _, _ = backups[item - 1]
        print(f"ID: {backup_id}")
        try:
            self._device.restore_backup(backup_id)
        except UserAbortException:
            eprint("Aborted by user")
            return
        except Bitbox02Exception:
            eprint("Restoring backup failed")
            return
        print("Please Remove SD Card")
        self._device.remove_sdcard()

    def _restore_from_mnemonic(self) -> None:
        try:
            self._device.restore_from_mnemonic()
            print("Restore successful")
        except UserAbortException:
            print("Aborted by user")

    def _list_device_info(self) -> None:
        print(f"All info: {self._device.device_info()}")

    def _reboot(self) -> None:
        inp = input("Select one of: 1=upgrade; 2=go to startup settings: ").strip()
        purpose = {
            "1": bitbox02.system.RebootRequest.Purpose.UPGRADE,  # pylint: disable=no-member
            "2": bitbox02.system.RebootRequest.Purpose.SETTINGS,  # pylint: disable=no-member
        }[inp]
        if self._device.reboot(purpose=purpose):
            print("Device rebooted")
            self._stop = True
        else:
            print("User aborted")

    def _check_sd_presence(self) -> None:
        print(f"SD Card inserted: {self._device.check_sdcard()}")

    def _insert_sdcard(self) -> None:
        self._device.insert_sdcard()

    def _remove_sdcard(self) -> None:
        self._device.remove_sdcard()

    def _get_root_fingerprint(self) -> None:
        print(f"Root fingerprint: {self._device.root_fingerprint().hex()}")
        self._device.root_fingerprint(display=True)

    def _display_zpub(self) -> None:
        try:
            print(
                "m/84'/0'/0' zpub: ",
                self._device.btc_xpub(
                    keypath=[84 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                    xpub_type=bitbox02.btc.BTCPubRequest.ZPUB,  # pylint: disable=no-member
                ),
            )
        except UserAbortException:
            eprint("Aborted by user")

    def _get_electrum_encryption_key(self) -> None:
        print(
            "Electrum wallet encryption xpub at keypath m/4541509'/1112098098':",
            self._device.electrum_encryption_key(
                keypath=[4541509 + HARDENED, 1112098098 + HARDENED]
            ),
        )

    def _btc_address(self) -> None:
        def address(display: bool) -> str:
            # pylint: disable=no-member
            return self._device.btc_address(
                keypath=[84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0],
                script_config=bitbox02.btc.BTCScriptConfig(
                    simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                ),
                display=display,
            )

        print("m/84'/0'/0'/0/0 address: ", address(False))
        address(True)

    def _btc_multisig_config(self, coin: "bitbox02.btc.BTCCoin.V") -> bitbox02.btc.BTCScriptConfig:
        """
        Get a mock multisig 1-of-2 multisig with the current device and some other arbitrary xpub.
        Registers it on the device if not already registered.
        """
        account_keypath = [48 + HARDENED, 0 + HARDENED, 0 + HARDENED, 2 + HARDENED]

        my_xpub = self._device.btc_xpub(
            keypath=account_keypath,
            coin=coin,
            xpub_type=bitbox02.btc.BTCPubRequest.XPUB,  # pylint: disable=no-member,
            display=False,
        )
        multisig_config = bitbox02.btc.BTCScriptConfig(
            multisig=bitbox02.btc.BTCScriptConfig.Multisig(
                threshold=1,
                xpubs=[
                    util.parse_xpub(my_xpub),
                    util.parse_xpub(
                        "xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazW"
                        "HLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy"
                    ),
                ],
                our_xpub_index=0,
            )
        )

        is_registered = self._device.btc_is_script_config_registered(
            coin, multisig_config, account_keypath
        )
        if is_registered:
            print("Multisig account already registered on the device.")
        else:
            multisig_name = input("Enter a name for the multisig account: ").strip()
            self._device.btc_register_script_config(
                coin=coin,
                script_config=multisig_config,
                keypath=account_keypath,
                name=multisig_name,
            )

        return multisig_config

    def _btc_multisig_address(self) -> None:
        try:
            coin = bitbox02.btc.BTC
            print(
                self._device.btc_address(
                    coin=coin,
                    keypath=[
                        48 + HARDENED,
                        0 + HARDENED,
                        0 + HARDENED,
                        2 + HARDENED,
                        1,
                        2,
                    ],
                    script_config=self._btc_multisig_config(coin),
                    display=True,
                )
            )
        except UserAbortException:
            print("Aborted by user")

    def _sign_btc_normal(self) -> None:
        # pylint: disable=no-member
        bip44_account: int = 0 + HARDENED
        inputs, outputs = _btc_demo_inputs_outputs(bip44_account)
        sigs = self._device.btc_sign(
            bitbox02.btc.BTC,
            [
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=[84 + HARDENED, 0 + HARDENED, bip44_account],
                ),
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
                    ),
                    keypath=[49 + HARDENED, 0 + HARDENED, bip44_account],
                ),
            ],
            inputs=inputs,
            outputs=outputs,
        )
        for input_index, sig in sigs:
            print("Signature for input {}: {}".format(input_index, sig.hex()))

    def _sign_btc_multiple_changes(self) -> None:
        # pylint: disable=no-member
        bip44_account: int = 0 + HARDENED
        inputs, outputs = _btc_demo_inputs_outputs(bip44_account)
        # Add a change output.
        outputs.append(
            bitbox02.BTCOutputInternal(
                keypath=[84 + HARDENED, 0 + HARDENED, bip44_account, 1, 0],
                value=int(1),
                script_config_index=0,
            )
        )
        sigs = self._device.btc_sign(
            bitbox02.btc.BTC,
            [
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=[84 + HARDENED, 0 + HARDENED, bip44_account],
                ),
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
                    ),
                    keypath=[49 + HARDENED, 0 + HARDENED, bip44_account],
                ),
            ],
            inputs=inputs,
            outputs=outputs,
        )
        for input_index, sig in sigs:
            print("Signature for input {}: {}".format(input_index, sig.hex()))

    def _sign_btc_locktime_rbf(self) -> None:
        # pylint: disable=no-member
        bip44_account: int = 0 + HARDENED
        inputs, outputs = _btc_demo_inputs_outputs(bip44_account)
        inputs[0]["sequence"] = 0xFFFFFFFF - 2
        sigs = self._device.btc_sign(
            bitbox02.btc.BTC,
            [
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=[84 + HARDENED, 0 + HARDENED, bip44_account],
                ),
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
                    ),
                    keypath=[49 + HARDENED, 0 + HARDENED, bip44_account],
                ),
            ],
            inputs=inputs,
            outputs=outputs,
            locktime=10,
        )
        for input_index, sig in sigs:
            print("Signature for input {}: {}".format(input_index, sig.hex()))

    def _sign_btc_taproot_inputs(self) -> None:
        # pylint: disable=no-member
        bip44_account: int = 0 + HARDENED
        inputs, outputs = _btc_demo_inputs_outputs(bip44_account)
        for inp in inputs:
            inp["keypath"] = [86 + HARDENED] + list(inp["keypath"][1:])
            inp["prev_tx"] = None
            inp["script_config_index"] = 0
        for outp in outputs:
            if isinstance(outp, bitbox02.BTCOutputInternal):
                outp.keypath = [86 + HARDENED] + list(outp.keypath[1:])
        script_configs = [
            bitbox02.btc.BTCScriptConfigWithKeypath(
                script_config=bitbox02.btc.BTCScriptConfig(
                    simple_type=bitbox02.btc.BTCScriptConfig.P2TR
                ),
                keypath=[86 + HARDENED, 0 + HARDENED, bip44_account],
            ),
        ]
        assert not bitbox02.btc_sign_needs_prevtxs(script_configs)
        sigs = self._device.btc_sign(
            bitbox02.btc.BTC,
            script_configs,
            inputs=inputs,
            outputs=outputs,
        )
        for input_index, sig in sigs:
            print("Signature for input {}: {}".format(input_index, sig.hex()))

    def _sign_btc_taproot_output(self) -> None:
        # pylint: disable=no-member
        bip44_account: int = 0 + HARDENED
        inputs, outputs = _btc_demo_inputs_outputs(bip44_account)
        assert isinstance(outputs[1], bitbox02.BTCOutputExternal)
        outputs[1].type = bitbox02.btc.P2TR
        outputs[1].payload = bytes.fromhex(
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        )
        sigs = self._device.btc_sign(
            bitbox02.btc.BTC,
            [
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=[84 + HARDENED, 0 + HARDENED, bip44_account],
                ),
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
                    ),
                    keypath=[49 + HARDENED, 0 + HARDENED, bip44_account],
                ),
            ],
            inputs=inputs,
            outputs=outputs,
        )
        for input_index, sig in sigs:
            print("Signature for input {}: {}".format(input_index, sig.hex()))

    def _sign_btc_tx_from_raw(self) -> None:
        """
        Experiment with testnet transactions.
        Uses blockchair.com to convert a testnet transaction to the input required by btc_sign(),
        including the previous transactions.
        """
        # pylint: disable=no-member

        def get(tx_id: str) -> Any:
            return requests.get(
                "https://api.blockchair.com/bitcoin/testnet/dashboards/transaction/{}".format(tx_id)
            ).json()["data"][tx_id]

        tx_id = input("Paste a btc testnet tx ID: ").strip()
        tx = get(tx_id)

        inputs: List[bitbox02.BTCInputType] = []
        outputs: List[bitbox02.BTCOutputType] = []

        bip44_account: int = 0 + HARDENED

        for inp in tx["inputs"]:
            print("Downloading prev tx")
            prev_tx = get(inp["transaction_hash"])
            print("Downloaded prev tx")
            prev_inputs: List[bitbox02.BTCPrevTxInputType] = []
            prev_outputs: List[bitbox02.BTCPrevTxOutputType] = []

            for prev_inp in prev_tx["inputs"]:
                prev_inputs.append(
                    {
                        "prev_out_hash": binascii.unhexlify(prev_inp["transaction_hash"])[::-1],
                        "prev_out_index": prev_inp["index"],
                        "signature_script": binascii.unhexlify(prev_inp["spending_signature_hex"]),
                        "sequence": prev_inp["spending_sequence"],
                    }
                )
            for prev_outp in prev_tx["outputs"]:
                prev_outputs.append(
                    {
                        "value": prev_outp["value"],
                        "pubkey_script": binascii.unhexlify(prev_outp["script_hex"]),
                    }
                )

            inputs.append(
                {
                    "prev_out_hash": binascii.unhexlify(inp["transaction_hash"])[::-1],
                    "prev_out_index": inp["index"],
                    "prev_out_value": inp["value"],
                    "sequence": inp["spending_sequence"],
                    "keypath": [84 + HARDENED, 1 + HARDENED, bip44_account, 0, 0],
                    "script_config_index": 0,
                    "prev_tx": {
                        "version": prev_tx["transaction"]["version"],
                        "locktime": prev_tx["transaction"]["lock_time"],
                        "inputs": prev_inputs,
                        "outputs": prev_outputs,
                    },
                }
            )

        for outp in tx["outputs"]:
            outputs.append(
                bitbox02.BTCOutputExternal(
                    # TODO: parse pubkey script
                    output_type=bitbox02.btc.P2WSH,
                    output_payload=b"11111111111111111111111111111111",
                    value=outp["value"],
                )
            )

        print("Start signing...")
        self._device.btc_sign(
            bitbox02.btc.TBTC,
            [
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=[84 + HARDENED, 1 + HARDENED, bip44_account],
                )
            ],
            inputs=inputs,
            outputs=outputs,
        )

    def _sign_btc_tx(self) -> None:
        """btc signing demos"""
        choices = (
            ("Normal tx", self._sign_btc_normal),
            ("Multiple change outputs", self._sign_btc_multiple_changes),
            ("Locktime/RBF", self._sign_btc_locktime_rbf),
            ("Taproot inputs", self._sign_btc_taproot_inputs),
            ("Taproot output", self._sign_btc_taproot_output),
            ("From testnet tx ID", self._sign_btc_tx_from_raw),
        )
        choice = ask_user(choices)
        if callable(choice):
            try:
                choice()
            except UserAbortException:
                eprint("Aborted by user")

    def _sign_btc_message(self) -> None:
        # pylint: disable=no-member

        keypath = [49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0]
        script_config = bitbox02.btc.BTCScriptConfig(
            simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
        )
        address = self._device.btc_address(
            keypath=keypath, script_config=script_config, display=False
        )

        print("Address:", address)

        msg = input(r"Message to sign (\n = newline): ")
        if msg.startswith("0x"):
            msg_bytes = binascii.unhexlify(msg[2:])
        else:
            msg_bytes = msg.replace(r"\n", "\n").encode("utf-8")

        try:
            _, _, sig65 = self._device.btc_sign_msg(
                bitbox02.btc.BTC,
                bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=script_config, keypath=keypath
                ),
                msg_bytes,
            )
            print("Signature:", base64.b64encode(sig65).decode("ascii"))
        except UserAbortException:
            print("Aborted by user")

    def _check_backup(self) -> None:
        print("Your BitBox02 will now perform a backup check")
        try:
            backup_id = self._device.check_backup()
        except UserAbortException:
            print("Aborted by user")
        else:
            if backup_id:
                print(f"Check successful. Backup with ID {backup_id} matches")
            else:
                print("No matching backup found")

    def _show_mnemnoic_seed(self) -> None:
        print("Your BitBox02 will now show the mnemonic seed phrase")
        try:
            self._device.show_mnemonic()
            print("Success")
        except UserAbortException:
            print("Aborted by user")

    def _create_backup(self) -> None:
        if self._device.check_backup(silent=True) is not None:
            if input("A backup already exists, continue? Y/n: ") not in ("", "Y", "y"):
                return
        try:
            if not self._device.create_backup():
                eprint("Creating the backup failed")
            else:
                print("Backup created sucessfully")
        except UserAbortException:
            print("Aborted by user")

    def _toggle_mnemonic_passphrase(self) -> None:
        enabled = self._device.device_info()["mnemonic_passphrase_enabled"]
        try:
            if enabled:
                if input("Mnemonic passprase enabled, disable? Y/n: ") not in (
                    "",
                    "Y",
                    "y",
                ):
                    return
                self._device.disable_mnemonic_passphrase()
            else:
                if input("Mnemonic passprase disabled, enable? Y/n: ") not in (
                    "",
                    "Y",
                    "y",
                ):
                    return
                self._device.enable_mnemonic_passphrase()
            enabled = not enabled
        except UserAbortException:
            print("Aborted by user")
        print("Success.")
        if enabled:
            print("You can enter a mnemonic passphrase on the next unlock.")
            print("Replug your BitBox02.")

    def _get_eth_xpub(self) -> None:
        try:
            xpub = self._device.eth_pub(
                keypath=[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0],
                output_type=bitbox02.eth.ETHPubRequest.XPUB,  # pylint: disable=no-member
                display=False,
            )
        except UserAbortException:
            eprint("Aborted by user")

        print("Ethereum xpub: {}".format(xpub))

    def _display_eth_address(self, contract_address: bytes = b"") -> None:
        def address(display: bool = False) -> str:
            return self._device.eth_pub(
                keypath=[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0],
                output_type=bitbox02.eth.ETHPubRequest.ADDRESS,  # pylint: disable=no-member
                contract_address=contract_address,
                display=display,
            )

        print("Ethereum address: {}".format(address(display=False)))
        try:
            address(display=True)
        except UserAbortException:
            eprint("Aborted by user")

    def _sign_eth_tx(self) -> None:
        # pylint: disable=line-too-long

        inp = input(
            "Select one of: 1=normal; 2=erc20; 3=erc721; 4=unknown erc20; 5=large data field; 6=BSC; 7=unknown network: "
        ).strip()

        chain_id = 1  # mainnet
        if inp == "6":
            chain_id = 56
        elif inp == "7":
            chain_id = 123456

        if inp in ("1", "6", "7"):
            # fmt: off
            tx = bytes([0xf8, 0x6e, 0x82, 0x1f, 0xdc, 0x85, 0x01, 0x65, 0xa0, 0xbc, 0x00, 0x82, 0x52,
            0x08, 0x94, 0x04, 0xf2, 0x64, 0xcf, 0x34, 0x44, 0x03, 0x13, 0xb4, 0xa0, 0x19, 0x2a,
            0x35, 0x28, 0x14, 0xfb, 0xe9, 0x27, 0xb8, 0x85, 0x88, 0x07, 0x5c, 0xf1, 0x25, 0x9e,
            0x9c, 0x40, 0x00, 0x80, 0x25, 0xa0, 0x15, 0xc9, 0x4c, 0x1a, 0x3d, 0xa0, 0xab, 0xc0,
            0xa9, 0x12, 0x4d, 0x28, 0x37, 0x80, 0x9c, 0xcc, 0x49, 0x3c, 0x41, 0x50, 0x4e, 0x45,
            0x71, 0xbc, 0xc3, 0x40, 0xee, 0xb6, 0x8a, 0x91, 0xf6, 0x41, 0xa0, 0x35, 0x99, 0x01,
            0x1d, 0x4c, 0xda, 0x2c, 0x33, 0xdd, 0x3b, 0x00, 0x07, 0x1e, 0xc1, 0x45, 0x33, 0x5e,
            0x5d, 0x2d, 0xd5, 0xed, 0x81, 0x2d, 0x5e, 0xeb, 0xee, 0xcb, 0xa5, 0x26, 0x4e, 0xd1,
            0xbf])
            # fmt: on
        elif inp == "2":
            tx = binascii.unhexlify(
                "f8ac82236785027aca1a808301d04894dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb000000000000000000000000e6ce0a092a99700cd4ccccbb1fedc39cf53e6330000000000000000000000000000000000000000000000000000000000365c0401ca0265f70103c605eaa1b64c3200d2e7934d7744a3068b377e26c4b080795c744c0a020bbcd34a306621fa8965040390bc240d6d0e3b88915ccdb309d15f1caba81b1"
            )
        elif inp == "3":
            tx = binascii.unhexlify(
                "f87282750b8502cb42fea0830927c0942cab2d282e588f00beabe2bf5577c7644972e10f808b00009470ff1c8de91c861d1ca0f07bca4f43eb1c461ca3cf208e920b60cb393dd37489a14e9f92632acb17dd7ca0694523c8b72052cf6a8b9f93719a664fbbbe59e731cefb1331b2d21ee80b5268"
            )
        elif inp == "4":
            tx = binascii.unhexlify(
                "f8aa81b9843b9aca0083010985949c23d67aea7b95d80942e3836bcdf7e708a747c180b844a9059cbb000000000000000000000000857b3d969eacb775a9f79cabc62ec4bb1d1cd60e000000000000000000000000000000000000000000000098a63cbeb859d027b026a0d3b1a9ba4aff7ebf81dca7dafdbe6d803d174f7805276f45530f2c30e74f5ffca02d86d5290f6ba2c5100e08764d8ab34cf33b03dff3f63219fd839ac9a95f7068"
            )
        elif inp == "5":
            tx = binascii.unhexlify(
                "f9016881b9843b9aca0083010985949c23d67aea7b95d80942e3836bcdf7e708a747c180b90141ef3f3d0b000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000009be6769ef4fc4ccda30e0e39052070d90d3f0bfe000000000000000000000000000000000000000000000000000000e8d4a51000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002c0000000000000000000000000000000000000000000000000000179fc8e808080"
            )
        else:
            print("None selected")
            return

        try:
            sig = self._device.eth_sign(
                tx,
                keypath=[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0],
                chain_id=chain_id,
            )
            print("Signature: {}".format(sig.hex()))
        except UserAbortException:
            eprint("Aborted by user")

    def _sign_eth_message(self) -> None:
        msg = input(r"Message to sign (\n = newline): ")
        if msg.startswith("0x"):
            msg_bytes = binascii.unhexlify(msg[2:])
        else:
            msg_bytes = msg.replace(r"\n", "\n").encode("utf-8")
        msg_hex = binascii.hexlify(msg_bytes).decode("utf-8")
        print(f"signing\nbytes: {repr(msg_bytes)}\nhex: 0x{msg_hex}")
        sig = self._device.eth_sign_msg(
            msg=msg_bytes,
            keypath=[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0],
        )

        print("Signature: 0x{}".format(binascii.hexlify(sig).decode("utf-8")))

    def _cardano(self) -> None:
        def xpubs() -> None:
            xpubs = self._device.cardano_xpubs(
                keypaths=[
                    [1852 + HARDENED, 1815 + HARDENED, HARDENED],
                    [1852 + HARDENED, 1815 + HARDENED, HARDENED + 1],
                ]
            )
            print("m/1852'/1815'/0' xpub: ", xpubs[0].hex())
            print("m/1852'/1815'/1' xpub: ", xpubs[1].hex())

        script_config = bitbox02.cardano.CardanoScriptConfig(
            pkh_skh=bitbox02.cardano.CardanoScriptConfig.PkhSkh(
                keypath_payment=[1852 + HARDENED, 1815 + HARDENED, HARDENED, 0, 0],
                keypath_stake=[1852 + HARDENED, 1815 + HARDENED, HARDENED, 2, 0],
            )
        )

        def get_address(display: bool) -> str:
            return self._device.cardano_address(
                bitbox02.cardano.CardanoAddressRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    display=display,
                    script_config=script_config,
                )
            )

        def address() -> None:
            print("m/1852'/1815'/0'/0/0 address: ", get_address(False))
            get_address(True)

        def sign() -> None:
            response = self._device.cardano_sign_transaction(
                transaction=bitbox02.cardano.CardanoSignTransactionRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    inputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "59864ee73ca5d91098a32b3ce9811bac1996dcbaefa6b6247dcaafb5779c2538"
                            ),
                            prev_out_index=0,
                        )
                    ],
                    outputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address="addr1q9qfllpxg2vu4lq6rnpel4pvpp5xnv3kvvgtxk6k6wp4ff89xrhu8jnu3p33vnctc9eklee5dtykzyag5penc6dcmakqsqqgpt",
                            value=1000000,
                        ),
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address=get_address(False),
                            value=4829501,
                            script_config=script_config,
                        ),
                    ],
                    fee=170499,
                    ttl=41115811,
                    certificates=[],
                    validity_interval_start=41110811,
                )
            )
            print(response)

        def sign_zero_ttl() -> None:
            response = self._device.cardano_sign_transaction(
                transaction=bitbox02.cardano.CardanoSignTransactionRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    inputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "59864ee73ca5d91098a32b3ce9811bac1996dcbaefa6b6247dcaafb5779c2538"
                            ),
                            prev_out_index=0,
                        )
                    ],
                    outputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address="addr1q9qfllpxg2vu4lq6rnpel4pvpp5xnv3kvvgtxk6k6wp4ff89xrhu8jnu3p33vnctc9eklee5dtykzyag5penc6dcmakqsqqgpt",
                            value=1000000,
                        ),
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address=get_address(False),
                            value=4829501,
                            script_config=script_config,
                        ),
                    ],
                    fee=170499,
                    ttl=0,
                    allow_zero_ttl=True,
                    certificates=[],
                    validity_interval_start=41110811,
                )
            )
            print(response)

        def sign_tokens() -> None:
            response = self._device.cardano_sign_transaction(
                transaction=bitbox02.cardano.CardanoSignTransactionRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    inputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "59864ee73ca5d91098a32b3ce9811bac1996dcbaefa6b6247dcaafb5779c2538"
                            ),
                            prev_out_index=0,
                        )
                    ],
                    outputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address="addr1q9qfllpxg2vu4lq6rnpel4pvpp5xnv3kvvgtxk6k6wp4ff89xrhu8jnu3p33vnctc9eklee5dtykzyag5penc6dcmakqsqqgpt",
                            value=1000000,
                            asset_groups=[
                                # Asset policy ids and asset names from: https://github.com/cardano-foundation/CIPs/blob/a2ef32d8a2b485fed7f6ffde2781dd58869ff511/CIP-0014/README.md#test-vectors
                                bitbox02.cardano.CardanoSignTransactionRequest.AssetGroup(
                                    policy_id=bytes.fromhex(
                                        "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209"
                                    ),
                                    tokens=[
                                        # asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3
                                        bitbox02.cardano.CardanoSignTransactionRequest.AssetGroup.Token(
                                            asset_name=bytes.fromhex("504154415445"),
                                            value=1,
                                        ),
                                        # asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f
                                        bitbox02.cardano.CardanoSignTransactionRequest.AssetGroup.Token(
                                            asset_name=bytes.fromhex(
                                                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373"
                                            ),
                                            value=3,
                                        ),
                                    ],
                                ),
                            ],
                        ),
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address=get_address(False),
                            value=4829501,
                            script_config=script_config,
                        ),
                    ],
                    fee=170499,
                    certificates=[],
                )
            )
            print(response)

        def delegate() -> None:
            response = self._device.cardano_sign_transaction(
                transaction=bitbox02.cardano.CardanoSignTransactionRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    inputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "64c39d60f9d6b4f883d05ae3585d0621d0febc06ad0ea3403bdc00bc23671615"
                            ),
                            prev_out_index=1,
                        ),
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "b7b2333e72f2670ab82051f426cc84000431975a34e71d5edf70ea6c0ddc9bf8"
                            ),
                            prev_out_index=0,
                        ),
                    ],
                    outputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address=get_address(False),
                            value=2741512,
                            script_config=script_config,
                        )
                    ],
                    fee=191681,
                    ttl=41539125,
                    certificates=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Certificate(
                            stake_registration=bitbox02.common.Keypath(
                                keypath=[2147485500, 2147485463, 2147483648, 2, 0]
                            )
                        ),
                        bitbox02.cardano.CardanoSignTransactionRequest.Certificate(
                            stake_delegation=bitbox02.cardano.CardanoSignTransactionRequest.Certificate.StakeDelegation(
                                keypath=[2147485500, 2147485463, 2147483648, 2, 0],
                                pool_keyhash=bytes.fromhex(
                                    "abababababababababababababababababababababababababababab"
                                ),
                            )
                        ),
                    ],
                )
            )
            print(response)

        def withdraw() -> None:
            response = self._device.cardano_sign_transaction(
                transaction=bitbox02.cardano.CardanoSignTransactionRequest(
                    network=bitbox02.cardano.CardanoMainnet,
                    inputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Input(
                            keypath=[2147485500, 2147485463, 2147483648, 0, 0],
                            prev_out_hash=bytes.fromhex(
                                "b7b2333e72f2670ab82051f426cc84000431975a34e71d5edf70ea6c0ddc9bf8"
                            ),
                            prev_out_index=0,
                        )
                    ],
                    outputs=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Output(
                            encoded_address=get_address(False),
                            value=4817591,
                            script_config=script_config,
                        )
                    ],
                    fee=175157,
                    ttl=41788708,
                    withdrawals=[
                        bitbox02.cardano.CardanoSignTransactionRequest.Withdrawal(
                            keypath=[2147485500, 2147485463, 2147483648, 2, 0],
                            value=1234567,
                        )
                    ],
                )
            )
            print([(w.public_key.hex(), w.signature.hex()) for w in response.shelley_witnesses])

        choices = (
            ("Retrieve account xpubs", xpubs),
            ("Retrieve a Shelley address", address),
            ("Sign a transaction", sign),
            ("Sign a transaction with TTL=0", sign_zero_ttl),
            ("Sign a transaction sending tokens", sign_tokens),
            ("Delegate staking to a pool", delegate),
            ("Withdraw staking rewards", withdraw),
        )
        choice = ask_user(choices)
        if callable(choice):
            try:
                choice()
            except UserAbortException:
                eprint("Aborted by user")

    def _reset_device(self) -> None:
        if self._device.reset():
            print("Device RESET")
            self._stop = True
        else:
            print("Device NOT reset")

    def _menu_notinit(self) -> None:
        """TODO: Document

        Returns:
            bool: If the user should be prompted again
        """
        choices = (
            ("Set up a new wallet", self._setup_workflow),
            ("Restore from backup", self._restore_backup_workflow),
            ("Restore from mnemonic", self._restore_from_mnemonic),
            ("List device info", self._list_device_info),
            ("Reboot into bootloader", self._reboot),
            ("Check if SD card inserted", self._check_sd_presence),
        )
        choice = ask_user(choices)
        if isinstance(choice, bool):
            self._stop = True
            return
        if choice is None:
            return
        choice()

    def _menu_init(self) -> None:
        """Print the menu"""
        choices = (
            ("List device info", self._list_device_info),
            ("Change device name", self._change_name_workflow),
            ("Get root fingerprint", self._get_root_fingerprint),
            ("Retrieve zpub of first account", self._display_zpub),
            ("Retrieve a BTC address", self._btc_address),
            ("Retrieve a BTC Multisig address", self._btc_multisig_address),
            ("Sign a BTC tx", self._sign_btc_tx),
            ("Sign a BTC Message", self._sign_btc_message),
            ("List backups", self._print_backups),
            ("Check backup", self._check_backup),
            ("Show mnemonic", self._show_mnemnoic_seed),
            ("Create backup", self._create_backup),
            ("Reboot into bootloader", self._reboot),
            ("Check if SD card inserted", self._check_sd_presence),
            ("Insert SD card", self._insert_sdcard),
            ("Remove SD card", self._remove_sdcard),
            ("Toggle BIP39 Mnemonic Passphrase", self._toggle_mnemonic_passphrase),
            ("Retrieve Ethereum xpub", self._get_eth_xpub),
            ("Retrieve Ethereum address", self._display_eth_address),
            (
                "Retrieve ERC20 address with long token name",
                lambda: self._display_eth_address(
                    contract_address=b"\xba\x11\xd0\x0c\x5f\x74\x25\x5f\x56\xa5\xe3\x66\xf4\xf7\x7f\x5a\x18\x6d\x7f\x55"
                ),
            ),
            ("Sign Ethereum tx", self._sign_eth_tx),
            ("Sign Ethereum Message", self._sign_eth_message),
            ("Cardano", self._cardano),
            ("Show Electrum wallet encryption key", self._get_electrum_encryption_key),
            ("Reset Device", self._reset_device),
        )
        choice = ask_user(choices)
        if isinstance(choice, bool):
            self._stop = True
            return
        if choice is None:
            return
        choice()

    def _menu(self) -> None:
        if not self._device.device_info()["initialized"]:
            self._menu_notinit()
            return
        self._menu_init()

    def run(self) -> int:
        """Entry point for program"""
        if self._debug:
            self._device.debug = True

        while not self._stop:
            self._menu()
        self._device.close()
        return 0


class SendMessageBootloader:
    """Simple test application for bootloader"""

    def __init__(self, device: bitbox02.Bootloader):
        self._device = device
        self._stop = False

    def _boot(self) -> None:
        self._device.reboot()
        self._stop = True

    def _get_versions(self) -> None:
        if self._device.erased():
            print("No firmware on device")
        else:
            version = self._device.versions()
            print(f"Firmware version: {version[0]}, Pubkeys version: {version[1]}")

    def _erase(self) -> None:
        self._device.erase()

    def _show_fw_hash(self) -> None:
        self._device.set_show_firmware_hash(True)

    def _dont_show_fw_hash(self) -> None:
        self._device.set_show_firmware_hash(False)

    def _get_hashes(self) -> None:
        firmware_hash, sigkeys_hash = self._device.get_hashes()
        print("Firmware hash:")
        print("\n".join(textwrap.wrap(firmware_hash.hex(), 16)))
        if input("Display on device? y/[n]: ") == "y":
            self._device.get_hashes(display_firmware_hash=True)
        print("Signature keys hash:")
        print("\n".join(textwrap.wrap(sigkeys_hash.hex(), 16)))
        if input("Display on device? y/[n]: ") == "y":
            self._device.get_hashes(display_signing_keydata_hash=True)

    def _menu(self) -> None:
        choices = (
            ("Boot", self._boot),
            ("Print versions", self._get_versions),
            ("Erase firmware", self._erase),
            ("Show firmware hash at startup", self._show_fw_hash),
            ("Don't show firmware hash at startup", self._dont_show_fw_hash),
            ("Get firmware & sigkey hashes", self._get_hashes),
            ("Rotate screen", self._device.screen_rotate),
        )
        choice = ask_user(choices)
        if isinstance(choice, bool):
            self._stop = True
            return
        if choice is None:
            return
        choice()

    def run(self) -> int:
        while not self._stop:
            self._menu()
        self._device.close()
        return 0


class U2FApp:
    """App"""

    APPID = "http://example.com"

    def __init__(self, device: u2f.bitbox02.BitBox02U2F, debug: bool):
        self._device = device
        self._stop = False
        self._dev_keyhandle: bytes = b"0" * 64
        self._dev_pubkey: bytes = b"0" * 64
        if debug:
            self._device.debug = True

    def _wink(self) -> None:
        print("Wink")
        self._device.u2fhid_wink()

    def _ping(self) -> None:
        ans = input("Message: ")
        res = self._device.u2fhid_ping(ans.encode("utf-8"))
        print(res.decode("utf-8"))

    def _register(self) -> None:
        try:
            res = self._device.u2f_register(self.APPID)
            if res is not None:
                (self._dev_pubkey, self._dev_keyhandle) = res
        except u2f.ConditionsNotSatisfiedException:
            print("Not registered")

    def _bogus(self) -> None:
        ans = input("Vendor [chromium, firefox]: ")
        try:
            self._device.u2f_register_bogus(ans)
        except ValueError as err:
            print("Invalid vendor, try again: {}".format(err))
        except u2f.ConditionsNotSatisfiedException:
            print("User not present")

    def _authenticate(self) -> None:
        if self._dev_keyhandle == b"0" * 64:
            print("Not yet registered, authenticating anyway...")
        try:
            self._device.u2f_authenticate(self.APPID, self._dev_keyhandle, self._dev_pubkey)
            print("User present")
        except u2f.ConditionsNotSatisfiedException:
            print("User not present")
        except u2f.WrongDataException:
            print("Keyhandle not for this key")

    def _menu(self) -> None:
        """Menu"""
        print("What would you like to do?")
        choices = (
            ("Wink", self._wink),
            ("Ping", self._ping),
            ("Register", self._register),
            ("Register with bogus AppId", self._bogus),
            ("Authenticate", self._authenticate),
        )
        choice = ask_user(choices)
        if isinstance(choice, bool):
            self._stop = True
            return
        if choice is None:
            return
        choice()

    def run(self) -> int:
        """Main function"""
        while not self._stop:
            self._menu()
        self._device.close()
        return 0


def connect_to_usb_bitbox(debug: bool, use_cache: bool) -> int:
    """
    Connects and runs the main menu on a BitBox02 connected
    over USB.
    """
    try:
        bitbox = devices.get_any_bitbox02()
    except devices.TooManyFoundException:
        print("Multiple bitboxes detected. Only one supported")
        return 1
    except devices.NoneFoundException:
        try:
            bootloader = devices.get_any_bitbox02_bootloader()
        except devices.TooManyFoundException:
            print("Multiple bitbox bootloaders detected. Only one supported")
            return 1
        except devices.NoneFoundException:
            print("Neither bitbox nor bootloader found.")
            return 1
        else:
            hid_device = hid.device()
            hid_device.open_path(bootloader["path"])
            bootloader_connection = bitbox02.Bootloader(u2fhid.U2FHid(hid_device), bootloader)
            boot_app = SendMessageBootloader(bootloader_connection)
            return boot_app.run()
    else:

        def show_pairing(code: str, device_response: Callable[[], bool]) -> bool:
            print("Please compare and confirm the pairing code on your BitBox02:")
            print(code)
            if not device_response():
                return False
            return input("Accept pairing? [y]/n: ").strip() != "n"

        class NoiseConfig(util.NoiseConfigUserCache):
            """NoiseConfig extends NoiseConfigUserCache"""

            def __init__(self) -> None:
                super().__init__("shift/send_message")

            def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
                return show_pairing(code, device_response)

            def attestation_check(self, result: bool) -> None:
                if result:
                    print("Device attestation PASSED")
                else:
                    print("Device attestation FAILED")

        class NoiseConfigNoCache(bitbox_api_protocol.BitBoxNoiseConfig):
            """NoiseConfig extends BitBoxNoiseConfig"""

            def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
                return show_pairing(code, device_response)

            def attestation_check(self, result: bool) -> None:
                if result:
                    print("Device attestation PASSED")
                else:
                    print("Device attestation FAILED")

        if use_cache:
            config: bitbox_api_protocol.BitBoxNoiseConfig = NoiseConfig()
        else:
            config = NoiseConfigNoCache()

        hid_device = hid.device()
        hid_device.open_path(bitbox["path"])
        bitbox_connection = bitbox02.BitBox02(
            transport=u2fhid.U2FHid(hid_device), device_info=bitbox, noise_config=config
        )
        try:
            bitbox_connection.check_min_version()
        except FirmwareVersionOutdatedException as exc:
            print("WARNING: ", exc)

        if debug:
            print("Device Info:")
            pprint.pprint(bitbox)
        return SendMessage(bitbox_connection, debug).run()


def main() -> int:
    """Main function"""
    parser = argparse.ArgumentParser(description="Tool for communicating with bitbox device")
    parser.add_argument("--debug", action="store_true", help="Print messages sent and received")
    parser.add_argument("--u2f", action="store_true", help="Use u2f menu instead")
    parser.add_argument(
        "--no-cache", action="store_true", help="Don't use cached or store noise keys"
    )
    args = parser.parse_args()

    if args.u2f:
        try:
            u2fbitbox = u2f.bitbox02.get_bitbox02_u2f_device()
        except devices.TooManyFoundException:
            print("Multiple bitboxes detected. Only one supported")
        except devices.NoneFoundException:
            print("No bitboxes detected")
        else:
            hid_device = hid.device()
            hid_device.open_path(u2fbitbox["path"])
            u2fdevice = u2f.bitbox02.BitBox02U2F(hid_device)
            u2fapp = U2FApp(u2fdevice, args.debug)
            return u2fapp.run()
        return 1

    return connect_to_usb_bitbox(args.debug, not args.no_cache)


if __name__ == "__main__":
    sys.exit(main())
