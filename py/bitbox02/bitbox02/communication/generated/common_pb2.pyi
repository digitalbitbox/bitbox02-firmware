"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class PubResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PUB_FIELD_NUMBER: builtins.int
    pub: typing.Text
    def __init__(self,
        *,
        pub: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["pub",b"pub"]) -> None: ...
global___PubResponse = PubResponse

class RootFingerprintRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    def __init__(self,
        ) -> None: ...
global___RootFingerprintRequest = RootFingerprintRequest

class RootFingerprintResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    FINGERPRINT_FIELD_NUMBER: builtins.int
    fingerprint: builtins.bytes
    def __init__(self,
        *,
        fingerprint: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["fingerprint",b"fingerprint"]) -> None: ...
global___RootFingerprintResponse = RootFingerprintResponse

class XPub(google.protobuf.message.Message):
    """See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.
    version field dropped as it will set dynamically based on the context (xpub, ypub, etc.).
    """
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    DEPTH_FIELD_NUMBER: builtins.int
    PARENT_FINGERPRINT_FIELD_NUMBER: builtins.int
    CHILD_NUM_FIELD_NUMBER: builtins.int
    CHAIN_CODE_FIELD_NUMBER: builtins.int
    PUBLIC_KEY_FIELD_NUMBER: builtins.int
    depth: builtins.bytes
    parent_fingerprint: builtins.bytes
    child_num: builtins.int
    chain_code: builtins.bytes
    public_key: builtins.bytes
    def __init__(self,
        *,
        depth: builtins.bytes = ...,
        parent_fingerprint: builtins.bytes = ...,
        child_num: builtins.int = ...,
        chain_code: builtins.bytes = ...,
        public_key: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["chain_code",b"chain_code","child_num",b"child_num","depth",b"depth","parent_fingerprint",b"parent_fingerprint","public_key",b"public_key"]) -> None: ...
global___XPub = XPub

class Keypath(google.protobuf.message.Message):
    """This message exists for use in oneof or repeated fields, where one can't inline `repeated uint32` due to protobuf rules."""
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    KEYPATH_FIELD_NUMBER: builtins.int
    @property
    def keypath(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.int]: ...
    def __init__(self,
        *,
        keypath: typing.Optional[typing.Iterable[builtins.int]] = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["keypath",b"keypath"]) -> None: ...
global___Keypath = Keypath

class KeyOriginInfo(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    ROOT_FINGERPRINT_FIELD_NUMBER: builtins.int
    KEYPATH_FIELD_NUMBER: builtins.int
    XPUB_FIELD_NUMBER: builtins.int
    root_fingerprint: builtins.bytes
    @property
    def keypath(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.int]: ...
    @property
    def xpub(self) -> global___XPub: ...
    def __init__(self,
        *,
        root_fingerprint: builtins.bytes = ...,
        keypath: typing.Optional[typing.Iterable[builtins.int]] = ...,
        xpub: typing.Optional[global___XPub] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["xpub",b"xpub"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["keypath",b"keypath","root_fingerprint",b"root_fingerprint","xpub",b"xpub"]) -> None: ...
global___KeyOriginInfo = KeyOriginInfo
