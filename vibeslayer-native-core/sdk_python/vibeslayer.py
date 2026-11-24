"""
`vibeslayer` Python Native SDK (`v1.0.0-beta.3`) — Zero Node.js, backed directly
by compiled C shared library `bin/libvibeslayer.so` via `ctypes`.
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_BIN_DIR = Path(__file__).resolve().parent.parent / "bin"
if sys.platform == "win32":
    _LIB_NAME = "vibeslayer.dll"
elif sys.platform == "darwin":
    _LIB_NAME = "libvibeslayer.dylib"
else:
    _LIB_NAME = "libvibeslayer.so"
_SO_PATH = _BIN_DIR / _LIB_NAME
if not _SO_PATH.is_file():
    raise FileNotFoundError(
        f"Compiled native library not found at {_SO_PATH}. "
        "Build it first with: make -C vibeslayer-native-core all"
    )
_LIB = ctypes.CDLL(str(_SO_PATH))
_LIB.vs_harden_process.argtypes = []
_LIB.vs_harden_process.restype = ctypes.c_int

_LIB.vs_unseal_vspk2.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
_LIB.vs_unseal_vspk2.restype = ctypes.c_int

_LIB.vs_unseal_vspk2_for_asset.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
_LIB.vs_unseal_vspk2_for_asset.restype = ctypes.c_int

_LIB.vs_unseal_vspk3.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
_LIB.vs_unseal_vspk3.restype = ctypes.c_int


@dataclass(frozen=True)
class ParamSpec:
    kind: str  # "int" | "str" | "bool" | "enum"
    min_val: int | float | None = None
    max_val: int | float | None = None
    values: list[Any] = field(default_factory=list)


@dataclass(frozen=True)
class ActionRule:
    domain: str
    context: str
    params: dict[str, ParamSpec] = field(default_factory=dict)


class Policy:
    def __init__(self, *, master_key_hex: str, actions: dict[str, ActionRule], enabled: bool = False) -> None:
        key_bytes = bytes.fromhex(master_key_hex)
        if len(key_bytes) != 32:
            raise ValueError("INVALID_POLICY: master_key_hex must be 32 bytes")
        self.enabled = enabled
        self._master_key = bytearray(key_bytes)
        self.actions = dict(actions)

    def zeroize(self) -> None:
        for i in range(len(self._master_key)):
            self._master_key[i] = 0

    def validate_params(self, action: str, supplied: dict[str, Any]) -> ActionRule:
        if not self.enabled:
            raise PermissionError("POLICY_DISABLED")
        if action not in self.actions:
            raise KeyError(f"UNKNOWN_ACTION:{action}")
        rule = self.actions[action]
        for k in supplied:
            if k not in rule.params:
                raise ValueError(f"UNKNOWN_PARAM:{k}")
        for name, spec in rule.params.items():
            if name not in supplied:
                raise ValueError(f"MISSING_PARAM:{name}")
            val = supplied[name]
            if spec.kind == "int":
                if not isinstance(val, int) or isinstance(val, bool):
                    raise TypeError(f"BAD_PARAM_TYPE:{name}")
                if (spec.min_val is not None and val < spec.min_val) or (
                    spec.max_val is not None and val > spec.max_val
                ):
                    raise ValueError(f"PARAM_OUT_OF_RANGE:{name}")
            elif spec.kind == "str":
                if not isinstance(val, str):
                    raise TypeError(f"BAD_PARAM_TYPE:{name}")
            elif spec.kind == "bool":
                if not isinstance(val, bool):
                    raise TypeError(f"BAD_PARAM_TYPE:{name}")
            elif spec.kind == "enum":
                if val not in spec.values:
                    raise ValueError(f"PARAM_OUT_OF_RANGE:{name}")
        return rule

    def unseal_action_vspk(
        self,
        *,
        action: str,
        params: dict[str, Any],
        asset_id: str,
        vspk_bytes: bytes,
    ) -> bytes:
        rule = self.validate_params(action, params)
        if len(vspk_bytes) < 40 or vspk_bytes[:5] != b"VSPK2":
            raise ValueError("BAD_VSPK2_HEADER")
        dlen = int.from_bytes(vspk_bytes[6:8], "little")
        alen = int.from_bytes(vspk_bytes[8:10], "little")
        if dlen > 128 or alen > 128 or 40 + dlen + alen > len(vspk_bytes):
            raise ValueError("TRUNCATED_VSPK2")
        hdr_asset_id = vspk_bytes[40 + dlen : 40 + dlen + alen].decode("utf-8", errors="strict")
        if hdr_asset_id != asset_id:
            raise PermissionError("ASSET_ID_MISMATCH")

        mk_buf = (ctypes.c_uint8 * 32).from_buffer(self._master_key)
        out_buf = ctypes.create_string_buffer(len(vspk_bytes))
        try:
            rc = _LIB.vs_unseal_vspk2_for_asset(
                mk_buf,
                rule.domain.encode("utf-8"),
                asset_id.encode("utf-8"),
                rule.context.encode("utf-8"),
                vspk_bytes,
                len(vspk_bytes),
                out_buf,
                len(vspk_bytes),
            )
            if rc < 0:
                raise RuntimeError(f"AEAD_OR_POLICY_UNSEAL_FAILED:{rc}")
            return out_buf.raw[:rc]
        finally:
            ctypes.memset(out_buf, 0, len(out_buf))

    def unseal_action_vspk3(
        self,
        *,
        action: str,
        params: dict[str, Any],
        asset_id: str,
        vspk_bytes: bytes,
    ) -> bytes:
        rule = self.validate_params(action, params)
        if len(vspk_bytes) < 92 + 1024:
            raise ValueError("TRUNCATED_VSPK3")

        mk_buf = (ctypes.c_uint8 * 32).from_buffer(self._master_key)
        out_buf = ctypes.create_string_buffer(len(vspk_bytes))
        try:
            rc = _LIB.vs_unseal_vspk3(
                mk_buf,
                rule.domain.encode("utf-8"),
                asset_id.encode("utf-8"),
                rule.context.encode("utf-8"),
                vspk_bytes,
                len(vspk_bytes),
                out_buf,
                len(vspk_bytes),
            )
            if rc < 0:
                raise RuntimeError(f"VSPK3_UNSEAL_FAILED:{rc}")
            return out_buf.raw[:rc]
        finally:
            ctypes.memset(out_buf, 0, len(out_buf))
