"""
`vibeslayer` Python Native SDK (`v2.0.0-alpha.1`) — `ctypes` bindings backed directly
by compiled C shared library `bin/libvibeslayer.so` via `ctypes`.

Supports 64-bit streaming VSPK3 v2 (`unseal_action_vspk3_v2_file`, constant ~132 KiB RAM,
no 2 GiB cap) as well as legacy VSPK3 v1 / VSPK2, with unified opaque `VaultAuthError`.
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class VaultAuthError(RuntimeError):
    """Unified opaque authentication error (never leaks commitment vs MAC vs padding)."""


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

_LIB.vs_unseal_vspk3_v2_chacha20_file.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.vs_unseal_vspk3_v2_chacha20_file.restype = ctypes.c_int64


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
            raise VaultAuthError("VAULT_AUTH_FAILED")
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
                raise VaultAuthError("VAULT_AUTH_FAILED")
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
            raise VaultAuthError("VAULT_AUTH_FAILED")

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
                raise VaultAuthError("VAULT_AUTH_FAILED")
            return out_buf.raw[:rc]
        finally:
            ctypes.memset(out_buf, 0, len(out_buf))

    def unseal_action_vspk3_v2_file(
        self,
        *,
        action: str,
        params: dict[str, Any],
        asset_id: str,
        in_path: str | Path,
        out_path: str | Path,
    ) -> int:
        """Stream-unseal a 64-bit VSPK3 v2 ChaCha20-Poly1305 vault file in constant ~132 KiB RAM."""
        rule = self.validate_params(action, params)
        mk_buf = (ctypes.c_uint8 * 32).from_buffer(self._master_key)
        plain_bytes = _LIB.vs_unseal_vspk3_v2_chacha20_file(
            mk_buf,
            rule.domain.encode("utf-8"),
            asset_id.encode("utf-8"),
            rule.context.encode("utf-8"),
            str(in_path).encode("utf-8"),
            str(out_path).encode("utf-8"),
        )
        if plain_bytes < 0:
            raise VaultAuthError("VAULT_AUTH_FAILED")
        return int(plain_bytes)
