"""ctypes binding to libmaze, the C core engine (core/).

Build the library first: make -C core
The path can be overridden with MAZE_LIB.

Only this module talks to C. It mirrors the public structs of core/include/maze.h
and checks their sizes against the library at load time, so a layout mismatch
fails loudly instead of corrupting memory.
"""

import base64
import ctypes
import os
import re
import threading
from pathlib import Path

from .config import PROJECT_ROOT, ConfigError

LIB_ENV = "MAZE_LIB"
DEFAULT_LIB_PATH = PROJECT_ROOT / "core" / "build" / "libmaze.so"

HASH_BYTES = 32
SALT_BYTES = 16
MAX_LAYERS = 16
MAX_DECOYS_PER_LAYER = 64
MAX_PASSWORD_BYTES = 4096
KDF_OPS_MIN, KDF_OPS_MAX = 1, 10
KDF_MEM_KIB_MIN, KDF_MEM_KIB_MAX = 8, 256 * 1024

# enum maze_outcome
WRONG, DECOY_FOUND, REAL_SUCCESS, EXIT_GRANTED, EXIT_DENIED, EXIT_UNAVAILABLE = range(6)

_OK = 0
_HashBytes = ctypes.c_uint8 * HASH_BYTES


class CoreError(ConfigError):
    """libmaze is missing, does not match this binding, or failed."""


class Kdf(ctypes.Structure):
    _fields_ = [("salt", ctypes.c_uint8 * SALT_BYTES),
                ("opslimit", ctypes.c_uint32),
                ("memlimit", ctypes.c_size_t)]


class Session(ctypes.Structure):
    _fields_ = [("layer", ctypes.c_uint32),
                ("cleared_mask", ctypes.c_uint32),
                ("cleared", _HashBytes * (MAX_LAYERS + 1))]


class Result(ctypes.Structure):
    _fields_ = [("outcome", ctypes.c_int),
                ("layer_before", ctypes.c_uint32),
                ("layer_after", ctypes.c_uint32),
                ("decoy_layer", ctypes.c_uint32),
                ("real_mask", ctypes.c_uint32)]


_lib = None
_lib_lock = threading.Lock()


def _declare(lib):
    p, u32, size = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_size_t
    kdf_p, session_p, result_p = (ctypes.POINTER(Kdf), ctypes.POINTER(Session),
                                  ctypes.POINTER(Result))
    signatures = {
        "maze_version": (ctypes.c_char_p, []),
        "maze_init": (ctypes.c_int, []),
        "maze_kdf_hash": (ctypes.c_int, [kdf_p, ctypes.c_char_p, size, _HashBytes]),
        "maze_engine_new": (p, [u32, kdf_p, kdf_p, _HashBytes]),
        "maze_engine_free": (None, [p]),
        "maze_engine_add_decoy": (ctypes.c_int, [p, u32, _HashBytes]),
        "maze_engine_set_route": (ctypes.c_int, [p, u32, u32, u32]),
        "maze_session_init": (None, [session_p]),
        "maze_login": (ctypes.c_int, [p, session_p, ctypes.c_char_p, size, result_p]),
        "maze_exit": (ctypes.c_int, [p, session_p, ctypes.POINTER(ctypes.c_char_p),
                                     ctypes.POINTER(size), size, result_p]),
        "maze_sizeof_kdf": (size, []),
        "maze_sizeof_session": (size, []),
        "maze_sizeof_result": (size, []),
    }
    for name, (restype, argtypes) in signatures.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = argtypes


def lib():
    """Load libmaze once and check that it matches this binding."""
    global _lib
    with _lib_lock:
        if _lib is not None:
            return _lib
        path = Path(os.environ.get(LIB_ENV) or DEFAULT_LIB_PATH)
        try:
            loaded = ctypes.CDLL(str(path))
            _declare(loaded)
        except (OSError, AttributeError) as exc:
            raise CoreError(f"Cannot load libmaze from {path}: {exc}. "
                            "Build it with: make -C core") from exc
        for name, struct in (("kdf", Kdf), ("session", Session), ("result", Result)):
            if getattr(loaded, f"maze_sizeof_{name}")() != ctypes.sizeof(struct):
                raise CoreError(f"libmaze at {path} does not match this version of Maze "
                                f"(struct {name} size differs). Rebuild it: make -C core")
        if loaded.maze_init() != _OK:
            raise CoreError("libmaze failed to initialise libsodium")
        _lib = loaded
        return _lib


def encode_password(password: str) -> bytes:
    """UTF-8 bytes of a guess, cut to the longest input the engine accepts."""
    return password.encode("utf-8", "surrogatepass")[:MAX_PASSWORD_BYTES]


# --- KDF parameters ----------------------------------------------------------

def make_kdf(salt: bytes, opslimit: int, memlimit_kib: int) -> Kdf:
    if len(salt) != SALT_BYTES:
        raise ConfigError(f"salt must be {SALT_BYTES} bytes")
    if not KDF_OPS_MIN <= opslimit <= KDF_OPS_MAX:
        raise ConfigError(f"opslimit must be {KDF_OPS_MIN}..{KDF_OPS_MAX}")
    if not KDF_MEM_KIB_MIN <= memlimit_kib <= KDF_MEM_KIB_MAX:
        raise ConfigError(f"memlimit_kib must be {KDF_MEM_KIB_MIN}..{KDF_MEM_KIB_MAX}")
    kdf = Kdf()
    ctypes.memmove(kdf.salt, salt, SALT_BYTES)
    kdf.opslimit = opslimit
    kdf.memlimit = memlimit_kib * 1024
    return kdf


def random_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def hash_password(kdf: Kdf, password: str) -> bytes:
    data = encode_password(password)
    out = _HashBytes()
    if lib().maze_kdf_hash(ctypes.byref(kdf), data, len(data), out) != _OK:
        raise CoreError("hashing failed")
    return bytes(out)


# --- PHC strings ($argon2id$v=19$m=...,t=...,p=1$salt$hash) -------------------

_PHC = re.compile(r"\$argon2id\$v=19\$m=(\d{1,7}),t=(\d{1,2}),p=1\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)")


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def b64decode(text: str, length: int, what: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        raise ConfigError(f"{what} must be base64 text")
    try:
        data = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except ValueError as exc:
        raise ConfigError(f"{what} is not valid base64") from exc
    if len(data) != length:
        raise ConfigError(f"{what} must decode to {length} bytes")
    return data


def encode_phc(kdf: Kdf, digest: bytes) -> str:
    return (f"$argon2id$v=19$m={kdf.memlimit // 1024},t={kdf.opslimit},p=1$"
            f"{b64encode(bytes(kdf.salt))}${b64encode(digest)}")


def parse_phc(text: str):
    """Return (Kdf, hash bytes) from a PHC string made by encode_phc."""
    match = _PHC.fullmatch(text.strip()) if isinstance(text, str) else None
    if not match:
        raise ConfigError("not an Argon2id hash in the form "
                          "$argon2id$v=19$m=<KiB>,t=<passes>,p=1$<salt>$<hash>")
    salt = b64decode(match.group(3), SALT_BYTES, "hash salt")
    digest = b64decode(match.group(4), HASH_BYTES, "hash value")
    return make_kdf(salt, int(match.group(2)), int(match.group(1))), digest


# --- engine ------------------------------------------------------------------

def new_session() -> Session:
    session = Session()
    lib().maze_session_init(ctypes.byref(session))
    return session


class Engine:
    """Owns one maze_engine. Immutable after construction; safe to share."""

    def __init__(self, layer_count: int, decoy_kdf: Kdf, real_kdf: Kdf, real_hash: bytes,
                 decoys: dict, routes: dict):
        core = lib()
        self.layer_count = layer_count
        self._handle = core.maze_engine_new(layer_count, ctypes.byref(decoy_kdf),
                                            ctypes.byref(real_kdf),
                                            _HashBytes.from_buffer_copy(real_hash))
        if not self._handle:
            raise CoreError("libmaze rejected the engine settings")
        try:
            for layer, hashes in decoys.items():
                for digest in hashes:
                    if core.maze_engine_add_decoy(self._handle, layer,
                                                  _HashBytes.from_buffer_copy(digest)) != _OK:
                        raise CoreError(f"libmaze rejected a decoy of layer {layer}")
            for layer, (on_match, on_wrong) in routes.items():
                if core.maze_engine_set_route(self._handle, layer, on_match, on_wrong) != _OK:
                    raise CoreError(f"libmaze rejected the route of layer {layer}")
        except CoreError:
            self.close()
            raise

    def close(self):
        if getattr(self, "_handle", None):
            lib().maze_engine_free(self._handle)
            self._handle = None

    __del__ = close

    def login(self, session: Session, password: str) -> Result:
        data = encode_password(password)
        result = Result()
        if lib().maze_login(self._handle, ctypes.byref(session), data, len(data),
                            ctypes.byref(result)) != _OK:
            raise CoreError("maze_login failed")
        return result

    def exit(self, session: Session, answers: list) -> Result:
        """answers[i] is the answer for layer i+1; one per layer below the current one."""
        encoded = [encode_password(a) for a in answers]
        n = len(encoded)
        array = (ctypes.c_char_p * max(n, 1))(*encoded)
        lens = (ctypes.c_size_t * max(n, 1))(*(len(a) for a in encoded))
        result = Result()
        if lib().maze_exit(self._handle, ctypes.byref(session), array, lens, n,
                           ctypes.byref(result)) != _OK:
            raise CoreError("maze_exit failed")
        return result
