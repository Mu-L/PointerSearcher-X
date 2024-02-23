from ctypes import (
    cdll,
    POINTER,
    Structure,
    c_void_p,
    c_char_p,
    c_bool,
    c_size_t,
    c_int,
    c_uint8,
)


class Param(Structure):
    _fields_ = [
        ("addr", c_size_t),
        ("depth", c_size_t),
        ("node", c_size_t),
        ("left", c_size_t),
        ("right", c_size_t),
    ]


class PointerScanTool:

    LIBRARY_FUNCS = {
        # Scan Pointer Chain
        "ptrs_init": (POINTER(c_void_p),),
        "ptrs_free": (None, POINTER(c_void_p)),
        "ptrs_create_pointer_map": (
            c_int,
            POINTER(c_void_p),
            c_int,
            c_bool,
            c_char_p,
            c_char_p,
        ),
        "ptrs_load_pointer_map": (c_int, POINTER(c_void_p), c_char_p, c_char_p),
        "ptrs_scan_pointer_chain": (c_int, POINTER(c_void_p), Param, c_char_p),
        # Verify Pointer Chain
        "ptrv_init": (POINTER(c_void_p),),
        "ptrv_free": (None, POINTER(c_void_p)),
        "ptrv_set_proc": (c_int, POINTER(c_void_p), c_int),
        "ptrv_invalid_filter": (c_int, POINTER(c_void_p), c_char_p),
        "ptrv_value_filter": (
            c_int,
            POINTER(c_void_p),
            c_char_p,
            POINTER(c_uint8),
            c_size_t,
        ),
        # Other Tools
        "compare_two_file": (c_int, c_char_p, c_char_p, c_char_p),
        # Error
        "get_last_error": (c_char_p,),
    }

    def _init_lib_functions(self):
        for k, v in self.LIBRARY_FUNCS.items():
            f = getattr(self._lib, k)
            f.restype = v[0]
            f.argtypes = v[1:]

    def __init__(self, libpath="libptrsx.dylib"):
        self._lib = cdll.LoadLibrary(libpath)
        self._init_lib_functions()
        self._ptrs = self._lib.ptrs_init()
        self._ptrv = self._lib.ptrv_init()

    def _get_last_error(self) -> str:
        return self._lib.get_last_error().decode()

    def free(self):
        return self._lib.ptrs_free(self._ptrs)

    def create_pointer_map(self, pid, align, info_path, bin_path):
        ret = self._lib.ptrs_create_pointer_map(
            self._ptrs,
            c_int(pid),
            c_bool(align),
            c_char_p(info_path.encode()),
            c_char_p(bin_path.encode()),
        )
        if ret < 0:
            err = self._get_last_error()
            raise Exception(err)

    def load_pointer_map(self, info_path, bin_path):
        ret = self._lib.ptrs_load_pointer_map(
            self._ptrs, c_char_p(info_path.encode()), c_char_p(bin_path.encode())
        )
        if ret < 0:
            err = self._get_last_error()
            raise Exception(err)

    def scan_pointer_chain(self, modules, param, file_path):
        ret = self._lib.ptrs_scan_pointer_chain(
            self._ptrs, modules, param, c_char_p(file_path.encode())
        )
        if ret < 0:
            err = self._get_last_error()
            raise Exception(err)
