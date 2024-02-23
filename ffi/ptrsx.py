from ctypes import (
    cdll,
    POINTER,
    Structure,
    byref,
    sizeof,
    c_void_p,
    c_char_p,
    c_size_t,
    c_int,
    c_ubyte,
)


class Param(Structure):
    _fields_ = [
        # target address
        ("_addr", c_size_t),
        # max depth
        ("_depth", c_size_t),
        # min depth to ignore
        ("_node", c_size_t),
        # reverse offset
        ("_left", c_size_t),
        # forward offset
        ("_right", c_size_t),
    ]

    def addr(self, value: int):
        self._addr = c_size_t(value)
        return self

    def depth(self, value: int):
        self._depth = c_size_t(value)
        return self

    def node(self, value: int):
        self._node = c_size_t(value)
        return self

    def left(self, value: int):
        self._left = c_size_t(value)
        return self

    def right(self, value: int):
        self._right = c_size_t(value)
        return self


class PointerScanTool:

    LIBRARY_FUNCS = {
        # init
        "ptrs_init": (POINTER(c_void_p),),
        "ptrs_free": (None, POINTER(c_void_p)),
        # set pid
        "ptrs_set_proc": (c_int, POINTER(c_void_p), c_int),
        # scan pointer chain
        "ptrs_create_pointer_map": (
            c_int,
            POINTER(c_void_p),
            c_char_p,
            c_char_p,
        ),
        "ptrs_load_pointer_map": (c_int, POINTER(c_void_p), c_char_p, c_char_p),
        "ptrs_scan_pointer_chain": (c_int, POINTER(c_void_p), Param, c_char_p),
        # verify pointer chain
        "ptrs_filter_invalid": (c_int, POINTER(c_void_p), c_char_p, c_char_p),
        "ptrs_filter_value": (
            c_int,
            POINTER(c_void_p),
            c_char_p,
            c_char_p,
            POINTER(c_ubyte),
            c_size_t,
        ),
        "ptrs_filter_addr": (
            c_int,
            POINTER(c_void_p),
            c_char_p,
            c_char_p,
            c_size_t,
        ),
        "ptrs_get_chain_addr": (c_int, POINTER(c_void_p), c_char_p, POINTER(c_size_t)),
        "compare_two_file": (c_int, c_char_p, c_char_p, c_char_p),
        # error
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
        self._ptr = self._lib.ptrs_init()

    def _check_ret(self, ret: c_int):
        if ret < 0:
            err = self._get_last_error()
            raise Exception(err)

    def _get_last_error(self) -> str:
        return self._lib.get_last_error().decode()

    def free(self):
        return self._lib.ptrs_free(self._ptr)

    # Set target process pid
    def set_pid(self, pid: int):
        ret = self._lib.ptrs_set_proc(self._ptr, c_int(pid))
        self._check_ret(ret)

    # Create a pointer map and write pointer information to `info_file` and `bin_file`
    def create_pointer_map(self, info_file: str, bin_file: str):
        ret = self._lib.ptrs_create_pointer_map(
            self._ptr,
            c_char_p(info_file.encode()),
            c_char_p(bin_file.encode()),
        )
        self._check_ret(ret)

    # Load the pointer file created by `self.create_pointer_map`
    def load_pointer_map(self, info_file: str, bin_file: str):
        ret = self._lib.ptrs_load_pointer_map(
            self._ptr, c_char_p(info_file.encode()), c_char_p(bin_file.encode())
        )
        self._check_ret(ret)

    # Scan the pointer chain and write the results to `outfile`
    # If there are multiple target addresses, you can use it in multiple threads, not sure if it is thread safe for now
    def scan_pointer_chain(self, param: Param, outfile: str):
        ret = self._lib.ptrs_scan_pointer_chain(
            self._ptr, param, c_char_p(outfile.encode())
        )
        self._check_ret(ret)

    # Filter all invalid pointer chains in `infile` and write the results to `outfile`
    def chain_filter_invalid(self, infile: str, outfile: str):
        ret = self._lib.ptrs_filter_invalid(
            self._ptr, c_char_p(infile.encode()), c_char_p(outfile.encode())
        )
        self._check_ret(ret)

    # Filter all pointer chains in `infile` based on `value` and write the results to `outfile`
    def chain_filter_value(self, infile: str, outfile: str, value: bytearray):
        data = (c_ubyte * len(value))(*value)
        size = c_size_t(sizeof(data))
        ret = self._lib.ptrs_filter_value(
            self._ptr, c_char_p(infile.encode()), c_char_p(outfile.encode()), data, size
        )
        self._check_ret(ret)

    # Filter all pointer chains in `infile` based on `addr` and write the results to `outfile`
    def chain_filter_addr(self, infile: str, outfile: str, addr: int):
        ret = self._lib.ptrs_filter_addr(
            self._ptr,
            c_char_p(infile.encode()),
            c_char_p(outfile.encode()),
            c_size_t(addr),
        )
        self._check_ret(ret)

    # Function returns the address pointed to by a single chain of pointers
    def chain_get_addr(self, chain: str) -> int:
        addr = c_size_t()
        ret = self._lib.ptrs_get_chain_addr(
            self._ptr, c_char_p(chain.encode()), byref(addr)
        )
        self._check_ret(ret)
        return int.from_bytes(addr, byteorder="little")

    # Compare the pointer chains in `infile1` and `infile2`, and write their intersection into `outfile`
    def compare_two_file(self, infile1: str, infile2: str, outfile: str):
        ret = self._lib.compare_two_file(
            c_char_p(infile1.encode()),
            c_char_p(infile2.encode()),
            c_char_p(outfile.encode()),
        )
        self._check_ret(ret)
