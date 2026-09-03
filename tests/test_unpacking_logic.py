import os
import random
import struct
import sys
import types
import unittest
from typing import Any, Dict, List, Optional
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Stand-ins for the native dependencies that aren't needed by these tests
if "lief" not in sys.modules:
    try:
        import lief  # noqa: F401
    except ImportError:
        _lief = types.ModuleType("lief")
        _lief.PE = types.SimpleNamespace(Binary=object,
                                         Section=object,
                                         DataDirectory=object)
        _lief.logging = types.SimpleNamespace(disable=lambda: None)
        sys.modules["lief"] = _lief

if "pyscylla" not in sys.modules:
    try:
        import pyscylla  # noqa: F401
    except ImportError:
        sys.modules["pyscylla"] = types.ModuleType("pyscylla")

if "xxhash" not in sys.modules:
    try:
        import xxhash  # noqa: F401
    except ImportError:
        import hashlib

        class _Xxh32:

            def __init__(self) -> None:
                self._hash = hashlib.md5()

            def update(self, data: Any) -> None:
                self._hash.update(
                    data.encode() if isinstance(data, str) else data)

            def digest(self) -> bytes:
                return self._hash.digest()[:4]

        _xxhash = types.ModuleType("xxhash")
        _xxhash.xxh32 = _Xxh32
        sys.modules["xxhash"] = _xxhash

from capstone import CS_ARCH_X86, CS_MODE_32, Cs  # noqa: E402

from unlicense import winlicense2, winlicense3  # noqa: E402
from unlicense.imports import find_wrapped_imports  # noqa: E402
from unlicense.process_control import (  # noqa: E402
    Architecture, MemoryRange, ProcessController, QueryProcessMemoryError,
    ReadProcessMemoryError)

TEXT_BASE = 0x401000
DATA_BASE = 0x402000
EXPORT_BASE = 0x70000000
WRAPPER_BASE = 0x60000000


class FakeProcessController(ProcessController):

    def __init__(self,
                 ranges: List[MemoryRange],
                 exports: Optional[Dict[int, Dict[str, Any]]] = None,
                 pointer_size: int = 4,
                 page_size: int = 0x1000):
        architecture = Architecture.X86_32 if pointer_size == 4 \
            else Architecture.X86_64
        super().__init__(1, "fake.exe", architecture, pointer_size, page_size)
        self.ranges = list(ranges)
        self.exports = exports if exports is not None else {}
        self.reads: List[Any] = []
        self.writes: List[Any] = []

    def _lookup(self, address: int) -> Optional[MemoryRange]:
        for mem_range in self.ranges:
            if mem_range.contains(address):
                return mem_range
        return None

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        return {"name": "fake.exe"} if self._lookup(address) else None

    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        return self._lookup(address)

    def find_export_by_name(self, module_name: str,
                            export_name: str) -> Optional[int]:
        return EXPORT_BASE

    def enumerate_modules(self) -> List[str]:
        return ["fake.exe"]

    def enumerate_module_ranges(self,
                                module_name: str,
                                include_data: bool = False
                                ) -> List[MemoryRange]:
        return list(self.ranges)

    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        return self.exports

    def allocate_process_memory(self, size: int, near: int) -> int:
        return 0x50000000

    def query_memory_protection(self, address: int) -> str:
        mem_range = self._lookup(address)
        if mem_range is None:
            raise QueryProcessMemoryError
        return mem_range.protection

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        return True

    def read_process_memory(self, address: int, size: int) -> bytes:
        self.reads.append((address, size))
        mem_range = self._lookup(address)
        if mem_range is None or mem_range.data is None:
            raise ReadProcessMemoryError
        offset = address - mem_range.base
        data = mem_range.data[offset:offset + size]
        if len(data) != size:
            raise ReadProcessMemoryError
        return bytes(data)

    def write_process_memory(self, address: int, data: List[int]) -> None:
        self.writes.append((address, bytes(data)))

    def terminate_process(self) -> None:
        pass


def make_text_range(code: bytes, size: int = 0x100) -> MemoryRange:
    return MemoryRange(TEXT_BASE, size, "r-x", code.ljust(size, b"\x00"))


def disassembler() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


class TestCallSiteScanning(unittest.TestCase):

    def test_no_exception_on_any_offset(self) -> None:
        random.seed(0xC0FFEE)
        code = bytes(random.randrange(256) for _ in range(0x400))
        text_range = make_text_range(code, 0x400)
        controller = FakeProcessController([text_range])
        find_wrapped_imports(text_range, {}, disassembler(), controller)

    def test_truncated_instruction_at_section_end(self) -> None:
        code = bytes(0x40) + bytes([0x90, 0xE8, 0x00])
        text_range = make_text_range(code, len(code))
        controller = FakeProcessController([text_range])
        find_wrapped_imports(text_range, {}, disassembler(), controller)

    def test_branch_opcodes_at_section_end(self) -> None:
        for tail in ([0xFF, 0x25], [0xE8], [0xE9], [0xFF, 0x25, 0, 0, 0, 0],
                     [0xE8, 0, 0, 0, 0], [0xE9, 0, 0, 0, 0], [0x90, 0xE8]):
            with self.subTest(tail=bytes(tail).hex()):
                code = bytes(0x40) + bytes(tail)
                text_range = make_text_range(code, len(code))
                controller = FakeProcessController([text_range])
                find_wrapped_imports(text_range, {}, disassembler(),
                                     controller)

    def test_dense_jmp_table_is_fully_detected(self) -> None:
        entry_count = 5
        code = bytearray()
        exports = {}
        for index in range(entry_count):
            target = EXPORT_BASE + index * 0x100
            rel = target - (TEXT_BASE + len(code) + 5)
            code += bytes([0xE9]) + struct.pack("<i", rel)
            exports[target] = {"name": f"api{index}", "address": hex(target)}

        text_range = make_text_range(bytes(code))
        controller = FakeProcessController([text_range], exports)
        api_to_calls, _ = find_wrapped_imports(text_range, exports,
                                               disassembler(), controller)

        self.assertEqual(len(api_to_calls), entry_count)
        by_addr = {
            call[0]: call
            for calls in api_to_calls.values() for call in calls
        }
        self.assertEqual(sorted(by_addr),
                         [TEXT_BASE + i * 5 for i in range(entry_count)])
        # Only the last entry has room for the 6-byte replacement
        for index in range(entry_count - 1):
            self.assertFalse(by_addr[TEXT_BASE + index * 5][3])
        self.assertTrue(by_addr[TEXT_BASE + (entry_count - 1) * 5][3])

    def test_only_padding_may_be_overwritten(self) -> None:
        targets = [EXPORT_BASE, EXPORT_BASE + 0x100]
        exports = {t: {"name": f"api{i}"} for i, t in enumerate(targets)}

        code = bytearray()
        # A real instruction (push eax) sits right after the first 5-byte jmp
        for index, filler in enumerate([0x50, 0x90]):
            rel = targets[index] - (TEXT_BASE + len(code) + 5)
            code += bytes([0xE9]) + struct.pack("<i", rel) + bytes([filler])

        text_range = make_text_range(bytes(code))
        controller = FakeProcessController([text_range], exports)
        api_to_calls, _ = find_wrapped_imports(text_range, exports,
                                               disassembler(), controller)

        patchable = {
            call[0]: call[3]
            for calls in api_to_calls.values() for call in calls
        }
        self.assertEqual(sorted(patchable), [TEXT_BASE, TEXT_BASE + 6])
        self.assertFalse(patchable[TEXT_BASE])
        self.assertTrue(patchable[TEXT_BASE + 6])

    def test_adjacent_indirect_calls_are_both_detected(self) -> None:
        targets = [EXPORT_BASE, EXPORT_BASE + 0x100]
        pointers = b"".join(struct.pack("<I", t) for t in targets)
        code = b"".join(
            bytes([0xFF, 0x15]) + struct.pack("<I", DATA_BASE + i * 4)
            for i in range(len(targets)))
        exports = {t: {"name": f"api{i}"} for i, t in enumerate(targets)}

        text_range = make_text_range(code)
        data_range = MemoryRange(DATA_BASE, 0x1000, "rw-",
                                 pointers.ljust(0x1000, b"\x00"))
        controller = FakeProcessController([text_range, data_range], exports)
        api_to_calls, _ = find_wrapped_imports(text_range, exports,
                                               disassembler(), controller)

        self.assertEqual(sorted(api_to_calls), targets)
        for calls in api_to_calls.values():
            self.assertTrue(calls[0][3])


class TestFindIatStart(unittest.TestCase):

    def test_iat_start_found_past_the_first_pointers(self) -> None:
        page_size = 0x1000
        start_offset = 0x800
        exports = {
            EXPORT_BASE + i * 0x10: {
                "name": f"api{i}"
            }
            for i in range(256)
        }
        page = bytearray(b"".join(
            struct.pack("<Q", i) for i in range(start_offset // 8)))
        for i in range((page_size - start_offset) // 8):
            page += struct.pack("<Q", EXPORT_BASE + i * 0x10)

        export_range = MemoryRange(EXPORT_BASE, 0x10000, "r-x")
        controller = FakeProcessController([export_range],
                                           exports,
                                           pointer_size=8)
        self.assertEqual(
            winlicense3._find_iat_start(bytes(page), exports, controller),
            start_offset)

    def test_garbage_page_is_rejected(self) -> None:
        controller = FakeProcessController([], {}, pointer_size=8)
        page = b"".join(struct.pack("<Q", i) for i in range(0x1000 // 8))
        self.assertIsNone(winlicense3._find_iat_start(page, {}, controller))


class TestUnwrapIat(unittest.TestCase):

    def test_unaligned_iat_is_read_without_gaps(self) -> None:
        page_size = 0x1000
        iat_base = DATA_BASE + 0x40
        iat_size = 0x2000
        entry_count = iat_size // 4
        exports = {
            EXPORT_BASE + i * 0x10: {
                "name": f"api{i}"
            }
            for i in range(entry_count)
        }
        container = bytearray(0x40)
        expected = b"".join(
            struct.pack("<I", EXPORT_BASE + i * 0x10)
            for i in range(entry_count))
        container += expected

        container_range = MemoryRange(DATA_BASE, 0x4000, "rw-",
                                      bytes(container).ljust(0x4000, b"\x00"))
        controller = FakeProcessController([container_range], exports)
        result = winlicense3._unwrap_iat(
            MemoryRange(iat_base, iat_size, "rw-"), controller)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result, (iat_size, entry_count))
        self.assertEqual(len(controller.writes), 1)
        self.assertEqual(controller.writes[0], (iat_base, expected))

    def test_reads_stay_inside_the_iat(self) -> None:
        iat_base = DATA_BASE + 0x40
        iat_size = 0x1800
        container_range = MemoryRange(DATA_BASE, 0x4000, "rw-", bytes(0x4000))
        controller = FakeProcessController([container_range], {})
        winlicense3._unwrap_iat(MemoryRange(iat_base, iat_size, "rw-"),
                                controller)

        self.assertTrue(controller.reads)
        for address, size in controller.reads:
            self.assertGreaterEqual(address, iat_base)
            self.assertLessEqual(address + size, iat_base + iat_size)
        self.assertEqual(sum(size for _, size in controller.reads), iat_size)


class TestFindIatFromCodeSections(unittest.TestCase):

    def test_candidate_size_is_expressed_in_bytes(self) -> None:
        pointer_count = 4
        wrappers = [WRAPPER_BASE + i * 0x100 for i in range(pointer_count)]
        pointers = b"".join(struct.pack("<I", w) for w in wrappers)
        code = b"".join(
            bytes([0xFF, 0x15]) + struct.pack("<I", DATA_BASE + i * 4)
            for i in range(pointer_count))

        text_range = MemoryRange(0, 0x100, "r-x")
        code_range = MemoryRange(TEXT_BASE, 0x100, "r-x",
                                 code.ljust(0x100, b"\x00"))
        data_range = MemoryRange(DATA_BASE, 0x1000, "rw-",
                                 pointers.ljust(0x1000, b"\x00"))
        wrapper_range = MemoryRange(WRAPPER_BASE, 0x1000, "r-x")
        controller = FakeProcessController(
            [code_range, data_range, wrapper_range], {})

        result = winlicense3._find_iat_from_code_sections(
            controller, TEXT_BASE, text_range, {})

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.base, DATA_BASE)
        self.assertEqual(result.size, pointer_count * 4)


class TestExportHashes(unittest.TestCase):

    def test_ambiguous_hashes_are_discarded(self) -> None:
        shared = winlicense2.EMPTY_FUNCTION_HASH + 1
        unique = winlicense2.EMPTY_FUNCTION_HASH + 2
        exports = {0x1000: {"name": "a"}, 0x2000: {"name": "b"},
                   0x3000: {"name": "c"}}
        hashes = {0x1000: shared, 0x2000: shared, 0x3000: unique}
        controller = FakeProcessController([])

        with mock.patch.object(
                winlicense2, "compute_function_hash",
                lambda md, addr, get_data, ctrl: hashes[addr]):
            result = winlicense2._generate_export_hashes(
                disassembler(), exports, controller)

        self.assertEqual(result, {unique: 0x3000})


if __name__ == "__main__":
    unittest.main()
