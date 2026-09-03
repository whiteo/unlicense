import logging
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from capstone import Cs  # type: ignore
from capstone.x86 import X86_OP_MEM, X86_OP_IMM  # type: ignore

from .dump_utils import pointer_size_to_fmt
from .process_control import Architecture, MemoryRange, ProcessController, ProcessControllerException

LOG = logging.getLogger(__name__)
# Size of the `FF 15/25 disp32` instruction call sites are replaced with
PATCHED_INSTRUCTION_SIZE = 6
# Bytes that are safe to overwrite when the patch is longer than the call site
PADDING_BYTES = frozenset((0x90, 0xCC, 0x00))

# Describes a map of API addresses to every call site that should point to it
# (instr_addr, call_size, instr_was_jmp, patchable)
ImportCallSiteInfo = Tuple[int, int, bool, bool]
ImportToCallSiteDict = Dict[int, List[ImportCallSiteInfo]]
# Describes a set of all found call sites
# (instr_addr, call_size, instr_was_jmp, call_dest, ptr_addr, patchable)
ImportWrapperInfo = Tuple[int, int, bool, int, Optional[int], bool]
WrapperSet = Set[ImportWrapperInfo]


def find_wrapped_imports(
    text_section_range: MemoryRange,
    exports_dict: Dict[int, Dict[str, Any]],  #
    md: Cs,
    process_controller: ProcessController
) -> Tuple[ImportToCallSiteDict, WrapperSet]:
    """
    Go through a code section and try to find wrapped (or not) import calls
    and jmps by disassembling instructions and using a few basic heuristics.
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)

    assert text_section_range.data is not None
    text_section_data = text_section_range.data

    wrapper_set: WrapperSet = set()
    api_to_calls: ImportToCallSiteDict = defaultdict(list)
    i = 0
    while i < text_section_range.size:
        if not _is_wrapped_thunk_jmp(text_section_data, i) and \
                not _is_wrapped_call(text_section_data, i) and \
                not _is_wrapped_tail_call(text_section_data, i) and \
                not _is_indirect_call(text_section_data, i):
            i += 1
            continue

        # Tail calls ("jmp X; int 3") also have to become a jmp
        if text_section_data[i] == 0xE9 or \
                text_section_data[i:i + 2] == bytes([0x90, 0xE9]) or \
                text_section_data[i:i + 2] == bytes([0xFF, 0x25]) or \
                _is_wrapped_tail_call(text_section_data, i):
            instr_was_jmp = True
        else:
            instr_was_jmp = False

        instr_addr = text_section_range.base + i
        instrs = md.disasm(text_section_data[i:i + 6], instr_addr)

        # Ensure the instructions are "call/jmp" or "nop; call/jmp"
        instruction = next(instrs, None)
        if instruction is None:
            i += 1
            continue
        had_nop = False
        if instruction.mnemonic in ["call", "jmp"]:
            call_size = instruction.size
            op = instruction.operands[0]
        elif instruction.mnemonic == "nop":
            had_nop = True
            instruction = next(instrs, None)
            if instruction is None:
                i += 1
                continue
            if instruction.mnemonic in ["call", "jmp"]:
                call_size = instruction.size
                op = instruction.operands[0]
            else:
                i += 1
                continue
        else:
            i += 1
            continue

        slot_size = call_size + 1 if had_nop else call_size
        patchable = _call_site_is_patchable(text_section_data, i, slot_size)
        next_offset = i + (max(slot_size, PATCHED_INSTRUCTION_SIZE)
                           if patchable else slot_size)

        if op.type == X86_OP_IMM:
            call_dest = op.value.imm
            ptr_addr = None
        elif op.type == X86_OP_MEM:
            try:
                if arch == Architecture.X86_32:
                    ptr_addr = op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                elif arch == Architecture.X86_64:
                    ptr_addr = instruction.address + instruction.size + op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                else:
                    raise NotImplementedError(
                        f"Unsupported architecture: {arch}")
            except ProcessControllerException:
                i += 1
                continue
        else:
            i += 1
            continue

        if not text_section_range.contains(call_dest):
            # Not wrapped, add it to list of "resolved wrappers"
            if call_dest in exports_dict:
                api_to_calls[call_dest].append(
                    (instr_addr, call_size, instr_was_jmp, patchable))
                i = next_offset
                continue
            # Wrapped, add it to set of wrappers to resolve
            if _is_in_executable_range(call_dest, process_controller):
                wrapper_set.add((instr_addr, call_size, instr_was_jmp,
                                 call_dest, ptr_addr, patchable))
                i = next_offset
                continue
        i += 1

    return api_to_calls, wrapper_set


def _call_site_is_patchable(code_section_data: bytes, offset: int,
                            slot_size: int) -> bool:
    """
    Check whether `PATCHED_INSTRUCTION_SIZE` bytes can be written at `offset`
    without overwriting anything but padding.
    """
    if offset + PATCHED_INSTRUCTION_SIZE > len(code_section_data):
        return False
    if slot_size >= PATCHED_INSTRUCTION_SIZE:
        return True

    tail = code_section_data[offset + slot_size:offset +
                             PATCHED_INSTRUCTION_SIZE]
    return all(byte in PADDING_BYTES for byte in tail)


def _is_indirect_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is an `FF15` call.
    """
    return code_section_data[offset:offset + 2] == bytes([0xFF, 0x15])


def _is_wrapped_thunk_jmp(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped jmp from a thunk table.
    """
    if offset + 6 >= len(code_section_data):
        return False

    is_e9_jmp = code_section_data[offset] == 0xE9
    # Dirty trick to catch last elements of thunk tables
    if offset > 6:
        jmp_behind = code_section_data[offset - 5] == 0xE9 or \
                     code_section_data[offset - 6] == 0xE9
    else:
        jmp_behind = False

    return (is_e9_jmp and code_section_data[offset + 6] in [0xE9, 0x90]) or \
           (is_e9_jmp and code_section_data[offset + 5] in [0xCC, 0x90, 0xE9]) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE9])) or \
           (is_e9_jmp and jmp_behind) or \
           (code_section_data[offset:offset + 2] == bytes([0xFF, 0x25]) and code_section_data[offset + 6] in [0x8B, 0xC0]) # Turbo delphi-style tuhnk


def _is_wrapped_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped import call. Themida 2.x
    replaces `FF15` calls with `E8` calls followed or preceded by a `nop`.
    """
    if offset + 5 >= len(code_section_data):
        return False

    return (code_section_data[offset] == 0xE8 and code_section_data[offset + 5] == 0x90) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8]))


def _is_wrapped_tail_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a tail call (and thus should be
    transformed into a `jmp`).
    """
    if offset + 6 >= len(code_section_data):
        return False

    is_call = code_section_data[offset] == 0xE8
    return (is_call and code_section_data[offset + 5] == 0xCC) or \
            (is_call and code_section_data[offset + 6] == 0xCC) or \
            (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8])
            and code_section_data[offset + 6] == 0xCC) or (
                code_section_data[offset:offset + 2] == bytes([0xFF, 0x25])
                and code_section_data[offset + 6] == 0xCC)


def _is_in_executable_range(address: int,
                            process_controller: ProcessController) -> bool:
    """
    Check if an address is located in an executable memory range.
    """
    mem_range = process_controller.find_range_by_address(address)
    if mem_range is None:
        return False

    protection: str = mem_range.protection[2]
    return protection == 'x'
