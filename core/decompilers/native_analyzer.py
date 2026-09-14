"""Native binary analyzer module for x86/x64 binaries."""

import os
import logging
import json
import struct
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OPT_OFF
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logging.warning("Capstone not available for disassembly")

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    logging.warning("LIEF not available for binary parsing")

try:
    # Try to import Ghidra/PyGhidra if available
    # Note: This requires Java and Ghidra installation
    # from pyghidra import PyGhidra
    HAS_GHIDRA = False
except ImportError:
    HAS_GHIDRA = False
    logging.warning("PyGhidra not available for decompilation")

logger = logging.getLogger(__name__)


class InstructionType(Enum):
    """Instruction type categories."""
    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    DATA_TRANSFER = "data_transfer"
    CONTROL_FLOW = "control_flow"
    STACK = "stack"
    SYSTEM = "system"
    FLOAT = "float"
    SIMD = "simd"
    OTHER = "other"


@dataclass
class InstructionInfo:
    """Information about a single instruction."""
    address: int
    size: int
    bytes: bytes
    mnemonic: str
    op_str: str
    instruction_type: InstructionType
    is_branch: bool = False
    is_call: bool = False
    is_jump: bool = False
    is_return: bool = False
    target_address: Optional[int] = None
    comments: List[str] = None
    
    def __post_init__(self):
        if self.comments is None:
            self.comments = []


@dataclass
class FunctionInfo:
    """Information about a function in the binary."""
    name: str
    address: int
    size: int
    instructions: List[InstructionInfo]
    called_functions: List[str]
    referenced_strings: List[str]
    is_exported: bool = False
    is_imported: bool = False
    has_prologue: bool = False
    has_epilogue: bool = False
    local_vars_count: int = 0
    parameters_count: int = 0


@dataclass
class SectionInfo:
    """Information about a binary section."""
    name: str
    address: int
    size: int
    virtual_size: int
    entropy: float
    is_executable: bool
    is_writable: bool
    is_readable: bool
    contains_code: bool = False


@dataclass
class NativeBinaryInfo:
    """Information about a native binary."""
    architecture: str
    entry_point: int
    sections: List[SectionInfo]
    functions: List[FunctionInfo]
    imports: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    strings: List[Dict[str, Any]]
    entropy_analysis: Dict[str, float]
    metadata: Dict[str, Any]


class NativeAnalyzer:
    """Native binary analyzer for x86/x64 binaries."""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.binary_data = None
        self.binary = None
        self.analyzer_info: Optional[NativeBinaryInfo] = None
        
        # Capstone disassembler instances
        self.cs_x86 = None
        self.cs_x64 = None
        
        # Symbol resolution maps
        self.iat_symbols: Dict[int, str] = {}
        self.string_symbols: Dict[int, str] = {}
        self.export_symbols: Dict[int, str] = {}
        self.function_symbols: Dict[int, str] = {}
        
        # Load binary data
        self._load_binary()
        
    def _load_binary(self):
        """Load binary file into memory."""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            
            if HAS_LIEF:
                try:
                    self.binary = lief.parse(self.binary_path)
                except Exception as e:
                    logger.warning(f"LIEF parsing failed: {e}")
                    self.binary = None
        except Exception as e:
            logger.error(f"Failed to load binary file: {e}")
            raise
    
    def analyze(self) -> NativeBinaryInfo:
        """Analyze the native binary."""
        if not self.binary_data:
            raise RuntimeError("Binary data not loaded")
        
        # Detect architecture
        architecture = self._detect_architecture()
        
        # Analyze sections
        sections = self._analyze_sections()
        
        # Analyze imports and exports
        imports = self._analyze_imports()
        exports = self._analyze_exports()
        
        # Extract strings
        strings = self._extract_strings()
        
        # Analyze functions (basic pattern matching)
        functions = self._analyze_functions()
        
        # Calculate entropy
        entropy_analysis = self._calculate_entropy()
        
        # Determine entry point
        entry_point = self._get_entry_point()
        
        metadata = {
            "file_size": len(self.binary_data),
            "analyzed_with_capstone": HAS_CAPSTONE,
            "analyzed_with_lief": HAS_LIEF and self.binary is not None,
            "analyzed_with_ghidra": HAS_GHIDRA,
        }
        
        self.analyzer_info = NativeBinaryInfo(
            architecture=architecture,
            entry_point=entry_point,
            sections=sections,
            functions=functions,
            imports=imports,
            exports=exports,
            strings=strings,
            entropy_analysis=entropy_analysis,
            metadata=metadata
        )
        
        return self.analyzer_info
    
    def disassemble_range(self, address: int, size: int, arch: str = "x64") -> List[InstructionInfo]:
        """Disassemble a specific memory range."""
        if not HAS_CAPSTONE:
            logger.warning("Capstone not available for disassembly")
            return []
        
        # Initialize capstone if needed
        if arch == "x64" and not self.cs_x64:
            self.cs_x64 = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs_x64.detail = True
        elif arch == "x86" and not self.cs_x86:
            self.cs_x86 = capstone.Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs_x86.detail = True
        
        cs = self.cs_x64 if arch == "x64" else self.cs_x86
        if not cs:
            return []
        
        # Calculate file offset from virtual address
        offset = self._va_to_offset(address)
        if offset is None or offset + size > len(self.binary_data):
            logger.warning(f"Invalid address range: 0x{address:x} - 0x{address+size:x}")
            return []
        
        code = self.binary_data[offset:offset + size]
        
        instructions = []
        for instr in cs.disasm(code, address):
            instr_info = self._create_instruction_info(instr)
            instructions.append(instr_info)
        
        return instructions
    
    def decompile_function(self, function_address: int, function_name: str = "") -> Optional[str]:
        """Decompile a function using available decompilers."""
        # First try Ghidra if available
        if HAS_GHIDRA:
            try:
                return self._decompile_with_ghidra(function_address, function_name)
            except Exception as e:
                logger.warning(f"Ghidra decompilation failed: {e}")
        
        # Fallback to pattern-based pseudocode generation
        return self._generate_pseudocode(function_address, function_name)
    
    def export_analysis(self, output_dir: str) -> Dict[str, str]:
        """Export analysis results to files."""
        os.makedirs(output_dir, exist_ok=True)
        exported_files = {}
        
        try:
            # 1. Export extracted strings
            strings_path = os.path.join(output_dir, "strings.txt")
            with open(strings_path, 'w', encoding='utf-8') as f:
                for string_info in (self.analyzer_info.strings if self.analyzer_info else []):
                    f.write(f"0x{string_info['address']:x}: {string_info['string']}\n")
            exported_files["strings"] = strings_path

            # 2. Export consolidated pseudocode.c
            pseudocode_path = os.path.join(output_dir, "pseudocode.c")
            with open(pseudocode_path, 'w', encoding='utf-8') as f:
                f.write("/*\n * Decompiled Native Pseudocode\n * Generated by Binary Deobfuscator\n */\n\n")
                f.write("#include <stdint.h>\n#include <stdbool.h>\n#include <windows.h>\n\n")
                for func in (self.analyzer_info.functions if self.analyzer_info else []):
                    code = self._generate_pseudocode(func.address, func.name)
                    if code:
                        f.write(code + "\n\n")
            exported_files["pseudocode.c"] = pseudocode_path

            # 3. Export consolidated disassembly.asm
            disasm_path = os.path.join(output_dir, "disassembly.asm")
            with open(disasm_path, 'w', encoding='utf-8') as f:
                f.write("; Disassembly output generated by Binary Deobfuscator\n\n")
                for func in (self.analyzer_info.functions if self.analyzer_info else []):
                    f.write(f"; ========================================================\n")
                    f.write(f"; Function: {func.name} (Address: 0x{func.address:x}, Size: {func.size} bytes)\n")
                    f.write(f"; ========================================================\n")
                    for instr in func.instructions:
                        f.write(f"  0x{instr.address:x}: {instr.mnemonic:<8} {instr.op_str}\n")
                    f.write("\n")
            exported_files["disassembly.asm"] = disasm_path

            # 4. Export JSON report summary
            report_path = os.path.join(output_dir, "analysis_report.json")
            if self.analyzer_info:
                summary_data = {
                    "architecture": self.analyzer_info.architecture,
                    "entry_point": hex(self.analyzer_info.entry_point),
                    "functions_count": len(self.analyzer_info.functions),
                    "imports_count": len(self.analyzer_info.imports),
                    "exports_count": len(self.analyzer_info.exports),
                    "strings_count": len(self.analyzer_info.strings),
                    "sections": [asdict(s) for s in self.analyzer_info.sections],
                    "entropy_analysis": self.analyzer_info.entropy_analysis,
                    "metadata": self.analyzer_info.metadata
                }
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(summary_data, f, indent=2, default=str)
                exported_files["report"] = report_path
            
        except Exception as e:
            logger.error(f"Failed to export analysis: {e}")
        
        return exported_files
    
    def _detect_architecture(self) -> str:
        """Detect the binary architecture."""
        if HAS_LIEF and self.binary:
            try:
                if isinstance(self.binary, lief.PE.Binary):
                    machine_str = str(self.binary.header.machine).upper()
                    if "AMD64" in machine_str or "X86_64" in machine_str:
                        return "x64"
                    elif "386" in machine_str or "X86" in machine_str:
                        return "x86"
                    elif "ARM64" in machine_str or "AARCH64" in machine_str:
                        return "ARM64"
                    elif "ARM" in machine_str:
                        return "ARM"
                elif isinstance(self.binary, lief.ELF.Binary):
                    machine_str = str(self.binary.header.machine_type).upper()
                    if "AMD64" in machine_str or "X86_64" in machine_str:
                        return "x64"
                    elif "386" in machine_str or "X86" in machine_str:
                        return "x86"
                    elif "ARM64" in machine_str or "AARCH64" in machine_str:
                        return "ARM64"
                    elif "ARM" in machine_str:
                        return "ARM"
            except Exception:
                pass
        
        # Fallback: try to detect from magic bytes
        if len(self.binary_data) >= 2:
            magic = self.binary_data[:2]
            if magic == b'MZ':  # PE header
                if len(self.binary_data) >= 0x40:
                    pe_offset = struct.unpack('<I', self.binary_data[0x3C:0x40])[0]
                    if pe_offset + 0x18 < len(self.binary_data):
                        machine = struct.unpack('<H', self.binary_data[pe_offset + 4:pe_offset + 6])[0]
                        if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                            return "x64"
                        elif machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                            return "x86"
                        elif machine == 0xaa64: # IMAGE_FILE_MACHINE_ARM64
                            return "ARM64"
                        elif machine in (0x1c0, 0x1c4): # IMAGE_FILE_MACHINE_ARM
                            return "ARM"
        
        return "x64"
    
    def _analyze_sections(self) -> List[SectionInfo]:
        """Analyze binary sections."""
        sections = []
        
        if HAS_LIEF and self.binary:
            try:
                for section in self.binary.sections:
                    try:
                        chars = getattr(section, 'characteristics', 0)
                        if isinstance(chars, int):
                            is_exec = bool(chars & 0x20000000)
                            is_write = bool(chars & 0x80000000)
                            is_read = bool(chars & 0x40000000)
                        else:
                            char_list = [str(c).upper() for c in getattr(section, 'characteristics_list', [])]
                            is_exec = any("EXEC" in c for c in char_list)
                            is_write = any("WRITE" in c for c in char_list)
                            is_read = any("READ" in c for c in char_list)

                        section_info = SectionInfo(
                            name=str(section.name),
                            address=int(section.virtual_address),
                            size=int(section.size),
                            virtual_size=int(getattr(section, 'virtual_size', section.size)),
                            entropy=float(getattr(section, 'entropy', 0.0)),
                            is_executable=is_exec,
                            is_writable=is_write,
                            is_readable=is_read,
                            contains_code=self._section_contains_code(section)
                        )
                        sections.append(section_info)
                    except Exception:
                        pass
            except Exception:
                sections = []
        
        if not sections and self.binary_data[:2] == b'MZ':
            # Manual / pefile fallback
            sections = self._parse_pe_sections_manual()
        
        return sections
    
    def _analyze_imports(self) -> List[Dict[str, Any]]:
        """Analyze imported functions."""
        imports = []
        try:
            import pefile
            pe = pefile.PE(data=self.binary_data)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
                        iat_va = imp.address if imp.address else 0
                        imports.append({
                            "dll": dll_name,
                            "function": func_name,
                            "ordinal": imp.ordinal,
                            "address": iat_va
                        })
                        if iat_va:
                            self.iat_symbols[iat_va] = func_name
        except Exception:
            pass
        
        if not imports and HAS_LIEF and self.binary and hasattr(self.binary, 'imports'):
            for imp in self.binary.imports:
                for entry in imp.entries:
                    func_name = entry.name or f"ordinal_{entry.ordinal}"
                    iat_va = entry.iat_address if hasattr(entry, 'iat_address') else 0
                    imports.append({
                        "dll": imp.name,
                        "function": func_name,
                        "ordinal": entry.ordinal,
                        "address": iat_va
                    })
                    if iat_va:
                        self.iat_symbols[iat_va] = func_name
        
        return imports
    
    def _analyze_exports(self) -> List[Dict[str, Any]]:
        """Analyze exported functions."""
        exports = []
        try:
            import pefile
            pe = pefile.PE(data=self.binary_data)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exp_name = exp.name.decode('utf-8', errors='ignore')
                        exp_va = image_base + exp.address
                        exports.append({
                            "name": exp_name,
                            "address": exp_va,
                            "ordinal": exp.ordinal
                        })
                        self.export_symbols[exp_va] = exp_name
                        self.function_symbols[exp_va] = exp_name
        except Exception:
            pass
        
        if not exports and HAS_LIEF and self.binary and hasattr(self.binary, 'exported_functions'):
            for exp in self.binary.exported_functions:
                exports.append({
                    "name": exp.name,
                    "address": exp.address,
                    "ordinal": exp.ordinal
                })
                self.export_symbols[exp.address] = exp.name
                self.function_symbols[exp.address] = exp.name
        
        return exports
    
    def _extract_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII strings from the binary and map to VAs."""
        strings = []
        try:
            import pefile
            pe = pefile.PE(data=self.binary_data)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            for s in pe.sections:
                data = s.get_data()
                sec_va = image_base + s.VirtualAddress
                curr = ""
                start_offset = 0
                for idx, b in enumerate(data):
                    if 32 <= b <= 126:
                        if not curr:
                            start_offset = idx
                        curr += chr(b)
                    else:
                        if len(curr) >= min_length:
                            str_va = sec_va + start_offset
                            strings.append({
                                "address": str_va,
                                "string": curr,
                                "length": len(curr)
                            })
                            self.string_symbols[str_va] = curr
                        curr = ""
        except Exception:
            current_string = ""
            current_address = 0
            for i, byte in enumerate(self.binary_data):
                if 32 <= byte <= 126:
                    if not current_string:
                        current_address = i
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append({
                            "address": current_address,
                            "string": current_string,
                            "length": len(current_string)
                        })
                        va = self._offset_to_va(current_address)
                        if va:
                            self.string_symbols[va] = current_string
                    current_string = ""
        
        return strings
    
    def _analyze_functions(self) -> List[FunctionInfo]:
        """Analyze functions in the binary using pattern recognition."""
        functions = []
        seen_addresses = set()
        
        if not HAS_CAPSTONE:
            return functions
        
        # 1. Add Entry Point function
        ep = self._get_entry_point()
        if ep:
            func = self._analyze_function_at(ep)
            func.name = "entry_point"
            functions.append(func)
            seen_addresses.add(ep)
        
        # 2. Add Exported functions
        if hasattr(self, 'analyzer_info') and self.analyzer_info and self.analyzer_info.exports:
            for exp in self.analyzer_info.exports:
                addr = exp.get("address", 0)
                if addr and addr not in seen_addresses:
                    func = self._analyze_function_at(addr)
                    func.name = exp.get("name", f"export_{addr:x}")
                    func.is_exported = True
                    functions.append(func)
                    seen_addresses.add(addr)
        
        # 3. Multi-byte function prologues
        common_prologues = [
            b"\x55\x8B\xEC",              # push ebp; mov ebp, esp (x86)
            b"\x55\x48\x89\xE5",          # push rbp; mov rbp, rsp (x64)
            b"\x48\x83\xEC",              # sub rsp, imm8 (x64)
            b"\x48\x81\xEC",              # sub rsp, imm32 (x64)
            b"\x40\x53\x48\x83\xEC",      # push rbx; sub rsp, imm8 (x64)
            b"\x48\x89\x5C\x24",          # mov [rsp+...], rbx (x64)
            b"\x48\x89\x4C\x24",          # mov [rsp+...], rcx (x64)
        ]
        
        # Scan code regions (limit to 500 significant functions to keep analysis fast and responsive)
        data_len = len(self.binary_data)
        i = 0
        while i < data_len - 8 and len(functions) < 500:
            matched = False
            for prologue in common_prologues:
                if self.binary_data[i:i+len(prologue)] == prologue:
                    func_address = self._offset_to_va(i)
                    if func_address and func_address not in seen_addresses:
                        func = self._analyze_function_at(func_address)
                        if func.instructions and len(func.instructions) >= 2:
                            functions.append(func)
                            seen_addresses.add(func_address)
                            i += max(func.size, len(prologue))
                            matched = True
                            break
            if not matched:
                i += 1
        
        return functions
    
    def _analyze_function_at(self, address: int) -> FunctionInfo:
        """Analyze a function at a specific address."""
        # Simple function analysis - disassemble until return
        if not HAS_CAPSTONE:
            return FunctionInfo(
                name=f"func_{address:x}",
                address=address,
                size=0,
                instructions=[],
                called_functions=[],
                referenced_strings=[]
            )
        
        arch = self._detect_architecture()
        if arch not in ["x86", "x64"]:
            arch = "x64"  # Default
        
        # Disassemble a reasonable amount
        instructions = self.disassemble_range(address, 1024, arch)
        
        # Try to find function end (ret instruction)
        func_size = 0
        called_funcs = []
        
        for instr in instructions:
            func_size += instr.size
            if instr.is_return:
                break
            
            # Track calls to other functions
            if instr.is_call and instr.target_address:
                called_funcs.append(hex(instr.target_address))
        
        return FunctionInfo(
            name=f"func_{address:x}",
            address=address,
            size=func_size,
            instructions=instructions[:50],  # Limit instructions for performance
            called_functions=called_funcs,
            referenced_strings=[],
            has_prologue=any(instr.mnemonic in ["push", "mov"] for instr in instructions[:3]),
            has_epilogue=any(instr.is_return for instr in instructions)
        )
    
    def _calculate_entropy(self) -> Dict[str, float]:
        """Calculate entropy for different parts of the binary."""
        from math import log2
        
        def shannon_entropy(data):
            if not data:
                return 0.0
            
            entropy = 0.0
            length = len(data)
            frequencies = {}
            
            for byte in data:
                frequencies[byte] = frequencies.get(byte, 0) + 1
            
            for freq in frequencies.values():
                probability = freq / length
                entropy -= probability * log2(probability)
            
            return entropy
        
        results = {
            "overall": shannon_entropy(self.binary_data),
            "first_1kb": shannon_entropy(self.binary_data[:1024]),
            "last_1kb": shannon_entropy(self.binary_data[-1024:]) if len(self.binary_data) > 1024 else 0.0,
        }
        
        return results
    
    def _get_entry_point(self) -> int:
        """Get the binary entry point."""
        if HAS_LIEF and self.binary:
            if isinstance(self.binary, lief.PE.Binary):
                return self.binary.optional_header.addressof_entrypoint
            elif isinstance(self.binary, lief.ELF.Binary):
                return self.binary.entrypoint
        
        return 0
    
    def _va_to_offset(self, virtual_address: int) -> Optional[int]:
        """Convert virtual address to file offset."""
        if HAS_LIEF and self.binary:
            try:
                if hasattr(self.binary, 'va_to_offset'):
                    return self.binary.va_to_offset(virtual_address)
                elif hasattr(self.binary, 'virtual_address_to_offset'):
                    return self.binary.virtual_address_to_offset(virtual_address)
            except Exception:
                pass
        
        # Check sections mapping
        if hasattr(self, 'analyzer_info') and self.analyzer_info and self.analyzer_info.sections:
            for section in self.analyzer_info.sections:
                va = section.address
                sz = section.size
                if va <= virtual_address < va + sz:
                    return virtual_address
        
        # Simple conversion assuming linear mapping
        return virtual_address if virtual_address < len(self.binary_data) else None
    
    def _offset_to_va(self, offset: int) -> Optional[int]:
        """Convert file offset to virtual address."""
        if HAS_LIEF and self.binary:
            try:
                if hasattr(self.binary, 'offset_to_virtual_address'):
                    return self.binary.offset_to_virtual_address(offset)
                elif hasattr(self.binary, 'offset_to_va'):
                    return self.binary.offset_to_va(offset)
            except Exception:
                pass
        
        return offset
    
    def _create_instruction_info(self, instr) -> InstructionInfo:
        """Create InstructionInfo from Capstone instruction."""
        # Determine instruction type
        instr_type = self._classify_instruction(instr.mnemonic)
        
        # Check for control flow instructions
        is_branch = instr.group(capstone.CS_GRP_JUMP) or instr.group(capstone.CS_GRP_CALL)
        is_call = instr.group(capstone.CS_GRP_CALL)
        is_jump = instr.group(capstone.CS_GRP_JUMP) and not instr.group(capstone.CS_GRP_CALL)
        is_return = instr.mnemonic in ['ret', 'retn', 'retf']
        
        # Extract target address for branches
        target_address = None
        if is_branch and instr.operands:
            for op in instr.operands:
                if op.type == capstone.CS_OP_IMM:
                    target_address = op.value.imm
                    break
        
        return InstructionInfo(
            address=instr.address,
            size=instr.size,
            bytes=instr.bytes,
            mnemonic=instr.mnemonic,
            op_str=instr.op_str,
            instruction_type=instr_type,
            is_branch=is_branch,
            is_call=is_call,
            is_jump=is_jump,
            is_return=is_return,
            target_address=target_address
        )
    
    def _classify_instruction(self, mnemonic: str) -> InstructionType:
        """Classify instruction by its mnemonic."""
        mnemonic = mnemonic.lower()
        
        # Arithmetic instructions
        arithmetic = ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg', 'adc', 'sbb']
        if any(mnemonic.startswith(op) for op in arithmetic):
            return InstructionType.ARITHMETIC
        
        # Logical instructions
        logical = ['and', 'or', 'xor', 'not', 'test', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror']
        if any(mnemonic.startswith(op) for op in logical):
            return InstructionType.LOGICAL
        
        # Data transfer instructions
        data_transfer = ['mov', 'lea', 'xchg', 'xlat', 'movsx', 'movzx']
        if any(mnemonic.startswith(op) for op in data_transfer):
            return InstructionType.DATA_TRANSFER
        
        # Control flow instructions
        control_flow = ['jmp', 'call', 'ret', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'loop']
        if any(mnemonic.startswith(op) for op in control_flow):
            return InstructionType.CONTROL_FLOW
        
        # Stack instructions
        stack = ['push', 'pop', 'pusha', 'popa', 'pushf', 'popf']
        if any(mnemonic.startswith(op) for op in stack):
            return InstructionType.STACK
        
        # System instructions
        system = ['int', 'syscall', 'sysenter', 'sysexit', 'iret', 'in', 'out']
        if any(mnemonic.startswith(op) for op in system):
            return InstructionType.SYSTEM
        
        # Floating point instructions
        float_ops = ['fadd', 'fsub', 'fmul', 'fdiv', 'fld', 'fst', 'fstp', 'fcom', 'fcomp']
        if any(mnemonic.startswith(op) for op in float_ops):
            return InstructionType.FLOAT
        
        # SIMD instructions
        simd = ['addpd', 'addps', 'addsd', 'addss', 'subpd', 'subps', 'subsd', 'subss', 'mulpd', 'mulps', 'mulsd', 'mulss', 'divpd', 'divps', 'divsd', 'divss']
        if any(mnemonic.startswith(op) for op in simd):
            return InstructionType.SIMD
        
        return InstructionType.OTHER
    
    def _section_contains_code(self, section) -> bool:
        """Check if a section likely contains code."""
        if not HAS_CAPSTONE:
            return False
        
        # Sample first 256 bytes of section for code detection
        sample_size = min(256, section.size)
        if sample_size <= 0:
            return False
        
        data = bytes(section.content[:sample_size])
        
        # Try to disassemble with Capstone
        cs = self.cs_x64 or self.cs_x86
        if not cs:
            # Initialize temporary disassembler
            cs = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
        
        try:
            # Count valid instructions
            valid_count = 0
            for instr in cs.disasm(data, section.virtual_address):
                if instr.size > 0:
                    valid_count += 1
            
            # If more than 50% of sampled bytes produce valid instructions, it's likely code
            return valid_count > (sample_size / 8)
        except:
            return False
    
    def _parse_pe_sections_manual(self) -> List[SectionInfo]:
        """Manually parse PE sections without LIEF."""
        sections = []
        
        try:
            # Parse PE headers manually
            # Find PE header offset
            if len(self.binary_data) < 0x40:
                return sections
            
            pe_offset = struct.unpack('<I', self.binary_data[0x3C:0x40])[0]
            if pe_offset + 0xF8 >= len(self.binary_data):
                return sections
            
            # Parse COFF header
            num_sections = struct.unpack('<H', self.binary_data[pe_offset + 6:pe_offset + 8])[0]
            
            # Parse section headers
            section_offset = pe_offset + 0x18 + struct.unpack('<H', self.binary_data[pe_offset + 0x14:pe_offset + 0x16])[0]
            
            for i in range(num_sections):
                sec_start = section_offset + i * 0x28
                if sec_start + 0x28 > len(self.binary_data):
                    break
                
                name = self.binary_data[sec_start:sec_start + 8].decode('ascii', errors='ignore').rstrip('\x00')
                virtual_size = struct.unpack('<I', self.binary_data[sec_start + 8:sec_start + 12])[0]
                virtual_address = struct.unpack('<I', self.binary_data[sec_start + 12:sec_start + 16])[0]
                size_raw = struct.unpack('<I', self.binary_data[sec_start + 16:sec_start + 20])[0]
                characteristics = struct.unpack('<I', self.binary_data[sec_start + 36:sec_start + 40])[0]
                
                is_executable = (characteristics & 0x20000000) != 0
                is_writable = (characteristics & 0x80000000) != 0
                is_readable = True  # Assume readable
                
                # Calculate entropy
                sec_data = self.binary_data[sec_start:sec_start + min(size_raw, 1024)]
                entropy = self._calculate_section_entropy(sec_data)
                
                section_info = SectionInfo(
                    name=name,
                    address=virtual_address,
                    size=size_raw,
                    virtual_size=virtual_size,
                    entropy=entropy,
                    is_executable=is_executable,
                    is_writable=is_writable,
                    is_readable=is_readable,
                    contains_code=is_executable
                )
                sections.append(section_info)
                
        except Exception as e:
            logger.warning(f"Manual PE parsing failed: {e}")
        
        return sections
    
    def _calculate_section_entropy(self, data):
        """Calculate entropy for a section."""
        from math import log2
        
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        frequencies = {}
        
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        for freq in frequencies.values():
            probability = freq / length
            if probability > 0:
                entropy -= probability * log2(probability)
        
        return entropy
    
    def _decompile_with_ghidra(self, function_address: int, function_name: str) -> Optional[str]:
        """Decompile using Ghidra (if available)."""
        # This is a placeholder for Ghidra integration
        # Actual implementation would require PyGhidra setup
        return None
    
    def _generate_pseudocode(self, function_address: int, function_name: str) -> str:
        """Generate high-level, structured C pseudocode with AST loops and branches."""
        arch = self._detect_architecture()
        instructions = self.disassemble_range(function_address, 1024, arch)
        
        if not instructions:
            return f"// Unable to disassemble function at 0x{function_address:x}\n"
        
        from core.decompilers.ast_restructurer import ASTControlFlowRestructurer
        symbols = {
            "iat": self.iat_symbols,
            "strings": self.string_symbols,
            "exports": self.export_symbols,
            "functions": self.function_symbols,
        }
        is_dll = self.binary_data[:2] == b'MZ' and bool(self.export_symbols)
        restructurer = ASTControlFlowRestructurer(symbols)
        return restructurer.restructure(instructions, function_address, function_name, is_dll=is_dll)


def analyze_native_binary(binary_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to analyze a native binary."""
    analyzer = NativeAnalyzer(binary_path)
    
    try:
        binary_info = analyzer.analyze()
        
        result = {
            "binary_info": asdict(binary_info),
            "capstone_available": HAS_CAPSTONE,
            "lief_available": HAS_LIEF,
            "ghidra_available": HAS_GHIDRA,
        }
        
        if output_dir:
            exported_files = analyzer.export_analysis(output_dir)
            result["exported_files"] = exported_files
        
        return result
    except Exception as e:
        logger.error(f"Failed to analyze binary: {e}")
        return {"error": str(e)}