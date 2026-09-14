"""File type detection module for binary analysis."""

import os
import magic
import pefile
import lief
from enum import Enum
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass


class BinaryType(Enum):
    """Binary file type enumeration."""
    UNKNOWN = "unknown"
    PE_EXE = "pe_exe"
    PE_DLL = "pe_dll"
    PE_DRIVER = "pe_driver"
    DOTNET = "dotnet"
    ELF = "elf"
    MACHO = "macho"
    RAW = "raw"


class Architecture(Enum):
    """CPU architecture enumeration."""
    UNKNOWN = "unknown"
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    POWERPC = "powerpc"


@dataclass
class BinaryInfo:
    """Binary file information container."""
    file_path: str
    file_size: int
    binary_type: BinaryType
    architecture: Architecture
    is_managed: bool = False
    is_packed: bool = False
    has_debug_info: bool = False
    imports: list = None
    exports: list = None
    sections: list = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.imports is None:
            self.imports = []
        if self.exports is None:
            self.exports = []
        if self.sections is None:
            self.sections = []
        if self.metadata is None:
            self.metadata = {}


class BinaryDetector:
    """Detects binary file type and extracts basic information."""
    
    def __init__(self):
        self.magic = magic.Magic(mime=True)
        
    def detect_file_type(self, file_path: str) -> BinaryInfo:
        """Detect the type of binary file and extract information."""
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        try:
            # First, try PE file detection
            binary_info = self._detect_pe_file(file_path, file_size)
            if binary_info.binary_type != BinaryType.UNKNOWN:
                return binary_info
                
            # Try ELF detection
            binary_info = self._detect_elf_file(file_path, file_size)
            if binary_info.binary_type != BinaryType.UNKNOWN:
                return binary_info
                
            # Fallback to magic detection
            return self._detect_by_magic(file_path, file_size)
            
        except Exception as e:
            # Return minimal info if detection fails
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=BinaryType.UNKNOWN,
                architecture=Architecture.UNKNOWN,
                metadata={"error": str(e)}
            )
    
    def _detect_pe_file(self, file_path: str, file_size: int) -> BinaryInfo:
        """Detect and analyze PE files."""
        try:
            pe = pefile.PE(file_path, fast_load=True)
            
            # Determine PE type
            if pe.is_dll():
                binary_type = BinaryType.PE_DLL
            elif pe.is_driver():
                binary_type = BinaryType.PE_DRIVER
            else:
                binary_type = BinaryType.PE_EXE
            
            # Determine architecture
            arch = self._get_pe_architecture(pe)
            
            # Check for .NET CLR
            is_managed = self._check_dotnet_clr(pe)
            
            # Extract basic info
            imports = self._extract_pe_imports(pe)
            exports = self._extract_pe_exports(pe)
            sections = self._extract_pe_sections(pe)
            
            metadata = {
                "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "image_base": pe.OPTIONAL_HEADER.ImageBase,
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            }
            
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=binary_type,
                architecture=arch,
                is_managed=is_managed,
                imports=imports,
                exports=exports,
                sections=sections,
                metadata=metadata
            )
            
        except Exception:
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=BinaryType.UNKNOWN,
                architecture=Architecture.UNKNOWN
            )
    
    def _detect_elf_file(self, file_path: str, file_size: int) -> BinaryInfo:
        """Detect and analyze ELF files."""
        try:
            binary = lief.parse(file_path)
            if not binary or not isinstance(binary, lief.ELF.Binary):
                return BinaryInfo(
                    file_path=file_path,
                    file_size=file_size,
                    binary_type=BinaryType.UNKNOWN,
                    architecture=Architecture.UNKNOWN
                )
            
            # ELF architecture detection
            arch = self._get_elf_architecture(binary)
            
            metadata = {
                "entry_point": binary.entrypoint,
                "type": str(binary.header.file_type),
                "machine_type": str(binary.header.machine_type),
                "has_symbols": len(binary.symbols) > 0,
                "has_debug": binary.has_debug,
            }
            
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=BinaryType.ELF,
                architecture=arch,
                metadata=metadata
            )
            
        except Exception:
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=BinaryType.UNKNOWN,
                architecture=Architecture.UNKNOWN
            )
    
    def _detect_by_magic(self, file_path: str, file_size: int) -> BinaryInfo:
        """Fallback detection using magic numbers."""
        try:
            mime_type = self.magic.from_file(file_path)
            
            binary_type = BinaryType.UNKNOWN
            if "application/x-dosexec" in mime_type:
                binary_type = BinaryType.PE_EXE
            elif "application/x-executable" in mime_type:
                binary_type = BinaryType.ELF
            elif "application/x-mach-binary" in mime_type:
                binary_type = BinaryType.MACHO
            
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=binary_type,
                architecture=Architecture.UNKNOWN,
                metadata={"mime_type": mime_type}
            )
        except Exception:
            return BinaryInfo(
                file_path=file_path,
                file_size=file_size,
                binary_type=BinaryType.RAW,
                architecture=Architecture.UNKNOWN
            )
    
    def _get_pe_architecture(self, pe: pefile.PE) -> Architecture:
        """Extract architecture from PE file."""
        machine = pe.FILE_HEADER.Machine
        
        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return Architecture.X86
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return Architecture.X64
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']:
            return Architecture.ARM
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
            return Architecture.ARM64
        else:
            return Architecture.UNKNOWN
    
    def _get_elf_architecture(self, elf: lief.ELF.Binary) -> Architecture:
        """Extract architecture from ELF file."""
        machine = elf.header.machine_type
        
        if machine == lief.ELF.ARCH.x86:
            return Architecture.X86
        elif machine == lief.ELF.ARCH.x86_64:
            return Architecture.X64
        elif machine == lief.ELF.ARCH.ARM:
            return Architecture.ARM
        elif machine == lief.ELF.ARCH.AARCH64:
            return Architecture.ARM64
        elif machine == lief.ELF.ARCH.MIPS:
            return Architecture.MIPS
        elif machine == lief.ELF.ARCH.PPC64:
            return Architecture.POWERPC
        else:
            return Architecture.UNKNOWN
    
    def _check_dotnet_clr(self, pe: pefile.PE) -> bool:
        """Check if PE file contains .NET CLR metadata."""
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if directory.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
                    return directory.VirtualAddress != 0
        return False
    
    def _extract_pe_imports(self, pe: pefile.PE) -> list:
        """Extract imported functions from PE file."""
        imports = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
                for func in entry.imports:
                    func_name = func.name.decode() if func.name and isinstance(func.name, bytes) else str(func.name)
                    imports.append({
                        "dll": dll_name,
                        "function": func_name,
                        "ordinal": func.ordinal if hasattr(func, 'ordinal') else None
                    })
        
        return imports
    
    def _extract_pe_exports(self, pe: pefile.PE) -> list:
        """Extract exported functions from PE file."""
        exports = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode() if exp.name and isinstance(exp.name, bytes) else str(exp.name)
                exports.append({
                    "name": exp_name,
                    "ordinal": exp.ordinal,
                    "address": exp.address
                })
        
        return exports
    
    def _extract_pe_sections(self, pe: pefile.PE) -> list:
        """Extract section information from PE file."""
        sections = []
        
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00') if isinstance(section.Name, bytes) else section.Name
            sections.append({
                "name": section_name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "entropy": section.get_entropy() if hasattr(section, 'get_entropy') else None
            })
        
        return sections