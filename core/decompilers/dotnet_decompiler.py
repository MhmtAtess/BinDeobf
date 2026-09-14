""".NET decompiler module using dnlib for assembly analysis."""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Try to import dnlib via pythonnet (clr)
HAS_DNLIB = False
try:
    import clr
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "dnlib.dll"),
        os.path.join(os.path.dirname(__file__), "..", "..", "dnlib.dll"),
        os.path.join(os.path.dirname(__file__), "..", "..", "libs", "dnlib.dll"),
        os.path.join(os.getcwd(), "dnlib.dll"),
    ]
    loaded = False
    for p in possible_paths:
        abs_p = os.path.abspath(p)
        if os.path.exists(abs_p):
            try:
                clr.AddReference(abs_p)
                loaded = True
                break
            except Exception:
                pass
    if not loaded:
        try:
            clr.AddReference("dnlib")
            loaded = True
        except Exception:
            pass

    import dnlib
    from dnlib.DotNet import ModuleDef, AssemblyDef, TypeDef, MethodDef, FieldDef, PropertyDef
    from dnlib.DotNet.Emit import OpCode, Instruction
    HAS_DNLIB = True
except Exception as e:
    HAS_DNLIB = False
    dnlib = None
    ModuleDef = AssemblyDef = TypeDef = MethodDef = FieldDef = PropertyDef = Any
    OpCode = Instruction = Any
    logger.warning(f"dnlib not available: {e}")

# Try to import ICSharpCode.Decompiler for advanced decompilation
HAS_DECOMPILER = False
try:
    import clr
    from System.Globalization import CultureInfo
    from System.Threading import Thread
    # Enforce InvariantCulture to prevent Turkish I/ı locale bugs in identifiers (e.g. ıntPtr -> intPtr)
    Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture
    Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture

    decompiler_dlls = [
        "System.Collections.Immutable.dll",
        "System.Reflection.Metadata.dll",
        "ICSharpCode.Decompiler.dll"
    ]
    for dll_name in decompiler_dlls:
        for p in [
            os.path.join(os.path.dirname(__file__), dll_name),
            os.path.join(os.path.dirname(__file__), "..", "..", dll_name),
            os.path.join(os.getcwd(), dll_name)
        ]:
            abs_dll = os.path.abspath(p)
            if os.path.exists(abs_dll):
                try:
                    clr.AddReference(abs_dll)
                    break
                except Exception:
                    pass
        else:
            try:
                clr.AddReference(dll_name.replace(".dll", ""))
            except Exception:
                pass

    from ICSharpCode.Decompiler import DecompilerSettings
    from ICSharpCode.Decompiler.CSharp import CSharpDecompiler
    HAS_DECOMPILER = True
except Exception as e:
    HAS_DECOMPILER = False
    logger.warning(f"ICSharpCode.Decompiler not available: {e}")


@dataclass
class DotNetTypeInfo:
    """Information about a .NET type."""
    name: str
    namespace: str
    full_name: str
    is_public: bool
    is_abstract: bool
    is_sealed: bool
    is_interface: bool
    is_enum: bool
    base_type: Optional[str]
    methods: List[Dict[str, Any]]
    fields: List[Dict[str, Any]]
    properties: List[Dict[str, Any]]
    nested_types: List[str]


@dataclass
class DotNetMethodInfo:
    """Information about a .NET method."""
    name: str
    return_type: str
    parameters: List[Dict[str, str]]
    is_public: bool
    is_private: bool
    is_static: bool
    is_virtual: bool
    is_abstract: bool
    attributes: List[str]
    il_instructions: Optional[List[Dict[str, Any]]] = None


@dataclass
class DotNetAssemblyInfo:
    """Information about a .NET assembly."""
    name: str
    version: str
    culture: str
    public_key_token: Optional[str]
    architecture: str
    target_framework: str
    types: List[DotNetTypeInfo]
    references: List[str]
    resources: List[Dict[str, Any]]
    entry_point: Optional[str]


class DotNetDecompiler:
    """.NET assembly decompiler and analyzer."""
    
    def __init__(self, assembly_path: str):
        self.assembly_path = assembly_path
        self.module: Optional[ModuleDef] = None
        self.assembly_info: Optional[DotNetAssemblyInfo] = None
        
        # Initialize decompiler if available
        self.decompiler = None
        if HAS_DECOMPILER:
            try:
                abs_path = os.path.abspath(self.assembly_path)
                self.decompiler = CSharpDecompiler(abs_path, DecompilerSettings())
            except Exception as e:
                logger.warning(f"Failed to initialize C# decompiler: {e}")
    
    def load(self) -> bool:
        """Load the .NET assembly for analysis."""
        if not HAS_DNLIB or dnlib is None:
            logger.error("dnlib is not available.")
            return False
        try:
            self.module = dnlib.DotNet.ModuleDefMD.Load(self.assembly_path)
            return True
        except Exception as e:
            logger.error(f"Failed to load .NET assembly: {e}")
            return False
    
    def analyze(self) -> DotNetAssemblyInfo:
        """Analyze the loaded .NET assembly."""
        if not self.module:
            raise RuntimeError("Assembly not loaded. Call load() first.")
        
        # Extract assembly info
        assembly_def = self.module.Assembly
        assembly_name = str(assembly_def.Name) if assembly_def else "Unknown"
        version = str(assembly_def.Version) if assembly_def else "0.0.0.0"
        
        # Extract types
        types_info = []
        for type_def in self.module.GetTypes():
            if type_def.FullName.startswith("<Module>"):
                continue
                
            type_info = self._extract_type_info(type_def)
            types_info.append(type_info)
        
        # Extract references
        references = []
        for asm_ref in self.module.GetAssemblyRefs():
            references.append(str(asm_ref))
        
        # Extract resources
        resources = []
        for resource in self.module.Resources:
            resource_info = {
                "name": str(resource.Name),
                "type": type(resource).__name__,
                "size": len(resource.Data) if hasattr(resource, 'Data') else 0
            }
            resources.append(resource_info)
        
        # Determine architecture and framework
        architecture = self._detect_architecture()
        target_framework = self._detect_target_framework()
        
        # Find entry point
        entry_point = None
        if self.module.EntryPoint:
            entry_point = str(self.module.EntryPoint)
        
        self.assembly_info = DotNetAssemblyInfo(
            name=assembly_name,
            version=version,
            culture="neutral",  # Default
            public_key_token=None,
            architecture=architecture,
            target_framework=target_framework,
            types=types_info,
            references=references,
            resources=resources,
            entry_point=entry_point
        )
        
        return self.assembly_info
    
    def decompile_method(self, method_full_name: str) -> Optional[str]:
        """Decompile a specific method to C# source code."""
        if not self.decompiler:
            logger.warning("C# decompiler not available")
            return None
        
        try:
            # Find the method in the assembly
            for type_def in self.module.GetTypes():
                for method_def in type_def.Methods:
                    if str(method_def) == method_full_name:
                        # Use ICSharpCode.Decompiler to decompile
                        return self.decompiler.DecompileMethodAsString(method_def.MDToken.ToUInt32())
        except Exception as e:
            logger.error(f"Failed to decompile method {method_full_name}: {e}")
        
        return None
    
    def decompile_type(self, type_full_name: str) -> Optional[str]:
        """Decompile a specific type to C# source code."""
        if not self.decompiler:
            logger.warning("C# decompiler not available")
            return None
        
        try:
            # Find the type in the assembly
            for type_def in self.module.GetTypes():
                if str(type_def) == type_full_name:
                    # Use ICSharpCode.Decompiler to decompile
                    return self.decompiler.DecompileTypeAsString(type_def.MDToken.ToUInt32())
        except Exception as e:
            logger.error(f"Failed to decompile type {type_full_name}: {e}")
        
        return None
    
    def export_source_code(self, output_dir: str) -> Dict[str, str]:
        """Export decompiled C# source code to files."""
        if not self.decompiler:
            logger.warning("C# decompiler not available")
            return {}
        
        os.makedirs(output_dir, exist_ok=True)
        exported_files = {}
        
        try:
            # 1. Export whole module C# source code
            try:
                full_source = self.decompiler.DecompileWholeModuleAsString()
                if full_source:
                    full_source_path = os.path.join(output_dir, "FullSource.cs")
                    with open(full_source_path, 'w', encoding='utf-8') as f:
                        f.write(full_source)
                    exported_files["FullSource.cs"] = full_source_path
            except Exception as e:
                logger.warning(f"Failed to decompile module source code: {e}")
            
            # Create a solution/project file structure
            self._create_project_structure(output_dir, exported_files)
            
        except Exception as e:
            logger.error(f"Failed to export source code: {e}")
        
        return exported_files
    
    def _extract_type_info(self, type_def: TypeDef) -> DotNetTypeInfo:
        """Extract information from a .NET type definition."""
        methods_info = []
        for method_def in type_def.Methods:
            methods_info.append(self._extract_method_info(method_def))
        
        fields_info = []
        for field_def in type_def.Fields:
            fields_info.append({
                "name": str(field_def.Name),
                "type": str(field_def.FieldType),
                "is_public": field_def.IsPublic,
                "is_static": field_def.IsStatic,
                "is_literal": field_def.IsLiteral,
                "default_value": str(field_def.Constant) if field_def.Constant else None
            })
        
        properties_info = []
        for prop_def in type_def.Properties:
            properties_info.append({
                "name": str(prop_def.Name),
                "type": str(prop_def.PropertySig.RetType),
                "getter": str(prop_def.GetMethod) if prop_def.GetMethod else None,
                "setter": str(prop_def.SetMethod) if prop_def.SetMethod else None
            })
        
        nested_types = [str(nested.FullName) for nested in type_def.NestedTypes]
        
        return DotNetTypeInfo(
            name=str(type_def.Name),
            namespace=str(type_def.Namespace),
            full_name=str(type_def.FullName),
            is_public=type_def.IsPublic,
            is_abstract=type_def.IsAbstract,
            is_sealed=type_def.IsSealed,
            is_interface=type_def.IsInterface,
            is_enum=type_def.IsEnum,
            base_type=str(type_def.BaseType) if type_def.BaseType else None,
            methods=methods_info,
            fields=fields_info,
            properties=properties_info,
            nested_types=nested_types
        )
    
    def _extract_method_info(self, method_def: MethodDef) -> Dict[str, Any]:
        """Extract information from a .NET method definition."""
        parameters = []
        try:
            if method_def.MethodSig and hasattr(method_def.MethodSig, 'Params'):
                for i, param in enumerate(method_def.MethodSig.Params):
                    parameters.append({
                        "index": i,
                        "type": str(param),
                        "name": f"param_{i}"
                    })
            elif hasattr(method_def, 'Parameters'):
                for i, param in enumerate(method_def.Parameters):
                    parameters.append({
                        "index": i,
                        "type": str(getattr(param, 'Type', str(param))),
                        "name": str(getattr(param, 'Name', f"param_{i}"))
                    })
        except Exception:
            pass
        
        il_instructions = None
        if method_def.HasBody and method_def.Body.HasInstructions:
            il_instructions = []
            for instr in method_def.Body.Instructions:
                il_instructions.append({
                    "offset": instr.Offset,
                    "opcode": str(instr.OpCode),
                    "operand": str(instr.Operand) if instr.Operand else None
                })
        
        return {
            "name": str(method_def.Name),
            "full_name": str(method_def),
            "return_type": str(method_def.ReturnType) if method_def.ReturnType else "void",
            "parameters": parameters,
            "is_public": method_def.IsPublic,
            "is_private": method_def.IsPrivate,
            "is_static": method_def.IsStatic,
            "is_virtual": method_def.IsVirtual,
            "is_abstract": method_def.IsAbstract,
            "attributes": [str(attr) for attr in method_def.CustomAttributes],
            "il_instructions": il_instructions
        }
    
    def _detect_architecture(self) -> str:
        """Detect the assembly architecture."""
        if not self.module:
            return "Unknown"
        
        try:
            if getattr(self.module, 'IsAMD64', False):
                return "x64"
            elif getattr(self.module, 'IsI386', False):
                return "x86"
            elif getattr(self.module, 'IsARM64', False):
                return "ARM64"
            elif getattr(self.module, 'IsARM', False):
                return "ARM"
            elif getattr(self.module, 'IsIA64', False):
                return "IA64"
            else:
                return "AnyCPU"
        except Exception:
            return "Unknown"
    
    def _detect_target_framework(self) -> str:
        """Detect the target .NET framework."""
        if not self.module:
            return "Unknown"
        
        # Check assembly attributes for framework version
        for attr in self.module.CustomAttributes:
            attr_str = str(attr)
            if "TargetFrameworkAttribute" in attr_str:
                # Extract framework version from attribute
                import re
                match = re.search(r'\.NET(?:Core)?(?:Framework)?,Version=v([\d.]+)', attr_str)
                if match:
                    return f".NET {match.group(1)}"
        
        return ".NET Framework (Unknown Version)"
    
    def _create_project_structure(self, output_dir: str, exported_files: Dict[str, str]):
        """Create basic project structure files."""
        # Create a simple csproj file
        csproj_content = """<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net461</TargetFramework>
    <LangVersion>latest</LangVersion>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
  </PropertyGroup>
</Project>
"""
        csproj_path = os.path.join(output_dir, "Decompiled.csproj")
        with open(csproj_path, 'w', encoding='utf-8') as f:
            f.write(csproj_content)
    
    def generate_report(self, output_path: str) -> bool:
        """Generate a JSON report of the assembly analysis."""
        if not self.assembly_info:
            raise RuntimeError("Assembly not analyzed. Call analyze() first.")
        
        try:
            # Convert dataclass to dict
            report_dict = asdict(self.assembly_info)
            
            # Write to JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, default=str)
            
            return True
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False


def analyze_dotnet_assembly(assembly_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to analyze a .NET assembly."""
    decompiler = DotNetDecompiler(assembly_path)
    
    if not decompiler.load():
        return {"error": "Failed to load assembly"}
    
    assembly_info = decompiler.analyze()
    
    result = {
        "assembly_info": asdict(assembly_info),
        "decompilation_available": HAS_DECOMPILER
    }
    
    if output_dir and HAS_DECOMPILER:
        exported_files = decompiler.export_source_code(output_dir)
        result["exported_files"] = exported_files
    
    return result