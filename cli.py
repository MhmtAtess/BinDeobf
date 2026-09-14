"""Command Line Interface for Binary Deobfuscator."""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

# Import core modules
from core.detectors import BinaryDetector, BinaryType
from core.decompilers.dotnet_decompiler import DotNetDecompiler, analyze_dotnet_assembly
from core.decompilers.native_analyzer import NativeAnalyzer, analyze_native_binary
from core.decompilers.python_deobfuscator import PythonDeobfuscator
from core.exporters.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Typer app
app = typer.Typer(
    name="BinDeobf",
    help="BinDeobf - Advanced binary analysis and decompilation tool",
    add_completion=False
)


# Ensure UTF-8 output encoding for Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Initialize console for rich output
console = Console(force_terminal=True, legacy_windows=False)


def print_banner():
    """Print application banner."""
    banner = (
        "+----------------------------------------------------------+\n"
        "|                        #BINDEOBF                         |\n"
        "|           Gelişmiş Binary Deobfuscator & Analyzer        |\n"
        "+----------------------------------------------------------+"
    )
    try:
        console.print(Panel(banner, style="bold blue"))
    except Exception:
        print(banner)


@app.command()
def analyze(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory for reports (default: output)"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, yaml, html, md, all"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output")
):
    """
    Analyze a binary file (detect type, architecture, imports/exports).
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print_banner()
    
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Analyzing file:[/bold] {file_path}")
    console.print(f"[bold]File size:[/bold] {file_path.stat().st_size:,} bytes")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # Step 1: Detect file type
        task1 = progress.add_task("[cyan]Detecting file type...", total=1)
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(str(file_path))
        progress.update(task1, advance=1)
        
        # Step 2: Analyze based on type
        task2 = progress.add_task("[cyan]Analyzing binary...", total=1)
        
        analysis_results = {}
        
        if binary_info.is_managed:
            console.print("[green]Detected:[/green] .NET Managed Binary")
            # Analyze .NET assembly
            decompiler = DotNetDecompiler(str(file_path))
            if decompiler.load():
                assembly_info = decompiler.analyze()
                analysis_results = {
                    "assembly_info": assembly_info,
                    "binary_info": binary_info
                }
            else:
                console.print("[red]Failed to load .NET assembly[/red]")
        else:
            console.print("[yellow]Detected:[/yellow] Native Binary")
            # Analyze native binary
            analyzer = NativeAnalyzer(str(file_path))
            binary_info = analyzer.analyze()
            analysis_results = {
                "binary_info": binary_info
            }
        
        progress.update(task2, advance=1)
        
        # Step 3: Generate report automatically to output directory
        report_files = {}
        if output_dir:
            task3 = progress.add_task("[cyan]Generating report...", total=1)
            out_path = Path(output_dir).resolve()
            out_path.mkdir(parents=True, exist_ok=True)
            
            report_gen = ReportGenerator(analysis_results)
            prefix = file_path.stem
            
            if format == "json":
                report_file = out_path / f"{prefix}_report.json"
                if report_gen.generate_json_report(str(report_file)):
                    report_files["json"] = str(report_file)
            elif format == "yaml":
                report_file = out_path / f"{prefix}_report.yaml"
                if report_gen.generate_yaml_report(str(report_file)):
                    report_files["yaml"] = str(report_file)
            elif format == "html":
                report_file = out_path / f"{prefix}_report.html"
                if report_gen.generate_html_report(str(report_file)):
                    report_files["html"] = str(report_file)
            elif format == "md":
                report_file = out_path / f"{prefix}_report.md"
                if report_gen.generate_markdown_report(str(report_file)):
                    report_files["markdown"] = str(report_file)
            elif format == "all":
                report_files = report_gen.export_all_formats(str(out_path), prefix=prefix)
            else:
                report_file = out_path / f"{prefix}_report.json"
                if report_gen.generate_json_report(str(report_file)):
                    report_files["json"] = str(report_file)
            
            progress.update(task3, advance=1)
        
        # Display summary
        console.print("\n[bold green]Analysis Complete![/bold green]")
        console.print(f"[bold]Binary Type:[/bold] {binary_info.binary_type.value}")
        console.print(f"[bold]Architecture:[/bold] {binary_info.architecture.value}")
        console.print(f"[bold]Managed:[/bold] {'Yes' if binary_info.is_managed else 'No'}")
        
        if binary_info.imports:
            console.print(f"[bold]Imports:[/bold] {len(binary_info.imports)} functions")
        
        if binary_info.exports:
            console.print(f"[bold]Exports:[/bold] {len(binary_info.exports)} functions")
        
        if binary_info.sections:
            console.print(f"[bold]Sections:[/bold] {len(binary_info.sections)} sections")
        
        if report_files:
            console.print(f"\n[bold green]Reports automatically saved to:[/bold green] {output_dir}")
            for fmt, path in report_files.items():
                console.print(f"  • {fmt.upper()}: {path}")


@app.command()
def decompile(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory for source code (default: output)"),
    force: bool = typer.Option(False, "--force", "-f", help="Force decompilation even if detection fails"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output")
):
    """
    Decompile binary file to source code (.NET to C#, Native to pseudocode).
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print_banner()
    
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Decompiling file:[/bold] {file_path}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # Step 1: Detect file type
        task1 = progress.add_task("[cyan]Detecting file type...", total=1)
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(str(file_path))
        progress.update(task1, advance=1)
        
        # Step 2: Decompile based on type
        task2 = progress.add_task("[cyan]Decompiling...", total=1)
        
        target_out_dir = Path(output_dir).resolve() / f"{file_path.stem}_decompiled"
        target_out_dir.mkdir(parents=True, exist_ok=True)
        
        if file_path.suffix.lower() in ['.py', '.pyc', '.pyw']:
            console.print("[green]Deobfuscating and decompiling Python script...[/green]")
            py_deobf = PythonDeobfuscator(str(file_path))
            exported_files = py_deobf.deobfuscate(str(target_out_dir))
            
            console.print(f"[green]Python deobfuscation complete![/green]")
            console.print(f"[bold green]Output directory:[/bold green] {target_out_dir}")
            if exported_files:
                console.print(f"[bold]Exported files:[/bold]")
                for file_type, file_path_item in exported_files.items():
                    console.print(f"  • {file_type}: {file_path_item}")
        
        elif binary_info.is_managed or force:
            console.print("[green]Decompiling .NET assembly to C#...[/green]")
            
            decompiler = DotNetDecompiler(str(file_path))
            if decompiler.load():
                decompiler.analyze()
                exported_files = decompiler.export_source_code(str(target_out_dir))
                
                console.print(f"[green]Decompilation complete![/green]")
                console.print(f"[bold green]Output directory:[/bold green] {target_out_dir}")
                
                if exported_files:
                    console.print(f"[bold]Exported files:[/bold] {len(exported_files)}")
                    for type_name, file_path_item in list(exported_files.items())[:5]:
                        console.print(f"  • {type_name}")
                    
                    if len(exported_files) > 5:
                        console.print(f"  ... and {len(exported_files) - 5} more")
            else:
                console.print("[red]Failed to load .NET assembly for decompilation[/red]")
        
        else:
            console.print("[yellow]Decompiling native binary to pseudocode...[/yellow]")
            
            analyzer = NativeAnalyzer(str(file_path))
            analyzer.analyze()
            exported_files = analyzer.export_analysis(str(target_out_dir))
            
            console.print(f"[green]Analysis complete![/green]")
            console.print(f"[bold green]Output directory:[/bold green] {target_out_dir}")
            
            if exported_files:
                console.print(f"[bold]Exported files:[/bold]")
                for file_type, file_path_item in exported_files.items():
                    console.print(f"  • {file_type}: {file_path_item}")
        
        progress.update(task2, advance=1)


@app.command()
def detect(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed information"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory (default: output)")
):
    """
    Detect binary file type and show basic information.
    """
    print_banner()
    
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Analyzing file:[/bold] {file_path}")
    
    detector = BinaryDetector()
    binary_info = detector.detect_file_type(str(file_path))
    
    # Create table for basic info
    table = Table(title="Binary File Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("File Path", str(file_path))
    table.add_row("File Size", f"{file_path.stat().st_size:,} bytes")
    table.add_row("Binary Type", binary_info.binary_type.value)
    table.add_row("Architecture", binary_info.architecture.value)
    table.add_row("Managed (.NET)", "Yes" if binary_info.is_managed else "No")
    table.add_row("Packed", "Yes" if binary_info.is_packed else "No")
    table.add_row("Debug Info", "Yes" if binary_info.has_debug_info else "No")
    
    console.print(table)
    
    # Auto-save detect results to output directory
    try:
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        detect_file = out_path / f"{file_path.stem}_detect.json"
        
        detect_data = {
            "file_path": str(file_path),
            "file_size": file_path.stat().st_size,
            "binary_type": binary_info.binary_type.value,
            "architecture": binary_info.architecture.value,
            "is_managed": binary_info.is_managed,
            "is_packed": binary_info.is_packed,
            "has_debug_info": binary_info.has_debug_info,
            "imports_count": len(binary_info.imports) if binary_info.imports else 0,
            "exports_count": len(binary_info.exports) if binary_info.exports else 0,
            "sections_count": len(binary_info.sections) if binary_info.sections else 0,
        }
        with open(detect_file, 'w', encoding='utf-8') as f:
            json.dump(detect_data, f, indent=2)
        console.print(f"[bold green]Detection saved to:[/bold green] {detect_file}")
    except Exception:
        pass
    
    if detailed:
        # Show sections
        if binary_info.sections:
            sections_table = Table(title="Sections")
            sections_table.add_column("Name", style="cyan")
            sections_table.add_column("VA", style="green")
            sections_table.add_column("Size", style="yellow")
            sections_table.add_column("Entropy", style="magenta")
            
            for section in binary_info.sections:
                sections_table.add_row(
                    section["name"],
                    f"0x{section['virtual_address']:x}",
                    f"{section['raw_size']:,} bytes",
                    f"{section.get('entropy', 0):.3f}" if section.get('entropy') else "N/A"
                )
            
            console.print(sections_table)
        
        # Show imports
        if binary_info.imports:
            imports_table = Table(title=f"Imports ({len(binary_info.imports)})")
            imports_table.add_column("DLL", style="cyan")
            imports_table.add_column("Function", style="green")
            imports_table.add_column("Ordinal", style="yellow")
            
            for imp in binary_info.imports[:10]:  # Show first 10
                imports_table.add_row(
                    imp["dll"],
                    imp["function"],
                    str(imp["ordinal"]) if imp["ordinal"] else "N/A"
                )
            
            if len(binary_info.imports) > 10:
                imports_table.add_row("...", f"... and {len(binary_info.imports) - 10} more", "...")
            
            console.print(imports_table)
        
        # Show exports
        if binary_info.exports:
            exports_table = Table(title=f"Exports ({len(binary_info.exports)})")
            exports_table.add_column("Name", style="cyan")
            exports_table.add_column("Address", style="green")
            exports_table.add_column("Ordinal", style="yellow")
            
            for exp in binary_info.exports[:10]:  # Show first 10
                exports_table.add_row(
                    exp["name"],
                    f"0x{exp['address']:x}",
                    str(exp["ordinal"])
                )
            
            if len(binary_info.exports) > 10:
                exports_table.add_row("...", f"... and {len(binary_info.exports) - 10} more", "...")
            
            console.print(exports_table)
        
        # Show metadata
        if binary_info.metadata:
            metadata_table = Table(title="Metadata")
            metadata_table.add_column("Key", style="cyan")
            metadata_table.add_column("Value", style="green")
            
            for key, value in binary_info.metadata.items():
                metadata_table.add_row(key, str(value))
            
            console.print(metadata_table)


@app.command()
def exports(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory (default: output)")
):
    """
    List exported functions from binary file.
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    detector = BinaryDetector()
    binary_info = detector.detect_file_type(str(file_path))
    
    if not binary_info.exports:
        console.print("[yellow]No exports found in the binary[/yellow]")
        return
    
    # Auto-save exports to output folder
    try:
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        exp_file = out_path / f"{file_path.stem}_exports.json"
        with open(exp_file, 'w', encoding='utf-8') as f:
            json.dump(binary_info.exports, f, indent=2)
    except Exception:
        pass
    
    if format == "json":
        console.print(json.dumps(binary_info.exports, indent=2))
    elif format == "csv":
        import csv
        import sys
        
        writer = csv.writer(sys.stdout)
        writer.writerow(["Name", "Address", "Ordinal"])
        for exp in binary_info.exports:
            writer.writerow([exp["name"], f"0x{exp['address']:x}", exp["ordinal"]])
    else:
        table = Table(title=f"Exported Functions ({len(binary_info.exports)})")
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Ordinal", style="yellow")
        
        for exp in binary_info.exports:
            table.add_row(
                exp["name"],
                f"0x{exp['address']:x}",
                str(exp["ordinal"])
            )
        
        console.print(table)
    
    console.print(f"[bold green]Exports automatically saved to:[/bold green] {output_dir}/{file_path.stem}_exports.json")


@app.command()
def imports(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory (default: output)")
):
    """
    List imported functions from binary file.
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    detector = BinaryDetector()
    binary_info = detector.detect_file_type(str(file_path))
    
    if not binary_info.imports:
        console.print("[yellow]No imports found in the binary[/yellow]")
        return
    
    # Auto-save imports to output folder
    try:
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        imp_file = out_path / f"{file_path.stem}_imports.json"
        with open(imp_file, 'w', encoding='utf-8') as f:
            json.dump(binary_info.imports, f, indent=2)
    except Exception:
        pass
    
    if format == "json":
        console.print(json.dumps(binary_info.imports, indent=2))
    elif format == "csv":
        import csv
        import sys
        
        writer = csv.writer(sys.stdout)
        writer.writerow(["DLL", "Function", "Ordinal"])
        for imp in binary_info.imports:
            writer.writerow([imp["dll"], imp["function"], imp["ordinal"] or ""])
    else:
        table = Table(title=f"Imported Functions ({len(binary_info.imports)})")
        table.add_column("DLL", style="cyan")
        table.add_column("Function", style="green")
        table.add_column("Ordinal", style="yellow")
        
        for imp in binary_info.imports[:50]:  # Limit to 50 imports
            table.add_row(
                imp["dll"],
                imp["function"],
                str(imp["ordinal"]) if imp["ordinal"] else "N/A"
            )
        
        if len(binary_info.imports) > 50:
            table.add_row("...", f"... and {len(binary_info.imports) - 50} more", "...")
        
        console.print(table)
    
    console.print(f"[bold green]Imports automatically saved to:[/bold green] {output_dir}/{file_path.stem}_imports.json")


@app.command()
def strings(
    file_path: str = typer.Argument(..., help="Path to binary file"),
    min_length: int = typer.Option(4, "--min-length", "-m", help="Minimum string length"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for strings (default: output/<file>_strings.txt)"),
    encoding: str = typer.Option("ascii", "--encoding", "-e", help="String encoding: ascii, utf8, utf16")
):
    """
    Extract strings from binary file.
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Extracting strings from:[/bold] {file_path}")
    console.print(f"[bold]Minimum length:[/bold] {min_length} characters")
    
    # Read binary file
    with open(file_path, 'rb') as f:
        binary_data = f.read()
    
    strings_list = []
    current_string = ""
    current_address = 0
    
    if encoding == "utf16":
        # Decode as UTF-16LE
        try:
            decoded = binary_data.decode('utf-16le', errors='ignore')
            for i, char in enumerate(decoded):
                if 32 <= ord(char) <= 126 or char in '\n\r\t':
                    if not current_string:
                        current_address = i * 2
                    current_string += char
                else:
                    if len(current_string) >= min_length:
                        strings_list.append({
                            "address": current_address,
                            "string": current_string,
                            "length": len(current_string)
                        })
                    current_string = ""
        except Exception:
            console.print("[red]Failed to decode as UTF-16[/red]")
    else:
        # ASCII/UTF-8 extraction
        for i, byte in enumerate(binary_data):
            if 32 <= byte <= 126:
                if not current_string:
                    current_address = i
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings_list.append({
                        "address": current_address,
                        "string": current_string,
                        "length": len(current_string)
                    })
                current_string = ""
    
    # Add last string if any
    if len(current_string) >= min_length:
        strings_list.append({
            "address": current_address,
            "string": current_string,
            "length": len(current_string)
        })
    
    console.print(f"[bold]Found {len(strings_list)} strings[/bold]")
    
    # Auto-save strings to output folder if output_file not given
    if not output_file:
        out_dir = Path("output").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / f"{file_path.stem}_strings.txt"
    else:
        output_path = Path(output_file).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for string_info in strings_list:
                f.write(f"0x{string_info['address']:x}: {string_info['string']}\n")
        console.print(f"[bold green]Strings automatically saved to:[/bold green] {output_path}")
    except Exception as e:
        console.print(f"[yellow]Could not save strings file: {e}[/yellow]")
    
    # Display sample strings in table
    if strings_list:
        table = Table(title=f"Extracted Strings Sample ({len(strings_list)} total)")
        table.add_column("Address", style="cyan")
        table.add_column("String", style="green")
        table.add_column("Length", style="yellow")
        
        for string_info in strings_list[:20]:  # Show first 20
            string = string_info["string"]
            if len(string) > 50:
                string = string[:47] + "..."
            table.add_row(
                f"0x{string_info['address']:x}",
                string,
                str(string_info["length"])
            )
        
        if len(strings_list) > 20:
            table.add_row("...", f"... and {len(strings_list) - 20} more strings (all saved to file)", "...")
        
        console.print(table)


@app.command()
def version():
    """
    Show tool version information.
    """
    print_banner()
    console.print("[bold]BinDeobf v1.0.0[/bold]")
    console.print("[dim]Advanced binary analysis and decompilation tool[/dim]")
    console.print("[dim]Supports .NET and Native binary analysis[/dim]")


def main():
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            import traceback
            traceback.print_exc()
        raise typer.Exit(1)


if __name__ == "__main__":
    main()