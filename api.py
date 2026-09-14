"""REST API for Binary Deobfuscator using FastAPI."""

import os
import json
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Import core modules
from core.detectors import BinaryDetector, BinaryInfo
from core.decompilers.dotnet_decompiler import DotNetDecompiler, analyze_dotnet_assembly
from core.decompilers.native_analyzer import NativeAnalyzer, analyze_native_binary
from core.exporters.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="BinDeobf API",
    description="REST API for binary analysis and decompilation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class AnalysisRequest(BaseModel):
    """Analysis request model."""
    file_path: Optional[str] = None
    output_format: str = Field(default="json", pattern="^(json|yaml|html|md)$")
    detailed: bool = False

class DecompileRequest(BaseModel):
    """Decompilation request model."""
    file_path: Optional[str] = None
    output_dir: Optional[str] = None
    force: bool = False

class DetectionResponse(BaseModel):
    """Binary detection response model."""
    file_path: str
    file_size: int
    binary_type: str
    architecture: str
    is_managed: bool
    is_packed: bool
    has_debug_info: bool
    imports_count: int
    exports_count: int
    sections_count: int
    metadata: Dict[str, Any]

class AnalysisResponse(BaseModel):
    """Analysis response model."""
    success: bool
    analysis_id: str
    timestamp: str
    binary_info: Dict[str, Any]
    report_path: Optional[str] = None
    error: Optional[str] = None

class DecompileResponse(BaseModel):
    """Decompilation response model."""
    success: bool
    decompilation_id: str
    timestamp: str
    output_dir: str
    exported_files: Dict[str, str]
    error: Optional[str] = None

# Global state for tracking analysis jobs
analysis_jobs: Dict[str, Dict[str, Any]] = {}

# Temporary directory for uploaded files
TEMP_DIR = Path(tempfile.gettempdir()) / "binary_deobfuscator"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with API information."""
    html_content = """
    <html>
        <head>
            <title>Binary Deobfuscator API</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 {
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                .endpoint {
                    background: #f8f9fa;
                    padding: 15px;
                    margin: 15px 0;
                    border-radius: 5px;
                    border-left: 4px solid #3498db;
                }
                .method {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-weight: bold;
                    font-size: 0.9em;
                    margin-right: 10px;
                }
                .get { background: #61affe; color: white; }
                .post { background: #49cc90; color: white; }
                .put { background: #fca130; color: white; }
                .delete { background: #f93e3e; color: white; }
                code {
                    background: #2d3748;
                    color: #e2e8f0;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Binary Deobfuscator API</h1>
                <p>REST API for binary analysis and decompilation of .NET and native binaries.</p>
                
                <h2>📋 Available Endpoints</h2>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/health</strong> - Check API health
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/detect/{file_path}</strong> - Detect binary file type
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <strong>/api/upload/detect</strong> - Upload and detect binary file
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/analyze/{file_path}</strong> - Analyze binary file
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <strong>/api/upload/analyze</strong> - Upload and analyze binary file
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/decompile/{file_path}</strong> - Decompile binary file
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <strong>/api/upload/decompile</strong> - Upload and decompile binary file
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/jobs/{job_id}</strong> - Get analysis job status
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <strong>/api/report/{report_path}</strong> - Download analysis report
                </div>
                
                <h2>🔧 Usage Examples</h2>
                
                <h3>cURL Examples:</h3>
                <pre><code># Detect binary type
curl -X POST -F "file=@target.exe" http://localhost:8000/api/upload/detect

# Analyze binary
curl -X POST -F "file=@target.exe" -F "output_format=json" http://localhost:8000/api/upload/analyze

# Decompile .NET assembly
curl -X POST -F "file=@target.dll" http://localhost:8000/api/upload/decompile</code></pre>
                
                <h2>📚 Documentation</h2>
                <p>Visit <a href="/docs">/docs</a> for interactive API documentation (Swagger UI)</p>
                <p>Visit <a href="/redoc">/redoc</a> for alternative API documentation</p>
                
                <h2>⚙️ Configuration</h2>
                <p><strong>Host:</strong> localhost:8000</p>
                <p><strong>Version:</strong> 1.0.0</p>
                <p><strong>Supported Formats:</strong> .NET assemblies (C#), Native binaries (x86/x64)</p>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/health")
async def health_check():
    """Check API health status."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "temp_dir": str(TEMP_DIR),
        "jobs_count": len(analysis_jobs)
    }


@app.get("/api/detect/{file_path:path}")
async def detect_binary(file_path: str):
    """Detect binary file type and basic information."""
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(str(path))
        
        response = DetectionResponse(
            file_path=str(path),
            file_size=binary_info.file_size,
            binary_type=binary_info.binary_type.value,
            architecture=binary_info.architecture.value,
            is_managed=binary_info.is_managed,
            is_packed=binary_info.is_packed,
            has_debug_info=binary_info.has_debug_info,
            imports_count=len(binary_info.imports),
            exports_count=len(binary_info.exports),
            sections_count=len(binary_info.sections),
            metadata=binary_info.metadata
        )
        
        return response
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/detect")
async def upload_and_detect(file: UploadFile = File(...)):
    """Upload binary file and detect its type."""
    try:
        # Save uploaded file to temp directory
        temp_file_path = TEMP_DIR / f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Detect binary type
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(str(temp_file_path))
        
        # Clean up temp file
        temp_file_path.unlink(missing_ok=True)
        
        response = DetectionResponse(
            file_path=file.filename,
            file_size=binary_info.file_size,
            binary_type=binary_info.binary_type.value,
            architecture=binary_info.architecture.value,
            is_managed=binary_info.is_managed,
            is_packed=binary_info.is_packed,
            has_debug_info=binary_info.has_debug_info,
            imports_count=len(binary_info.imports),
            exports_count=len(binary_info.exports),
            sections_count=len(binary_info.sections),
            metadata=binary_info.metadata
        )
        
        return response
    except Exception as e:
        logger.error(f"Upload detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analyze/{file_path:path}")
async def analyze_binary(
    file_path: str,
    output_format: str = "json",
    detailed: bool = False,
    background_tasks: BackgroundTasks = None
):
    """Analyze binary file and generate report."""
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Generate unique analysis ID
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create output directory
        output_dir = TEMP_DIR / analysis_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Start analysis in background
        if background_tasks:
            background_tasks.add_task(
                perform_analysis,
                str(path),
                str(output_dir),
                output_format,
                analysis_id
            )
            
            return AnalysisResponse(
                success=True,
                analysis_id=analysis_id,
                timestamp=datetime.now().isoformat(),
                binary_info={"status": "analysis_started"},
                report_path=None
            )
        else:
            # Perform analysis synchronously
            result = perform_analysis(
                str(path),
                str(output_dir),
                output_format,
                analysis_id
            )
            
            return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/analyze")
async def upload_and_analyze(
    file: UploadFile = File(...),
    output_format: str = Form("json"),
    detailed: bool = Form(False),
    background_tasks: BackgroundTasks = None
):
    """Upload binary file and analyze it."""
    try:
        # Generate unique analysis ID
        analysis_id = f"upload_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Save uploaded file to temp directory
        temp_file_path = TEMP_DIR / f"{analysis_id}_{file.filename}"
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Create output directory
        output_dir = TEMP_DIR / analysis_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Start analysis in background
        if background_tasks:
            background_tasks.add_task(
                perform_analysis,
                str(temp_file_path),
                str(output_dir),
                output_format,
                analysis_id,
                cleanup_file=str(temp_file_path)
            )
            
            return AnalysisResponse(
                success=True,
                analysis_id=analysis_id,
                timestamp=datetime.now().isoformat(),
                binary_info={
                    "filename": file.filename,
                    "status": "analysis_started"
                },
                report_path=None
            )
        else:
            # Perform analysis synchronously
            result = perform_analysis(
                str(temp_file_path),
                str(output_dir),
                output_format,
                analysis_id,
                cleanup_file=str(temp_file_path)
            )
            
            return result
    except Exception as e:
        logger.error(f"Upload analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/decompile/{file_path:path}")
async def decompile_binary(
    file_path: str,
    output_dir: Optional[str] = None,
    force: bool = False,
    background_tasks: BackgroundTasks = None
):
    """Decompile binary file to source code."""
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Generate unique decompilation ID
        decompilation_id = f"decompile_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Use provided output directory or create temp one
        if output_dir:
            output_path = Path(output_dir).resolve()
        else:
            output_path = TEMP_DIR / decompilation_id
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Start decompilation in background
        if background_tasks:
            background_tasks.add_task(
                perform_decompilation,
                str(path),
                str(output_path),
                force,
                decompilation_id
            )
            
            return DecompileResponse(
                success=True,
                decompilation_id=decompilation_id,
                timestamp=datetime.now().isoformat(),
                output_dir=str(output_path),
                exported_files={"status": "decompilation_started"}
            )
        else:
            # Perform decompilation synchronously
            result = perform_decompilation(
                str(path),
                str(output_path),
                force,
                decompilation_id
            )
            
            return result
    except Exception as e:
        logger.error(f"Decompilation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/decompile")
async def upload_and_decompile(
    file: UploadFile = File(...),
    output_dir: Optional[str] = Form(None),
    force: bool = Form(False),
    background_tasks: BackgroundTasks = None
):
    """Upload binary file and decompile it."""
    try:
        # Generate unique decompilation ID
        decompilation_id = f"upload_decompile_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Save uploaded file to temp directory
        temp_file_path = TEMP_DIR / f"{decompilation_id}_{file.filename}"
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Use provided output directory or create temp one
        if output_dir:
            output_path = Path(output_dir).resolve()
        else:
            output_path = TEMP_DIR / decompilation_id
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Start decompilation in background
        if background_tasks:
            background_tasks.add_task(
                perform_decompilation,
                str(temp_file_path),
                str(output_path),
                force,
                decompilation_id,
                cleanup_file=str(temp_file_path)
            )
            
            return DecompileResponse(
                success=True,
                decompilation_id=decompilation_id,
                timestamp=datetime.now().isoformat(),
                output_dir=str(output_path),
                exported_files={"status": "decompilation_started"}
            )
        else:
            # Perform decompilation synchronously
            result = perform_decompilation(
                str(temp_file_path),
                str(output_path),
                force,
                decompilation_id,
                cleanup_file=str(temp_file_path)
            )
            
            return result
    except Exception as e:
        logger.error(f"Upload decompilation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get status of an analysis/decompilation job."""
    if job_id in analysis_jobs:
        return analysis_jobs[job_id]
    else:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@app.get("/api/report/{report_path:path}")
async def download_report(report_path: str):
    """Download analysis report file."""
    try:
        path = Path(report_path).resolve()
        
        # Security check: ensure file is within temp directory
        if not str(path).startswith(str(TEMP_DIR)):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            path,
            filename=path.name,
            media_type="application/octet-stream"
        )
    except Exception as e:
        logger.error(f"Report download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/strings/{file_path:path}")
async def extract_strings(
    file_path: str,
    min_length: int = 4,
    encoding: str = "ascii"
):
    """Extract strings from binary file."""
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Read binary file
        with open(path, 'rb') as f:
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
            except:
                raise HTTPException(status_code=400, detail="Failed to decode as UTF-16")
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
        
        return {
            "success": True,
            "count": len(strings_list),
            "strings": strings_list,
            "parameters": {
                "min_length": min_length,
                "encoding": encoding
            }
        }
    except Exception as e:
        logger.error(f"String extraction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
def perform_analysis(
    file_path: str,
    output_dir: str,
    output_format: str,
    analysis_id: str,
    cleanup_file: Optional[str] = None
) -> AnalysisResponse:
    """Perform binary analysis and generate report."""
    try:
        # Update job status
        analysis_jobs[analysis_id] = {
            "status": "in_progress",
            "started_at": datetime.now().isoformat(),
            "file_path": file_path
        }
        
        # Detect binary type
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(file_path)
        
        analysis_results = {}
        
        if binary_info.is_managed:
            # Analyze .NET assembly
            decompiler = DotNetDecompiler(file_path)
            if decompiler.load():
                assembly_info = decompiler.analyze()
                analysis_results = {
                    "assembly_info": assembly_info,
                    "binary_info": binary_info
                }
            else:
                raise Exception("Failed to load .NET assembly")
        else:
            # Analyze native binary
            analyzer = NativeAnalyzer(file_path)
            binary_info = analyzer.analyze()
            analysis_results = {
                "binary_info": binary_info
            }
        
        # Generate report
        report_gen = ReportGenerator(analysis_results)
        
        report_files = {}
        if output_format == "json":
            report_path = Path(output_dir) / "analysis_report.json"
            if report_gen.generate_json_report(str(report_path)):
                report_files["json"] = str(report_path)
        elif output_format == "yaml":
            report_path = Path(output_dir) / "analysis_report.yaml"
            if report_gen.generate_yaml_report(str(report_path)):
                report_files["yaml"] = str(report_path)
        elif output_format == "html":
            report_path = Path(output_dir) / "analysis_report.html"
            if report_gen.generate_html_report(str(report_path)):
                report_files["html"] = str(report_path)
        elif output_format == "md":
            report_path = Path(output_dir) / "analysis_report.md"
            if report_gen.generate_markdown_report(str(report_path)):
                report_files["markdown"] = str(report_path)
        else:
            # Export all formats
            report_files = report_gen.export_all_formats(output_dir)
        
        # Clean up uploaded file if specified
        if cleanup_file and Path(cleanup_file).exists():
            Path(cleanup_file).unlink(missing_ok=True)
        
        # Update job status
        analysis_jobs[analysis_id] = {
            "status": "completed",
            "started_at": analysis_jobs[analysis_id]["started_at"],
            "completed_at": datetime.now().isoformat(),
            "file_path": file_path,
            "report_files": report_files
        }
        
        return AnalysisResponse(
            success=True,
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            binary_info=analysis_results,
            report_path=list(report_files.values())[0] if report_files else None
        )
        
    except Exception as e:
        logger.error(f"Analysis job {analysis_id} failed: {e}")
        
        # Clean up uploaded file if specified
        if cleanup_file and Path(cleanup_file).exists():
            Path(cleanup_file).unlink(missing_ok=True)
        
        # Update job status
        analysis_jobs[analysis_id] = {
            "status": "failed",
            "started_at": analysis_jobs.get(analysis_id, {}).get("started_at", datetime.now().isoformat()),
            "failed_at": datetime.now().isoformat(),
            "file_path": file_path,
            "error": str(e)
        }
        
        return AnalysisResponse(
            success=False,
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            binary_info={},
            error=str(e)
        )


def perform_decompilation(
    file_path: str,
    output_dir: str,
    force: bool,
    decompilation_id: str,
    cleanup_file: Optional[str] = None
) -> DecompileResponse:
    """Perform binary decompilation."""
    try:
        # Update job status
        analysis_jobs[decompilation_id] = {
            "status": "in_progress",
            "started_at": datetime.now().isoformat(),
            "file_path": file_path
        }
        
        # Detect binary type
        detector = BinaryDetector()
        binary_info = detector.detect_file_type(file_path)
        
        exported_files = {}
        
        if binary_info.is_managed or force:
            # Decompile .NET assembly
            decompiler = DotNetDecompiler(file_path)
            if decompiler.load():
                decompiler.analyze()
                exported_files = decompiler.export_source_code(output_dir)
            else:
                raise Exception("Failed to load .NET assembly for decompilation")
        else:
            # Analyze native binary
            analyzer = NativeAnalyzer(file_path)
            analyzer.analyze()
            exported_files = analyzer.export_analysis(output_dir)
        
        # Clean up uploaded file if specified
        if cleanup_file and Path(cleanup_file).exists():
            Path(cleanup_file).unlink(missing_ok=True)
        
        # Update job status
        analysis_jobs[decompilation_id] = {
            "status": "completed",
            "started_at": analysis_jobs[decompilation_id]["started_at"],
            "completed_at": datetime.now().isoformat(),
            "file_path": file_path,
            "exported_files": exported_files
        }
        
        return DecompileResponse(
            success=True,
            decompilation_id=decompilation_id,
            timestamp=datetime.now().isoformat(),
            output_dir=output_dir,
            exported_files=exported_files
        )
        
    except Exception as e:
        logger.error(f"Decompilation job {decompilation_id} failed: {e}")
        
        # Clean up uploaded file if specified
        if cleanup_file and Path(cleanup_file).exists():
            Path(cleanup_file).unlink(missing_ok=True)
        
        # Update job status
        analysis_jobs[decompilation_id] = {
            "status": "failed",
            "started_at": analysis_jobs.get(decompilation_id, {}).get("started_at", datetime.now().isoformat()),
            "failed_at": datetime.now().isoformat(),
            "file_path": file_path,
            "error": str(e)
        }
        
        return DecompileResponse(
            success=False,
            decompilation_id=decompilation_id,
            timestamp=datetime.now().isoformat(),
            output_dir=output_dir,
            exported_files={},
            error=str(e)
        )


def cleanup_old_files():
    """Clean up old temporary files."""
    try:
        cutoff_time = datetime.now().timestamp() - (24 * 60 * 60)  # 24 hours
        
        for item in TEMP_DIR.iterdir():
            if item.is_file():
                if item.stat().st_mtime < cutoff_time:
                    item.unlink(missing_ok=True)
            elif item.is_dir():
                if item.stat().st_mtime < cutoff_time:
                    shutil.rmtree(item, ignore_errors=True)
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Startup event handler."""
    logger.info("Binary Deobfuscator API starting up...")
    cleanup_old_files()


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler."""
    logger.info("Binary Deobfuscator API shutting down...")


def main():
    """Main entry point for running the API server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Binary Deobfuscator API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    uvicorn.run(
        "api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()