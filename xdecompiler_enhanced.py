#!/usr/bin/env python3
"""
xDecompiler Enhanced - Maximum Extraction Tool
Advanced tool for extracting ALL possible source code from any executable
"""

import os
import sys
import pefile
import capstone
import json
import subprocess
import zipfile
import tempfile
import shutil
import re
import hashlib
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    """Terminal color codes for output formatting"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class MaxExtractor:
    """Maximum extraction engine for all file types"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.pe = None
        self.content = None
        self.output_dir = None
        self.extracted_files = []
        self.code_fragments = []
        self.analysis_results = {}
        
    def load_file(self) -> bool:
        """Load and analyze the target file"""
        try:
            # Load raw content
            with open(self.filename, 'rb') as f:
                self.content = f.read()
            
            # Try to load as PE
            try:
                self.pe = pefile.PE(self.filename)
                print(f"{Colors.GREEN}[+] PE file loaded successfully{Colors.ENDC}")
            except:
                print(f"{Colors.BLUE}[*] Not a valid PE file, using raw analysis{Colors.ENDC}")
            
            # Create output directory
            self.create_output_directory()
            
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error loading file: {e}{Colors.ENDC}")
            return False
    
    def create_output_directory(self):
        """Create output directory in Downloads"""
        try:
            downloads_dir = Path.home() / "Downloads"
            exe_name = Path(self.filename).stem
            self.output_dir = downloads_dir / f"{exe_name}_FULL_EXTRACTED"
            
            # Remove existing directory if it exists
            if self.output_dir.exists():
                shutil.rmtree(self.output_dir)
            
            self.output_dir.mkdir(parents=True, exist_ok=True)
            print(f"{Colors.GREEN}[+] Output directory: {self.output_dir}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Using fallback directory: {e}{Colors.ENDC}")
            self.output_dir = Path.cwd() / f"{Path(self.filename).stem}_FULL_EXTRACTED"
            self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def extract_everything(self) -> bool:
        """Extract everything possible from the file"""
        print(f"{Colors.HEADER}=== MAXIMUM EXTRACTION MODE ==={Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Starting comprehensive extraction...{Colors.ENDC}")
        
        success = False
        
        # Stage 1: Raw analysis and file carving
        print(f"{Colors.HEADER}[STAGE 1] Raw Analysis & File Carving{Colors.ENDC}")
        success |= self.extract_embedded_files()
        success |= self.extract_overlay_data()
        success |= self.extract_resources()
        
        # Stage 2: Language-specific extraction
        print(f"{Colors.HEADER}[STAGE 2] Language-Specific Extraction{Colors.ENDC}")
        success |= self.extract_python_maximum()
        success |= self.extract_dotnet_maximum()
        success |= self.extract_java_maximum()
        success |= self.extract_javascript_maximum()
        success |= self.extract_electron_maximum()
        success |= self.extract_autohotkey_maximum()
        success |= self.extract_cpp_maximum()
        
        # Stage 3: Advanced pattern matching
        print(f"{Colors.HEADER}[STAGE 3] Advanced Pattern Matching{Colors.ENDC}")
        success |= self.extract_code_patterns()
        success |= self.extract_configuration_files()
        success |= self.extract_certificates()
        success |= self.extract_databases()
        
        # Stage 4: Memory and binary analysis
        print(f"{Colors.HEADER}[STAGE 4] Memory & Binary Analysis{Colors.ENDC}")
        success |= self.extract_memory_patterns()
        success |= self.extract_strings_advanced()
        success |= self.extract_assembly_code()
        
        # Stage 5: Create comprehensive report
        print(f"{Colors.HEADER}[STAGE 5] Creating Comprehensive Report{Colors.ENDC}")
        self.create_extraction_report()
        
        return success
    
    def extract_embedded_files(self) -> bool:
        """Extract embedded files using multiple signatures"""
        try:
            print(f"{Colors.BLUE}[*] Searching for embedded files...{Colors.ENDC}")
            
            embedded_dir = self.output_dir / "embedded_files"
            embedded_dir.mkdir(exist_ok=True)
            
            # Extended file signatures
            signatures = {
                # Archives
                b'PK\x03\x04': {'ext': '.zip', 'type': 'ZIP Archive'},
                b'PK\x05\x06': {'ext': '.zip', 'type': 'ZIP Archive (End)'},
                b'Rar!': {'ext': '.rar', 'type': 'RAR Archive'},
                b'7z\xbc\xaf\x27\x1c': {'ext': '.7z', 'type': '7-Zip Archive'},
                b'BZh': {'ext': '.bz2', 'type': 'BZip2 Archive'},
                b'\x1f\x8b\x08': {'ext': '.gz', 'type': 'GZip Archive'},
                b'MSCF': {'ext': '.cab', 'type': 'CAB Archive'},
                
                # Images
                b'\x89PNG\r\n\x1a\n': {'ext': '.png', 'type': 'PNG Image'},
                b'\xff\xd8\xff': {'ext': '.jpg', 'type': 'JPEG Image'},
                b'GIF87a': {'ext': '.gif', 'type': 'GIF Image'},
                b'GIF89a': {'ext': '.gif', 'type': 'GIF Image'},
                b'BM': {'ext': '.bmp', 'type': 'BMP Image'},
                b'RIFF': {'ext': '.webp', 'type': 'WebP Image'},
                
                # Documents
                b'%PDF': {'ext': '.pdf', 'type': 'PDF Document'},
                b'PK\x03\x04\x14\x00\x06\x00': {'ext': '.docx', 'type': 'Word Document'},
                b'PK\x03\x04\x14\x00\x08\x00': {'ext': '.xlsx', 'type': 'Excel Document'},
                b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'ext': '.doc', 'type': 'Old Word Document'},
                
                # Executables
                b'MZ': {'ext': '.exe', 'type': 'Windows Executable'},
                b'\x7fELF': {'ext': '.elf', 'type': 'Linux Executable'},
                b'\xfe\xed\xfa\xce': {'ext': '.macho', 'type': 'macOS Executable'},
                b'\xfe\xed\xfa\xcf': {'ext': '.macho', 'type': 'macOS Executable'},
                
                # Scripts and Code
                b'#!/usr/bin/python': {'ext': '.py', 'type': 'Python Script'},
                b'#!/usr/bin/env python': {'ext': '.py', 'type': 'Python Script'},
                b'#!/bin/sh': {'ext': '.sh', 'type': 'Shell Script'},
                b'#!/bin/bash': {'ext': '.sh', 'type': 'Shell Script'},
                b'<?php': {'ext': '.php', 'type': 'PHP Script'},
                b'<?xml': {'ext': '.xml', 'type': 'XML File'},
                b'<html': {'ext': '.html', 'type': 'HTML File'},
                b'<HTML': {'ext': '.html', 'type': 'HTML File'},
                b'<!DOCTYPE': {'ext': '.html', 'type': 'HTML File'},
                
                # Java
                b'\xca\xfe\xba\xbe': {'ext': '.class', 'type': 'Java Class'},
                b'PK\x03\x04\x14\x00\x08\x00\x08\x00': {'ext': '.jar', 'type': 'Java Archive'},
                b'dex\n': {'ext': '.dex', 'type': 'Android DEX'},
                
                # .NET
                b'BSJB': {'ext': '.net', 'type': '.NET Metadata'},
                
                # Databases
                b'SQLite format 3': {'ext': '.db', 'type': 'SQLite Database'},
                b'Microsoft SQL Server': {'ext': '.mdf', 'type': 'SQL Server Database'},
                
                # Certificates
                b'-----BEGIN CERTIFICATE-----': {'ext': '.crt', 'type': 'Certificate'},
                b'-----BEGIN PRIVATE KEY-----': {'ext': '.key', 'type': 'Private Key'},
                b'-----BEGIN RSA PRIVATE KEY-----': {'ext': '.key', 'type': 'RSA Private Key'},
                
                # Configuration
                b'[': {'ext': '.ini', 'type': 'INI Configuration'},
                b'{': {'ext': '.json', 'type': 'JSON Configuration'},
                b'---': {'ext': '.yaml', 'type': 'YAML Configuration'},
            }
            
            extracted_count = 0
            
            for signature, info in signatures.items():
                pos = 0
                while True:
                    pos = self.content.find(signature, pos)
                    if pos == -1:
                        break
                    
                    try:
                        # Extract file based on type
                        if info['type'] in ['ZIP Archive', 'Java Archive']:
                            # Handle ZIP-based files
                            extracted_count += self.extract_zip_file(pos, info, embedded_dir, extracted_count)
                        elif info['type'] in ['PNG Image', 'JPEG Image', 'GIF Image', 'BMP Image']:
                            # Handle image files
                            extracted_count += self.extract_image_file(pos, info, embedded_dir, extracted_count)
                        elif info['type'] in ['PDF Document']:
                            # Handle PDF files
                            extracted_count += self.extract_pdf_file(pos, info, embedded_dir, extracted_count)
                        elif info['type'] in ['Python Script', 'Shell Script', 'PHP Script']:
                            # Handle script files
                            extracted_count += self.extract_script_file(pos, info, embedded_dir, extracted_count)
                        else:
                            # Handle other files
                            extracted_count += self.extract_generic_file(pos, info, embedded_dir, extracted_count)
                    
                    except Exception as e:
                        print(f"{Colors.WARNING}[!] Error extracting file at 0x{pos:x}: {e}{Colors.ENDC}")
                    
                    pos += len(signature)
            
            if extracted_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {extracted_count} embedded files{Colors.ENDC}")
                return True
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Embedded file extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_zip_file(self, pos: int, info: dict, embedded_dir: Path, count: int) -> int:
        """Extract ZIP-based files"""
        try:
            # Find end of ZIP file
            end_pos = self.content.find(b'PK\x05\x06', pos)
            if end_pos == -1:
                return 0
            
            # Find actual end
            end_pos += 22  # Standard end record size
            
            # Extract file
            zip_data = self.content[pos:end_pos]
            zip_file = embedded_dir / f"embedded_{count}{info['ext']}"
            
            with open(zip_file, 'wb') as f:
                f.write(zip_data)
            
            # Try to extract contents
            try:
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    extract_dir = embedded_dir / f"extracted_{count}_{info['type'].replace(' ', '_')}"
                    zip_ref.extractall(extract_dir)
                    print(f"{Colors.GREEN}[+] Extracted {info['type']}: {zip_file.name}{Colors.ENDC}")
                    return 1
            except:
                print(f"{Colors.WARNING}[!] Could not extract ZIP contents: {zip_file.name}{Colors.ENDC}")
                return 1
                
        except Exception as e:
            return 0
    
    def extract_image_file(self, pos: int, info: dict, embedded_dir: Path, count: int) -> int:
        """Extract image files"""
        try:
            # Determine end position based on image type
            if info['ext'] == '.png':
                end_marker = b'IEND\xaeB`\x82'
                end_pos = self.content.find(end_marker, pos)
                if end_pos != -1:
                    end_pos += len(end_marker)
                else:
                    end_pos = pos + 1024 * 1024  # 1MB max
            elif info['ext'] == '.jpg':
                end_marker = b'\xff\xd9'
                end_pos = self.content.find(end_marker, pos)
                if end_pos != -1:
                    end_pos += len(end_marker)
                else:
                    end_pos = pos + 1024 * 1024  # 1MB max
            else:
                end_pos = pos + 1024 * 1024  # 1MB max for other formats
            
            # Extract image
            image_data = self.content[pos:end_pos]
            image_file = embedded_dir / f"embedded_{count}{info['ext']}"
            
            with open(image_file, 'wb') as f:
                f.write(image_data)
            
            print(f"{Colors.GREEN}[+] Extracted {info['type']}: {image_file.name}{Colors.ENDC}")
            return 1
            
        except Exception as e:
            return 0
    
    def extract_pdf_file(self, pos: int, info: dict, embedded_dir: Path, count: int) -> int:
        """Extract PDF files"""
        try:
            # Find end of PDF
            end_marker = b'%%EOF'
            end_pos = self.content.find(end_marker, pos)
            if end_pos != -1:
                end_pos += len(end_marker)
            else:
                end_pos = pos + 10 * 1024 * 1024  # 10MB max
            
            # Extract PDF
            pdf_data = self.content[pos:end_pos]
            pdf_file = embedded_dir / f"embedded_{count}{info['ext']}"
            
            with open(pdf_file, 'wb') as f:
                f.write(pdf_data)
            
            print(f"{Colors.GREEN}[+] Extracted {info['type']}: {pdf_file.name}{Colors.ENDC}")
            return 1
            
        except Exception as e:
            return 0
    
    def extract_script_file(self, pos: int, info: dict, embedded_dir: Path, count: int) -> int:
        """Extract script files"""
        try:
            # Find end of script (next null byte or reasonable limit)
            end_pos = pos
            while end_pos < len(self.content) and end_pos < pos + 100000:  # 100KB max
                if self.content[end_pos] == 0:
                    break
                end_pos += 1
            
            # Extract script
            script_data = self.content[pos:end_pos]
            script_file = embedded_dir / f"embedded_{count}{info['ext']}"
            
            with open(script_file, 'wb') as f:
                f.write(script_data)
            
            # Try to decode as text
            try:
                text = script_data.decode('utf-8', errors='ignore')
                text_file = embedded_dir / f"embedded_{count}_decoded.txt"
                with open(text_file, 'w', encoding='utf-8') as f:
                    f.write(text)
                print(f"{Colors.GREEN}[+] Extracted {info['type']}: {script_file.name} (decoded){Colors.ENDC}")
            except:
                print(f"{Colors.GREEN}[+] Extracted {info['type']}: {script_file.name}{Colors.ENDC}")
            
            return 1
            
        except Exception as e:
            return 0
    
    def extract_generic_file(self, pos: int, info: dict, embedded_dir: Path, count: int) -> int:
        """Extract generic files"""
        try:
            # Use reasonable size limit
            max_size = 5 * 1024 * 1024  # 5MB max
            end_pos = min(pos + max_size, len(self.content))
            
            # Extract file
            file_data = self.content[pos:end_pos]
            file_path = embedded_dir / f"embedded_{count}{info['ext']}"
            
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            print(f"{Colors.GREEN}[+] Extracted {info['type']}: {file_path.name}{Colors.ENDC}")
            return 1
            
        except Exception as e:
            return 0
    
    def extract_python_maximum(self) -> bool:
        """Maximum Python extraction with all possible methods"""
        try:
            print(f"{Colors.BLUE}[*] Maximum Python extraction...{Colors.ENDC}")
            
            python_dir = self.output_dir / "python_extraction"
            python_dir.mkdir(exist_ok=True)
            
            extracted_any = False
            
            # Method 1: PyInstaller extraction
            if self.extract_pyinstaller_advanced(python_dir):
                extracted_any = True
            
            # Method 2: py2exe extraction  
            if self.extract_py2exe_advanced(python_dir):
                extracted_any = True
            
            # Method 3: cx_Freeze extraction
            if self.extract_cxfreeze_advanced(python_dir):
                extracted_any = True
            
            # Method 4: Nuitka extraction
            if self.extract_nuitka_advanced(python_dir):
                extracted_any = True
            
            # Method 5: Raw Python code search
            if self.extract_python_code_raw(python_dir):
                extracted_any = True
            
            # Method 6: Python bytecode search
            if self.extract_python_bytecode(python_dir):
                extracted_any = True
            
            return extracted_any
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Python extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_pyinstaller_advanced(self, python_dir: Path) -> bool:
        """Advanced PyInstaller extraction"""
        try:
            print(f"{Colors.BLUE}[*] Advanced PyInstaller extraction...{Colors.ENDC}")
            
            # Check for PyInstaller signatures
            pyinstaller_signatures = [
                b'PyInstaller',
                b'pyi-runtime-tmpdir',
                b'PYZ-00.pyz',
                b'PyInstaller Bootloader',
                b'Cannot open PyInstaller archive',
                b'bootloader_ignore_signals'
            ]
            
            has_pyinstaller = any(sig in self.content for sig in pyinstaller_signatures)
            
            if not has_pyinstaller:
                return False
            
            print(f"{Colors.GREEN}[+] PyInstaller signatures detected{Colors.ENDC}")
            
            # Use pyinstxtractor if available
            extractor_dir = python_dir / "pyinstaller_extracted"
            extractor_dir.mkdir(exist_ok=True)
            
            # Try multiple extraction methods
            methods = [
                self.extract_with_pyinstxtractor,
                self.extract_pyinstaller_manual,
                self.extract_pyinstaller_raw
            ]
            
            for method in methods:
                try:
                    if method(extractor_dir):
                        print(f"{Colors.GREEN}[+] PyInstaller extraction successful{Colors.ENDC}")
                        return True
                except Exception as e:
                    print(f"{Colors.WARNING}[!] Method failed: {e}{Colors.ENDC}")
                    continue
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] PyInstaller extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_with_pyinstxtractor(self, extractor_dir: Path) -> bool:
        """Extract using pyinstxtractor"""
        try:
            # Try to find or download pyinstxtractor
            pyinstxtractor_path = Path(__file__).parent / "pyinstxtractor.py"
            
            if not pyinstxtractor_path.exists():
                # Try to download pyinstxtractor
                import urllib.request
                url = "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py"
                urllib.request.urlretrieve(url, str(pyinstxtractor_path))
            
            # Run pyinstxtractor
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run([
                    'python', str(pyinstxtractor_path), self.filename
                ], cwd=temp_dir, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Copy extracted files
                    for item in Path(temp_dir).iterdir():
                        if item.is_dir():
                            shutil.copytree(item, extractor_dir / item.name, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, extractor_dir)
                    
                    # Decompile all .pyc files found
                    self.decompile_all_pyc_files(extractor_dir)
                    
                    return True
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] pyinstxtractor method failed: {e}{Colors.ENDC}")
            return False
    
    def extract_pyinstaller_manual(self, extractor_dir: Path) -> bool:
        """Manual PyInstaller extraction"""
        try:
            print(f"{Colors.BLUE}[*] Manual PyInstaller extraction...{Colors.ENDC}")
            
            # Look for overlay data (PyInstaller archive)
            overlay_start = self.find_overlay_start()
            if overlay_start is None:
                return False
            
            overlay_data = self.content[overlay_start:]
            
            # Save overlay
            overlay_file = extractor_dir / "overlay.bin"
            with open(overlay_file, 'wb') as f:
                f.write(overlay_data)
            
            # Look for CArchive signature
            archive_start = overlay_data.find(b'MEI\x0c\x0b\x0a\x0b\x0e')
            if archive_start != -1:
                print(f"{Colors.GREEN}[+] Found CArchive at offset 0x{archive_start:x}{Colors.ENDC}")
                
                # Extract archive manually
                archive_data = overlay_data[archive_start:]
                self.extract_carchive_manual(archive_data, extractor_dir)
                
                return True
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Manual PyInstaller extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_pyinstaller_raw(self, extractor_dir: Path) -> bool:
        """Raw PyInstaller data extraction"""
        try:
            print(f"{Colors.BLUE}[*] Raw PyInstaller data extraction...{Colors.ENDC}")
            
            # Look for Python bytecode signatures
            bytecode_patterns = [
                b'\x63\x00\x00\x00',  # Python 3.x bytecode
                b'\x03\xf3\r\n',      # Python 2.7 bytecode
                b'\xee\x0c\r\n',      # Python 3.8 bytecode
                b'\x61\x0d\r\n',      # Python 3.9 bytecode
                b'\x55\x0d\r\n',      # Python 3.10 bytecode
            ]
            
            found_bytecode = []
            
            for pattern in bytecode_patterns:
                pos = 0
                while True:
                    pos = self.content.find(pattern, pos)
                    if pos == -1:
                        break
                    
                    found_bytecode.append(pos)
                    pos += len(pattern)
            
            if found_bytecode:
                print(f"{Colors.GREEN}[+] Found {len(found_bytecode)} potential bytecode locations{Colors.ENDC}")
                
                # Extract bytecode files
                for i, pos in enumerate(found_bytecode):
                    try:
                        # Extract up to 1MB from each location
                        bytecode_data = self.content[pos:pos + 1024*1024]
                        bytecode_file = extractor_dir / f"bytecode_{i}.pyc"
                        
                        with open(bytecode_file, 'wb') as f:
                            f.write(bytecode_data)
                        
                        # Try to decompile
                        self.try_decompile_bytecode(bytecode_file, extractor_dir)
                        
                    except Exception as e:
                        continue
                
                return True
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Raw PyInstaller extraction failed: {e}{Colors.ENDC}")
            return False
    
    def decompile_all_pyc_files(self, directory: Path):
        """Decompile all .pyc files in a directory"""
        try:
            pyc_files = list(directory.rglob('*.pyc'))
            pyo_files = list(directory.rglob('*.pyo'))
            all_bytecode = pyc_files + pyo_files
            
            if not all_bytecode:
                return
            
            print(f"{Colors.BLUE}[*] Decompiling {len(all_bytecode)} bytecode files...{Colors.ENDC}")
            
            decompiled_dir = directory / "decompiled_source"
            decompiled_dir.mkdir(exist_ok=True)
            
            success_count = 0
            
            for bytecode_file in all_bytecode:
                if self.try_decompile_bytecode(bytecode_file, decompiled_dir):
                    success_count += 1
            
            print(f"{Colors.GREEN}[+] Successfully decompiled {success_count}/{len(all_bytecode)} files{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Bytecode decompilation failed: {e}{Colors.ENDC}")
    
    def try_decompile_bytecode(self, bytecode_file: Path, output_dir: Path) -> bool:
        """Try to decompile a bytecode file using multiple methods"""
        try:
            # Method 1: uncompyle6
            try:
                result = subprocess.run([
                    'python', '-m', 'uncompyle6', str(bytecode_file)
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and result.stdout.strip():
                    output_file = output_dir / f"{bytecode_file.stem}.py"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(f"# Decompiled with uncompyle6 from {bytecode_file.name}\n")
                        f.write(result.stdout)
                    
                    print(f"{Colors.GREEN}[+] Decompiled with uncompyle6: {output_file.name}{Colors.ENDC}")
                    return True
            except:
                pass
            
            # Method 2: decompyle3
            try:
                result = subprocess.run([
                    'python', '-m', 'decompyle3', str(bytecode_file)
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and result.stdout.strip():
                    output_file = output_dir / f"{bytecode_file.stem}_decompyle3.py"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(f"# Decompiled with decompyle3 from {bytecode_file.name}\n")
                        f.write(result.stdout)
                    
                    print(f"{Colors.GREEN}[+] Decompiled with decompyle3: {output_file.name}{Colors.ENDC}")
                    return True
            except:
                pass
            
            # Method 3: dis (disassembly)
            try:
                result = subprocess.run([
                    'python', '-c', f'''
import dis
import marshal
import sys

try:
    with open(r"{bytecode_file}", "rb") as f:
        data = f.read()
    
    # Skip magic number and timestamp
    if len(data) > 12:
        code = marshal.loads(data[12:])
        dis.dis(code)
except Exception as e:
    print(f"Error: {{e}}")
'''
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout.strip():
                    output_file = output_dir / f"{bytecode_file.stem}_disassembly.txt"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(f"# Disassembly from {bytecode_file.name}\n")
                        f.write(result.stdout)
                    
                    print(f"{Colors.GREEN}[+] Disassembled: {output_file.name}{Colors.ENDC}")
                    return True
            except:
                pass
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Decompilation failed for {bytecode_file.name}: {e}{Colors.ENDC}")
            return False
    
    def find_overlay_start(self) -> Optional[int]:
        """Find the start of overlay data in PE file"""
        try:
            if not self.pe:
                return None
            
            # Calculate overlay start
            overlay_start = 0
            
            # Find the end of the last section
            for section in self.pe.sections:
                section_end = section.PointerToRawData + section.SizeOfRawData
                if section_end > overlay_start:
                    overlay_start = section_end
            
            # Check if there's overlay data
            if overlay_start < len(self.content):
                return overlay_start
            
            return None
            
        except Exception as e:
            return None
    
    def extract_carchive_manual(self, archive_data: bytes, output_dir: Path):
        """Manually extract CArchive data"""
        try:
            print(f"{Colors.BLUE}[*] Manually extracting CArchive...{Colors.ENDC}")
            
            # This is a simplified CArchive parser
            # Real implementation would need to handle the full CArchive format
            
            # Save raw archive
            archive_file = output_dir / "carchive.bin"
            with open(archive_file, 'wb') as f:
                f.write(archive_data)
            
            # Look for embedded files within the archive
            pos = 0
            file_count = 0
            
            while pos < len(archive_data) - 4:
                # Look for file signatures
                if archive_data[pos:pos+4] == b'PK\x03\x04':  # ZIP file
                    # Extract ZIP file
                    zip_end = archive_data.find(b'PK\x05\x06', pos)
                    if zip_end != -1:
                        zip_data = archive_data[pos:zip_end + 22]
                        zip_file = output_dir / f"extracted_zip_{file_count}.zip"
                        with open(zip_file, 'wb') as f:
                            f.write(zip_data)
                        file_count += 1
                
                pos += 1
            
            print(f"{Colors.GREEN}[+] Extracted {file_count} files from CArchive{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] CArchive extraction failed: {e}{Colors.ENDC}")
    
    def extract_code_patterns(self) -> bool:
        """Extract code patterns using advanced regex"""
        try:
            print(f"{Colors.BLUE}[*] Extracting code patterns...{Colors.ENDC}")
            
            patterns_dir = self.output_dir / "code_patterns"
            patterns_dir.mkdir(exist_ok=True)
            
            # Convert binary to text (multiple encodings)
            text_versions = []
            
            encodings = ['utf-8', 'utf-16le', 'utf-16be', 'ascii', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    text_versions.append((encoding, text))
                except:
                    continue
            
            # Advanced code patterns
            patterns = {
                'python': {
                    'functions': r'def\s+(\w+)\s*\([^)]*\)\s*:',
                    'classes': r'class\s+(\w+)(?:\([^)]*\))?\s*:',
                    'imports': r'(?:from\s+(\w+(?:\.\w+)*)\s+)?import\s+([^#\n]+)',
                    'variables': r'(\w+)\s*=\s*[^=\n]+',
                    'loops': r'for\s+\w+\s+in\s+[^:\n]+:',
                    'conditionals': r'if\s+[^:\n]+:',
                    'exceptions': r'try\s*:|except\s+[^:\n]*:',
                    'decorators': r'@\w+(?:\([^)]*\))?',
                    'lambdas': r'lambda\s+[^:\n]+:',
                    'comprehensions': r'\[.+for\s+\w+\s+in\s+[^\]]+\]',
                },
                'javascript': {
                    'functions': r'function\s+(\w+)\s*\([^)]*\)\s*\{',
                    'arrow_functions': r'(?:const|let|var)\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
                    'variables': r'(?:const|let|var)\s+(\w+)\s*=',
                    'classes': r'class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{',
                    'methods': r'(\w+)\s*\([^)]*\)\s*\{',
                    'objects': r'(\w+)\s*:\s*\{',
                    'requires': r'require\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    'imports': r'import\s+[^from\n]+\s+from\s+[\'"]([^\'"]+)[\'"]',
                    'exports': r'(?:module\.)?exports?\s*=|export\s+',
                    'jquery': r'\$\s*\([^)]+\)',
                },
                'csharp': {
                    'classes': r'(?:public|private|protected|internal)?\s*(?:abstract|sealed)?\s*class\s+(\w+)',
                    'methods': r'(?:public|private|protected|internal)?\s*(?:static|virtual|override)?\s*\w+\s+(\w+)\s*\([^)]*\)',
                    'properties': r'(?:public|private|protected|internal)?\s*\w+\s+(\w+)\s*\{\s*get|set',
                    'namespaces': r'namespace\s+([^\s{]+)',
                    'using': r'using\s+([^;]+);',
                    'interfaces': r'(?:public|internal)?\s*interface\s+(\w+)',
                    'enums': r'(?:public|internal)?\s*enum\s+(\w+)',
                    'structs': r'(?:public|internal)?\s*struct\s+(\w+)',
                    'events': r'(?:public|private|protected|internal)?\s*event\s+\w+\s+(\w+)',
                    'delegates': r'(?:public|private|protected|internal)?\s*delegate\s+\w+\s+(\w+)',
                },
                'java': {
                    'classes': r'(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)',
                    'interfaces': r'(?:public|private|protected)?\s*interface\s+(\w+)',
                    'methods': r'(?:public|private|protected)?\s*(?:static|final|abstract)?\s*\w+\s+(\w+)\s*\([^)]*\)',
                    'packages': r'package\s+([^;]+);',
                    'imports': r'import\s+(?:static\s+)?([^;]+);',
                    'annotations': r'@(\w+)(?:\([^)]*\))?',
                    'enums': r'(?:public|private|protected)?\s*enum\s+(\w+)',
                    'constructors': r'(?:public|private|protected)?\s*(\w+)\s*\([^)]*\)\s*\{',
                    'variables': r'(?:public|private|protected)?\s*(?:static|final)?\s*\w+\s+(\w+)\s*[=;]',
                    'constants': r'(?:public|private|protected)?\s*static\s+final\s+\w+\s+(\w+)',
                },
                'cpp': {
                    'includes': r'#include\s*[<"]([^>"]+)[>"]',
                    'functions': r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{',
                    'classes': r'class\s+(\w+)(?:\s*:\s*[^{]+)?\s*\{',
                    'structs': r'struct\s+(\w+)\s*\{',
                    'namespaces': r'namespace\s+(\w+)\s*\{',
                    'templates': r'template\s*<[^>]+>\s*(?:class|struct|typename)\s+(\w+)',
                    'macros': r'#define\s+(\w+)',
                    'typedefs': r'typedef\s+[^;]+\s+(\w+);',
                    'variables': r'(?:static|extern)?\s*\w+\s+(\w+)\s*[=;]',
                    'enums': r'enum\s+(?:class\s+)?(\w+)',
                }
            }
            
            found_patterns = {}
            
            for language, lang_patterns in patterns.items():
                found_patterns[language] = {}
                
                for pattern_type, pattern in lang_patterns.items():
                    matches = []
                    
                    for encoding, text in text_versions:
                        try:
                            pattern_matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
                            for match in pattern_matches:
                                context_start = max(0, match.start() - 100)
                                context_end = min(len(text), match.end() + 100)
                                context = text[context_start:context_end]
                                
                                matches.append({
                                    'match': match.group(0),
                                    'groups': match.groups(),
                                    'context': context,
                                    'encoding': encoding,
                                    'position': match.start()
                                })
                        except:
                            continue
                    
                    if matches:
                        found_patterns[language][pattern_type] = matches
            
            # Save patterns
            total_patterns = 0
            for language, lang_patterns in found_patterns.items():
                if lang_patterns:
                    lang_file = patterns_dir / f"{language}_patterns.json"
                    with open(lang_file, 'w', encoding='utf-8') as f:
                        json.dump(lang_patterns, f, indent=2, ensure_ascii=False)
                    
                    # Create readable summary
                    summary_file = patterns_dir / f"{language}_summary.txt"
                    with open(summary_file, 'w', encoding='utf-8') as f:
                        f.write(f"{language.upper()} Code Patterns Summary\n")
                        f.write("=" * 50 + "\n\n")
                        
                        for pattern_type, matches in lang_patterns.items():
                            f.write(f"{pattern_type.upper()} ({len(matches)} matches):\n")
                            f.write("-" * 30 + "\n")
                            
                            for match in matches[:10]:  # Show first 10 matches
                                f.write(f"Match: {match['match']}\n")
                                f.write(f"Context: {match['context'][:200]}...\n")
                                f.write(f"Encoding: {match['encoding']}\n")
                                f.write(f"Position: 0x{match['position']:x}\n")
                                f.write("-" * 20 + "\n")
                            
                            f.write("\n")
                            total_patterns += len(matches)
            
            if total_patterns > 0:
                print(f"{Colors.GREEN}[+] Found {total_patterns} code patterns across all languages{Colors.ENDC}")
                return True
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Code pattern extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_overlay_data(self) -> bool:
        """Extract overlay data from PE file"""
        try:
            print(f"{Colors.BLUE}[*] Extracting overlay data...{Colors.ENDC}")
            
            if not self.pe:
                return False
                
            # Find overlay start
            overlay_start = self.find_overlay_start()
            if overlay_start is None:
                return False
                
            overlay_data = self.content[overlay_start:]
            if len(overlay_data) < 100:  # Too small to be meaningful
                return False
                
            # Save overlay data
            overlay_dir = self.output_dir / "overlay_data"
            overlay_dir.mkdir(exist_ok=True)
            
            overlay_file = overlay_dir / "overlay.bin"
            with open(overlay_file, 'wb') as f:
                f.write(overlay_data)
                
            print(f"{Colors.GREEN}[+] Extracted overlay data: {len(overlay_data)} bytes{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Overlay extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_resources(self) -> bool:
        """Extract PE resources"""
        try:
            print(f"{Colors.BLUE}[*] Extracting PE resources...{Colors.ENDC}")
            
            if not self.pe:
                return False
                
            resources_dir = self.output_dir / "resources"
            resources_dir.mkdir(exist_ok=True)
            
            extracted_count = 0
            
            # Extract resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            
                            # Determine file extension
                            ext = '.bin'
                            if resource_type.name and resource_type.name.string:
                                res_name = resource_type.name.string.decode('utf-8', errors='ignore')
                                if 'ICON' in res_name:
                                    ext = '.ico'
                                elif 'BITMAP' in res_name:
                                    ext = '.bmp'
                                elif 'CURSOR' in res_name:
                                    ext = '.cur'
                                elif 'MENU' in res_name:
                                    ext = '.rc'
                                elif 'DIALOG' in res_name:
                                    ext = '.rc'
                                elif 'STRING' in res_name:
                                    ext = '.txt'
                                elif 'MANIFEST' in res_name:
                                    ext = '.xml'
                            
                            # Save resource
                            resource_file = resources_dir / f"resource_{extracted_count}{ext}"
                            with open(resource_file, 'wb') as f:
                                f.write(data)
                            
                            extracted_count += 1
            
            if extracted_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {extracted_count} resources{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Resource extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_dotnet_maximum(self) -> bool:
        """Extract .NET assemblies and metadata"""
        try:
            print(f"{Colors.BLUE}[*] .NET extraction...{Colors.ENDC}")
            
            # Check for .NET signatures
            dotnet_signatures = [b'.NET', b'mscoree.dll', b'mscorlib', b'System.']
            
            if not any(sig in self.content for sig in dotnet_signatures):
                return False
                
            dotnet_dir = self.output_dir / "dotnet_extraction"
            dotnet_dir.mkdir(exist_ok=True)
            
            print(f"{Colors.GREEN}[+] .NET signatures detected{Colors.ENDC}")
            
            # Try to extract .NET metadata
            metadata_file = dotnet_dir / "metadata.txt"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                f.write("# .NET Metadata Analysis\n")
                f.write(f"File: {self.filename}\n\n")
                
                # Look for .NET strings
                for encoding in ['utf-8', 'utf-16le']:
                    try:
                        text = self.content.decode(encoding, errors='ignore')
                        dotnet_matches = re.findall(r'System\.\w+', text)
                        if dotnet_matches:
                            f.write(f"## .NET Types ({encoding}):\n")
                            for match in set(dotnet_matches)[:50]:
                                f.write(f"- {match}\n")
                            f.write("\n")
                    except:
                        continue
            
            return True
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] .NET extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_java_maximum(self) -> bool:
        """Extract Java classes and resources"""
        try:
            print(f"{Colors.BLUE}[*] Java extraction...{Colors.ENDC}")
            
            # Check for Java signatures
            java_signatures = [b'\xca\xfe\xba\xbe', b'java/', b'javax/', b'org.apache']
            
            if not any(sig in self.content for sig in java_signatures):
                return False
                
            java_dir = self.output_dir / "java_extraction"
            java_dir.mkdir(exist_ok=True)
            
            print(f"{Colors.GREEN}[+] Java signatures detected{Colors.ENDC}")
            
            # Extract Java class files
            pos = 0
            class_count = 0
            while True:
                pos = self.content.find(b'\xca\xfe\xba\xbe', pos)
                if pos == -1:
                    break
                    
                # Extract class file (estimate size)
                class_data = self.content[pos:pos + 65536]  # Max 64KB per class
                class_file = java_dir / f"class_{class_count}.class"
                
                with open(class_file, 'wb') as f:
                    f.write(class_data)
                
                class_count += 1
                pos += 4
            
            if class_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {class_count} Java class files{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Java extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_javascript_maximum(self) -> bool:
        """Extract JavaScript code"""
        try:
            print(f"{Colors.BLUE}[*] JavaScript extraction...{Colors.ENDC}")
            
            js_dir = self.output_dir / "javascript_extraction"
            js_dir.mkdir(exist_ok=True)
            
            # Look for JavaScript patterns
            js_patterns = [
                rb'function\s+\w+\s*\(',
                rb'var\s+\w+\s*=',
                rb'document\.',
                rb'window\.',
                rb'console\.',
                rb'require\s*\(',
                rb'module\.exports'
            ]
            
            found_js = False
            
            for encoding in ['utf-8', 'utf-16le', 'ascii']:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    
                    for pattern in js_patterns:
                        pattern_str = pattern.decode('utf-8', errors='ignore')
                        if re.search(pattern_str, text, re.IGNORECASE):
                            found_js = True
                            break
                    
                    if found_js:
                        # Extract JavaScript-like code
                        js_file = js_dir / f"extracted_js_{encoding}.js"
                        with open(js_file, 'w', encoding='utf-8') as f:
                            f.write(f"// JavaScript code extracted from {self.filename}\n")
                            f.write(f"// Encoding: {encoding}\n\n")
                            
                            # Find function definitions
                            functions = re.findall(r'function\s+\w+\s*\([^)]*\)\s*\{[^}]*\}', text, re.IGNORECASE)
                            for func in functions[:10]:  # First 10 functions
                                f.write(func + "\n\n")
                        
                        print(f"{Colors.GREEN}[+] Extracted JavaScript code ({encoding}){Colors.ENDC}")
                        
                except:
                    continue
            
            return found_js
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] JavaScript extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_electron_maximum(self) -> bool:
        """Extract Electron application resources"""
        try:
            print(f"{Colors.BLUE}[*] Electron extraction...{Colors.ENDC}")
            
            # Check for Electron signatures
            electron_signatures = [b'electron', b'app.asar', b'node_modules', b'package.json']
            
            if not any(sig in self.content for sig in electron_signatures):
                return False
                
            electron_dir = self.output_dir / "electron_extraction"
            electron_dir.mkdir(exist_ok=True)
            
            print(f"{Colors.GREEN}[+] Electron signatures detected{Colors.ENDC}")
            
            # Look for ASAR archives
            asar_positions = []
            pos = 0
            while True:
                pos = self.content.find(b'app.asar', pos)
                if pos == -1:
                    break
                asar_positions.append(pos)
                pos += 8
            
            if asar_positions:
                print(f"{Colors.GREEN}[+] Found {len(asar_positions)} ASAR references{Colors.ENDC}")
                
                # Extract ASAR-like data
                for i, pos in enumerate(asar_positions):
                    asar_data = self.content[pos:pos + 1024*1024]  # 1MB max
                    asar_file = electron_dir / f"asar_data_{i}.bin"
                    
                    with open(asar_file, 'wb') as f:
                        f.write(asar_data)
                
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Electron extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_autohotkey_maximum(self) -> bool:
        """Extract AutoHotkey scripts"""
        try:
            print(f"{Colors.BLUE}[*] AutoHotkey extraction...{Colors.ENDC}")
            
            # Check for AutoHotkey signatures
            ahk_signatures = [b'AutoHotkey', b'#NoEnv', b'#SingleInstance', b'SendInput']
            
            if not any(sig in self.content for sig in ahk_signatures):
                return False
                
            ahk_dir = self.output_dir / "autohotkey_extraction"
            ahk_dir.mkdir(exist_ok=True)
            
            print(f"{Colors.GREEN}[+] AutoHotkey signatures detected{Colors.ENDC}")
            
            # Extract AutoHotkey scripts
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    
                    # Look for AutoHotkey patterns
                    ahk_patterns = [
                        r'#\w+',  # Directives
                        r'^\w+::\w+',  # Hotkeys
                        r'SendInput\s*,',  # Commands
                        r'WinActivate\s*,',
                        r'Sleep\s*,\s*\d+'
                    ]
                    
                    found_patterns = []
                    for pattern in ahk_patterns:
                        matches = re.findall(pattern, text, re.MULTILINE)
                        found_patterns.extend(matches)
                    
                    if found_patterns:
                        ahk_file = ahk_dir / f"extracted_ahk_{encoding}.ahk"
                        with open(ahk_file, 'w', encoding='utf-8') as f:
                            f.write(f"; AutoHotkey script extracted from {self.filename}\n")
                            f.write(f"; Encoding: {encoding}\n\n")
                            
                            for pattern in found_patterns[:50]:  # First 50 patterns
                                f.write(f"{pattern}\n")
                        
                        print(f"{Colors.GREEN}[+] Extracted AutoHotkey script ({encoding}){Colors.ENDC}")
                        return True
                        
                except:
                    continue
            
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] AutoHotkey extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_cpp_maximum(self) -> bool:
        """Extract C++ code and resources"""
        try:
            print(f"{Colors.BLUE}[*] C++ extraction...{Colors.ENDC}")
            
            cpp_dir = self.output_dir / "cpp_extraction"
            cpp_dir.mkdir(exist_ok=True)
            
            # Look for C++ patterns
            cpp_patterns = [
                rb'#include\s*<',
                rb'std::',
                rb'namespace\s+\w+',
                rb'class\s+\w+',
                rb'template\s*<'
            ]
            
            found_cpp = False
            
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    
                    for pattern in cpp_patterns:
                        pattern_str = pattern.decode('utf-8', errors='ignore')
                        if re.search(pattern_str, text, re.IGNORECASE):
                            found_cpp = True
                            break
                    
                    if found_cpp:
                        # Extract C++ code
                        cpp_file = cpp_dir / f"extracted_cpp_{encoding}.cpp"
                        with open(cpp_file, 'w', encoding='utf-8') as f:
                            f.write(f"// C++ code extracted from {self.filename}\n")
                            f.write(f"// Encoding: {encoding}\n\n")
                            
                            # Find includes
                            includes = re.findall(r'#include\s*<[^>]+>', text)
                            for include in includes[:20]:  # First 20 includes
                                f.write(f"{include}\n")
                            

                            f.write("\n")
                            
                            # Find class definitions
                            classes = re.findall(r'class\s+\w+[^{]*\{[^}]*\}', text, re.IGNORECASE)
                            for cls in classes[:5]:  # First 5 classes
                                f.write(f"{cls}\n\n")
                        
                        print(f"{Colors.GREEN}[+] Extracted C++ code ({encoding}){Colors.ENDC}")
                        
                except:
                    continue
            
            return found_cpp
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] C++ extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_configuration_files(self) -> bool:
        """Extract configuration files"""
        try:
            print(f"{Colors.BLUE}[*] Extracting configuration files...{Colors.ENDC}")
            
            config_dir = self.output_dir / "configuration_files"
            config_dir.mkdir(exist_ok=True)
            
            extracted_count = 0
            
            # Look for configuration patterns
            config_patterns = {
                'ini': [rb'\[[\w\s]+\]', rb'\w+\s*=\s*\w+'],
                'json': [rb'\{[\s\S]*"[\w\s]+"\s*:\s*"[\w\s]+"\s*[\s\S]*\}'],
                'xml': [rb'<\?xml', rb'<[\w\s]+>'],
                'yaml': [rb'^\s*\w+\s*:\s*\w+', rb'^\s*-\s+\w+']
            }
            
            for config_type, patterns in config_patterns.items():
                for encoding in ['utf-8', 'ascii', 'latin-1']:
                    try:
                        text = self.content.decode(encoding, errors='ignore')
                        
                        for pattern in patterns:
                            pattern_str = pattern.decode('utf-8', errors='ignore')
                            matches = re.findall(pattern_str, text, re.MULTILINE)
                            
                            if matches:
                                config_file = config_dir / f"extracted_{config_type}_{encoding}.{config_type}"
                                with open(config_file, 'w', encoding='utf-8') as f:
                                    f.write(f"# {config_type.upper()} configuration extracted from {self.filename}\n")
                                    f.write(f"# Encoding: {encoding}\n\n")
                                    
                                    for match in matches[:20]:  # First 20 matches
                                        f.write(f"{match}\n")
                                
                                extracted_count += 1
                                break
                                
                    except:
                        continue
            
            if extracted_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {extracted_count} configuration files{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Configuration extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_certificates(self) -> bool:
        """Extract certificates and keys"""
        try:
            print(f"{Colors.BLUE}[*] Extracting certificates...{Colors.ENDC}")
            
            cert_dir = self.output_dir / "certificates"
            cert_dir.mkdir(exist_ok=True)
            
            # Look for certificate patterns
            cert_patterns = {
                'pem': [b'-----BEGIN CERTIFICATE-----', b'-----END CERTIFICATE-----'],
                'key': [b'-----BEGIN PRIVATE KEY-----', b'-----END PRIVATE KEY-----'],
                'rsa': [b'-----BEGIN RSA PRIVATE KEY-----', b'-----END RSA PRIVATE KEY-----']
            }
            
            extracted_count = 0
            
            for cert_type, (start_pattern, end_pattern) in cert_patterns.items():
                pos = 0
                while True:
                    start_pos = self.content.find(start_pattern, pos)
                    if start_pos == -1:
                        break
                        
                    end_pos = self.content.find(end_pattern, start_pos)
                    if end_pos != -1:
                        end_pos += len(end_pattern)
                        
                        cert_data = self.content[start_pos:end_pos]
                        cert_file = cert_dir / f"certificate_{extracted_count}.{cert_type}"
                        
                        with open(cert_file, 'wb') as f:
                            f.write(cert_data)
                        
                        extracted_count += 1
                        pos = end_pos
                    else:
                        pos = start_pos + len(start_pattern)
            
            if extracted_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {extracted_count} certificates{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Certificate extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_databases(self) -> bool:
        """Extract database files"""
        try:
            print(f"{Colors.BLUE}[*] Extracting database files...{Colors.ENDC}")
            
            db_dir = self.output_dir / "databases"
            db_dir.mkdir(exist_ok=True)
            
            # Look for database signatures
            db_signatures = {
                'sqlite': b'SQLite format 3',
                'access': b'Standard Jet DB',
                'mysql': b'MySQL'
            }
            
            extracted_count = 0
            
            for db_type, signature in db_signatures.items():
                pos = 0
                while True:
                    pos = self.content.find(signature, pos)
                    if pos == -1:
                        break
                        
                    # Extract database (estimate size)
                    db_data = self.content[pos:pos + 10*1024*1024]  # Max 10MB
                    db_file = db_dir / f"database_{extracted_count}.{db_type}"
                    
                    with open(db_file, 'wb') as f:
                        f.write(db_data)
                    
                    extracted_count += 1
                    pos += len(signature)
            
            if extracted_count > 0:
                print(f"{Colors.GREEN}[+] Extracted {extracted_count} database files{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Database extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_memory_patterns(self) -> bool:
        """Extract memory patterns and strings"""
        try:
            print(f"{Colors.BLUE}[*] Extracting memory patterns...{Colors.ENDC}")
            
            memory_dir = self.output_dir / "memory_patterns"
            memory_dir.mkdir(exist_ok=True)
            
            # Extract interesting memory patterns
            patterns = {
                'urls': rb'https?://[^\s<>"{}|\\^`\[\]]*',
                'emails': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'ips': rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'registry': rb'HKEY_[A-Z_]+\\[^\x00]*',
                'paths': rb'[A-Za-z]:\\[^\x00]*',
                'base64': rb'[A-Za-z0-9+/]{20,}={0,2}'
            }
            
            found_patterns = {}
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, self.content)
                if matches:
                    found_patterns[pattern_name] = matches
            
            if found_patterns:
                # Save patterns
                patterns_file = memory_dir / "extracted_patterns.txt"
                with open(patterns_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Memory patterns extracted from {self.filename}\n\n")
                    
                    for pattern_name, matches in found_patterns.items():
                        f.write(f"## {pattern_name.upper()} ({len(matches)} matches):\n")
                        for match in matches[:20]:  # First 20 matches
                            try:
                                decoded = match.decode('utf-8', errors='ignore')
                                f.write(f"- {decoded}\n")
                            except:
                                f.write(f"- {match}\n")
                        f.write("\n")
                
                total_matches = sum(len(matches) for matches in found_patterns.values())
                print(f"{Colors.GREEN}[+] Extracted {total_matches} memory patterns{Colors.ENDC}")
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Memory pattern extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_strings_advanced(self) -> bool:
        """Advanced string extraction"""
        try:
            print(f"{Colors.BLUE}[*] Advanced string extraction...{Colors.ENDC}")
            
            strings_dir = self.output_dir / "strings_analysis"
            strings_dir.mkdir(exist_ok=True)
            
            # Extract strings with different encodings
            encodings = ['utf-8', 'utf-16le', 'utf-16be', 'ascii', 'latin-1']
            
            for encoding in encodings:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    
                    # Find printable strings
                    strings = re.findall(r'[^\x00-\x1f\x7f-\x9f]{4,}', text)
                    
                    if strings:
                        strings_file = strings_dir / f"strings_{encoding}.txt"
                        with open(strings_file, 'w', encoding='utf-8') as f:
                            f.write(f"# Strings extracted with {encoding} encoding\n")
                            f.write(f"# Total strings: {len(strings)}\n\n")
                            
                            for string in strings[:1000]:  # First 1000 strings
                                f.write(f"{string}\n")
                        
                        print(f"{Colors.GREEN}[+] Extracted {len(strings)} strings ({encoding}){Colors.ENDC}")
                        
                except:
                    continue
            
            return True
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] String extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_assembly_code(self) -> bool:
        """Extract and disassemble assembly code"""
        try:
            print(f"{Colors.BLUE}[*] Extracting assembly code...{Colors.ENDC}")
            
            asm_dir = self.output_dir / "assembly_code"
            asm_dir.mkdir(exist_ok=True)
            
            # Try to disassemble with capstone
            try:
                import capstone
                
                # Disassemble x86-64 code
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                
                # Find potential code sections
                if self.pe:
                    for section in self.pe.sections:
                        if section.Characteristics & 0x20000000:  # Executable section
                            section_data = section.get_data()
                            
                            asm_file = asm_dir / f"section_{section.Name.decode('utf-8', errors='ignore').strip()}.asm"
                            with open(asm_file, 'w', encoding='utf-8') as f:
                                f.write(f"; Assembly code from section {section.Name}\n")
                                f.write(f"; Virtual Address: 0x{section.VirtualAddress:x}\n")
                                f.write(f"; Size: {len(section_data)} bytes\n\n")
                                
                                # Disassemble first 1000 instructions
                                count = 0
                                for instruction in md.disasm(section_data, section.VirtualAddress):
                                    f.write(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}\n")
                                    count += 1
                                    if count >= 1000:
                                        break
                            
                            print(f"{Colors.GREEN}[+] Disassembled section: {section.Name.decode('utf-8', errors='ignore').strip()}{Colors.ENDC}")
                
                return True
                
            except ImportError:
                print(f"{Colors.WARNING}[!] Capstone not available for disassembly{Colors.ENDC}")
                return False
                
        except Exception as e:
            print(f"{Colors.WARNING}[!] Assembly extraction failed: {e}{Colors.ENDC}")
            return False

    # Missing methods for Python extraction
    def extract_py2exe_advanced(self, python_dir: Path) -> bool:
        """Advanced py2exe extraction"""
        try:
            print(f"{Colors.BLUE}[*] py2exe extraction...{Colors.ENDC}")
            
            py2exe_signatures = [b'py2exe', b'library.zip', b'python27.dll']
            
            if not any(sig in self.content for sig in py2exe_signatures):
                return False
                
            print(f"{Colors.GREEN}[+] py2exe signatures detected{Colors.ENDC}")
            
            # Look for embedded library.zip
            zip_pos = self.content.find(b'PK\x03\x04')
            if zip_pos != -1:
                py2exe_dir = python_dir / "py2exe_extracted"
                py2exe_dir.mkdir(exist_ok=True)
                
                # Extract ZIP archive
                zip_data = self.content[zip_pos:zip_pos + 10*1024*1024]  # Max 10MB
                zip_file = py2exe_dir / "library.zip"
                
                with open(zip_file, 'wb') as f:
                    f.write(zip_data)
                
                # Try to extract ZIP contents
                try:
                    import zipfile
                    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                        zip_ref.extractall(py2exe_dir)
                        
                    # Decompile extracted .pyc files
                    self.decompile_all_pyc_files(py2exe_dir)
                    
                    return True
                except:
                    pass
                    
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] py2exe extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_cxfreeze_advanced(self, python_dir: Path) -> bool:
        """Advanced cx_Freeze extraction"""
        try:
            print(f"{Colors.BLUE}[*] cx_Freeze extraction...{Colors.ENDC}")
            
            cxfreeze_signatures = [b'cx_Freeze', b'__startup__', b'__main__']
            
            if not any(sig in self.content for sig in cxfreeze_signatures):
                return False
                
            print(f"{Colors.GREEN}[+] cx_Freeze signatures detected{Colors.ENDC}")
            
            cxfreeze_dir = python_dir / "cxfreeze_extracted"
            cxfreeze_dir.mkdir(exist_ok=True)
            
            # Extract embedded modules
            self.extract_python_bytecode(cxfreeze_dir)
            
            return True
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] cx_Freeze extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_nuitka_advanced(self, python_dir: Path) -> bool:
        """Advanced Nuitka extraction"""
        try:
            print(f"{Colors.BLUE}[*] Nuitka extraction...{Colors.ENDC}")
            
            nuitka_signatures = [b'nuitka', b'__nuitka__']
            
            if not any(sig in self.content for sig in nuitka_signatures):
                return False
                
            print(f"{Colors.GREEN}[+] Nuitka signatures detected{Colors.ENDC}")
            
            nuitka_dir = python_dir / "nuitka_extracted"
            nuitka_dir.mkdir(exist_ok=True)
            
            # Nuitka creates compiled C++ code, extract strings
            self.extract_strings_advanced()
            
            return True
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Nuitka extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_python_code_raw(self, python_dir: Path) -> bool:
        """Raw Python code extraction"""
        try:
            print(f"{Colors.BLUE}[*] Raw Python code extraction...{Colors.ENDC}")
            
            raw_dir = python_dir / "raw_python"
            raw_dir.mkdir(exist_ok=True)
            
            # Look for Python code patterns
            python_patterns = [
                rb'def\s+\w+\s*\(',
                rb'class\s+\w+\s*\(',
                rb'import\s+\w+',
                rb'from\s+\w+\s+import'
            ]
            
            found_python = False
            
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    text = self.content.decode(encoding, errors='ignore')
                    
                    for pattern in python_patterns:
                        pattern_str = pattern.decode('utf-8', errors='ignore')
                        if re.search(pattern_str, text, re.IGNORECASE):
                            found_python = True
                            break
                    
                    if found_python:
                        python_file = raw_dir / f"extracted_python_{encoding}.py"
                        with open(python_file, 'w', encoding='utf-8') as f:
                            f.write(f"# Python code extracted from {self.filename}\n")
                            f.write(f"# Encoding: {encoding}\n\n")
                            
                            # Extract Python functions
                            functions = re.findall(r'def\s+\w+\s*\([^)]*\):[^:]*?(?=\ndef|\nclass|\n\n|\Z)', text, re.DOTALL)
                            for func in functions[:10]:  # First 10 functions
                                f.write(f"{func}\n\n")
                            

                            # Extract Python classes
                            classes = re.findall(r'class\s+\w+[^:]*:[^:]*?(?=\nclass|\ndef|\n\n|\Z)', text, re.DOTALL)
                            for cls in classes[:5]:  # First 5 classes
                                f.write(f"{cls}\n\n")
                        
                        print(f"{Colors.GREEN}[+] Extracted raw Python code ({encoding}){Colors.ENDC}")
                        
                except:
                    continue
            
            return found_python
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Raw Python extraction failed: {e}{Colors.ENDC}")
            return False
    
    def extract_python_bytecode(self, python_dir: Path) -> bool:
        """Extract Python bytecode files"""
        try:
            print(f"{Colors.BLUE}[*] Python bytecode extraction...{Colors.ENDC}")
            
            bytecode_dir = python_dir / "bytecode_files"
            bytecode_dir.mkdir(exist_ok=True)
            
            # Look for Python bytecode magic numbers
            bytecode_magic = [
                b'\x03\xf3\r\n',  # Python 2.7
                b'\x33\x0d\r\n',  # Python 3.0
                b'\x9c\x0c\r\n',  # Python 3.1
                b'\xee\x0c\r\n',  # Python 3.8
                b'\x61\x0d\r\n',  # Python 3.9
                b'\x55\x0d\r\n',  # Python 3.10
                b'\xa7\x0d\r\n',  # Python 3.11
            ]
            
            found_bytecode = []
            
            for magic in bytecode_magic:
                pos = 0
                while True:
                    pos = self.content.find(magic, pos)
                    if pos == -1:
                        break
                        
                    # Extract potential bytecode
                    bytecode_data = self.content[pos:pos + 1024*1024]  # Max 1MB
                    bytecode_file = bytecode_dir / f"bytecode_{len(found_bytecode)}.pyc"
                    
                    with open(bytecode_file, 'wb') as f:
                        f.write(bytecode_data)
                    
                    found_bytecode.append(bytecode_file)
                    pos += len(magic)
            
            if found_bytecode:
                print(f"{Colors.GREEN}[+] Found {len(found_bytecode)} potential bytecode files{Colors.ENDC}")
                
                # Try to decompile all found bytecode
                for bytecode_file in found_bytecode:
                    self.try_decompile_bytecode(bytecode_file, python_dir)
                
                return True
                
            return False
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Bytecode extraction failed: {e}{Colors.ENDC}")
            return False

    def create_extraction_report(self):
        """Create comprehensive extraction report"""
        try:
            print(f"{Colors.BLUE}[*] Creating extraction report...{Colors.ENDC}")
            
            report_file = self.output_dir / "EXTRACTION_REPORT.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("# xDecompiler Enhanced - Rapport d'extraction maximale\n\n")
                f.write(f"**Fichier analysé:** {self.filename}\n")
                f.write(f"**Date d'extraction:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Taille du fichier:** {len(self.content):,} bytes\n")
                f.write(f"**Hash SHA256:** {hashlib.sha256(self.content).hexdigest()}\n\n")
                
                f.write("## Résumé de l'extraction\n\n")
                
                # Compter les fichiers extraits
                extracted_count = 0
                for root, dirs, files in os.walk(self.output_dir):
                    extracted_count += len(files)
                
                f.write(f"- **Fichiers totaux extraits:** {extracted_count}\n")
                f.write(f"- **Dossier de sortie:** {self.output_dir}\n\n")
                
                f.write("## Contenu extrait par catégorie\n\n")
                
                # Lister les sous-dossiers
                categories = {}
                for item in sorted(self.output_dir.iterdir()):
                    if item.is_dir():
                        file_count = sum(1 for _ in item.rglob('*') if _.is_file())
                        categories[item.name] = file_count
                        f.write(f"- **{item.name}**: {file_count} fichiers\n")
                
                f.write("\n## Méthodes d'extraction utilisées\n\n")
                f.write("1. **Détection de fichiers intégrés**: Analyse par signatures binaires\n")
                f.write("2. **Extraction spécialisée par langage**: Python, .NET, Java, JavaScript, C++\n")
                f.write("3. **Correspondance de motifs de code**: Détection avancée de code par regex\n")
                f.write("4. **Extraction de ressources**: Ressources PE, images, certificats\n")
                f.write("5. **Analyse de motifs mémoire**: Reconnaissance de motifs binaires\n")
                f.write("6. **Analyse de chaînes**: Extraction multi-encodage\n")
                f.write("7. **Désassemblage**: Code assembleur des sections exécutables\n\n")
                
                f.write("## Résultats par type de contenu\n\n")
                
                # Analyser le contenu par type
                content_analysis = {
                    "Scripts Python": categories.get("python_extraction", 0),
                    "Code JavaScript": categories.get("javascript_extraction", 0),
                    "Code C#/.NET": categories.get("dotnet_extraction", 0),
                    "Code Java": categories.get("java_extraction", 0),
                    "Code C++": categories.get("cpp_extraction", 0),
                    "Scripts AutoHotkey": categories.get("autohotkey_extraction", 0),
                    "Applications Electron": categories.get("electron_extraction", 0),
                    "Fichiers intégrés": categories.get("embedded_files", 0),
                    "Ressources PE": categories.get("resources", 0),
                    "Motifs de code": categories.get("code_patterns", 0),
                    "Fichiers de configuration": categories.get("configuration_files", 0),
                    "Certificats": categories.get("certificates", 0),
                    "Bases de données": categories.get("databases", 0),
                    "Motifs mémoire": categories.get("memory_patterns", 0),
                    "Analyse de chaînes": categories.get("strings_analysis", 0),
                    "Code assembleur": categories.get("assembly_code", 0),
                    "Données overlay": categories.get("overlay_data", 0)
                }
                
                for content_type, count in content_analysis.items():
                    if count > 0:
                        f.write(f"✅ **{content_type}**: {count} éléments extraits\n")
                    else:
                        f.write(f"❌ **{content_type}**: Aucun élément trouvé\n")
                
                f.write("\n## Recommandations d'analyse\n\n")
                
                if categories.get("python_extraction", 0) > 0:
                    f.write("🐍 **Python**: Vérifiez les dossiers de décompilation Python pour le code source\n")
                
                if categories.get("embedded_files", 0) > 0:
                    f.write("📦 **Fichiers intégrés**: Examinez les archives extraites pour plus de contenu\n")
                
                if categories.get("code_patterns", 0) > 0:
                    f.write("🔍 **Motifs de code**: Analysez les patterns pour identifier le code source potentiel\n")
                
                if categories.get("strings_analysis", 0) > 0:
                    f.write("📝 **Chaînes**: Recherchez des informations de configuration dans l'analyse de chaînes\n")
                
                if categories.get("resources", 0) > 0:
                    f.write("🎨 **Ressources**: Examinez les ressources extraites (icônes, manifestes, etc.)\n")
                
                f.write("\n## Outils recommandés pour analyse approfondie\n\n")
                f.write("- **Python**: uncompyle6, decompyle3, pycdc\n")
                f.write("- **.NET**: ILSpy, dotPeek, Reflexil, dnSpy\n")
                f.write("- **Java**: jadx, jd-gui, CFR, Procyon\n")
                f.write("- **JavaScript**: js-beautify, babel, ESLint\n")
                f.write("- **Analyse binaire**: Ghidra, IDA Pro, radare2, x64dbg\n")
                f.write("- **Analyse PE**: PE-bear, CFF Explorer, PEiD\n")
                f.write("- **Hex editors**: HxD, 010 Editor, ImHex\n\n")
                
                f.write("## Structure des dossiers\n\n")
                f.write("```\n")
                f.write(f"{self.output_dir.name}/\n")
                for item in sorted(self.output_dir.iterdir()):
                    if item.is_dir():
                        f.write(f"├── {item.name}/\n")
                        
                        # Lister quelques fichiers d'exemple
                        files = list(item.iterdir())[:3]
                        for i, file in enumerate(files):
                            if i == len(files) - 1 and len(list(item.iterdir())) <= 3:
                                f.write(f"│   └── {file.name}\n")
                            else:
                                f.write(f"│   ├── {file.name}\n")
                        
                        if len(list(item.iterdir())) > 3:
                            f.write(f"│   └── ... et {len(list(item.iterdir())) - 3} autres fichiers\n")
                
                f.write("└── EXTRACTION_REPORT.md\n")
                f.write("```\n\n")
                
                f.write("---\n")
                f.write("*Rapport généré par xDecompiler Enhanced*\n")
            
            print(f"{Colors.GREEN}[+] Rapport d'extraction créé: {report_file}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Échec de création du rapport: {e}{Colors.ENDC}")

def main():
    """Main function"""
    print(f"{Colors.HEADER}")
    print("=" * 60)
    print("    xDecompiler Enhanced - Maximum Extraction Tool")
    print("    Extract ALL possible source code from executables")
    print("=" * 60)
    print(f"{Colors.ENDC}")
    
    if len(sys.argv) != 2:
        print(f"{Colors.BLUE}Usage: python xdecompiler_enhanced.py <executable_file>{Colors.ENDC}")
        print(f"{Colors.BLUE}Example: python xdecompiler_enhanced.py ComfyUI.exe{Colors.ENDC}")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    if not os.path.exists(filename):
        print(f"{Colors.FAIL}[!] File not found: {filename}{Colors.ENDC}")
        sys.exit(1)
    
    # Create extractor
    extractor = MaxExtractor(filename)
    
    # Load file
    if not extractor.load_file():
        print(f"{Colors.FAIL}[!] Failed to load file{Colors.ENDC}")
        sys.exit(1)
    
    # Extract everything
    print(f"{Colors.HEADER}[*] Starting maximum extraction...{Colors.ENDC}")
    start_time = time.time()
    
    success = extractor.extract_everything()
    
    end_time = time.time()
    duration = end_time - start_time
    
    if success:
        print(f"{Colors.GREEN}")
        print("=" * 60)
        print(f"    EXTRACTION COMPLETED SUCCESSFULLY")
        print(f"    Duration: {duration:.2f} seconds")
        print(f"    Output Directory: {extractor.output_dir}")
        print("=" * 60)
        print(f"{Colors.ENDC}")
        
        # Open output directory
        try:
            if os.name == 'nt':  # Windows
                os.startfile(str(extractor.output_dir))
            else:  # Unix/Linux/Mac
                subprocess.run(['xdg-open', str(extractor.output_dir)])
        except:
            pass
    else:
        print(f"{Colors.WARNING}")
        print("=" * 60)
        print(f"    EXTRACTION COMPLETED WITH WARNINGS")
        print(f"    Some content may have been extracted")
        print(f"    Check output directory: {extractor.output_dir}")
        print("=" * 60)
        print(f"{Colors.ENDC}")

if __name__ == "__main__":
    main()
