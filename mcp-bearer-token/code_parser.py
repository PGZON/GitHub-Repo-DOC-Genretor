import os
import re
import ast
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional, Union
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("code_parser")

# Constants
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
SKIP_EXTENSIONS = {'.pyc', '.min.js', '.map', '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'}
IGNORE_DIRS = {'.git', 'node_modules', 'dist', 'build', '__pycache__', 'venv', '.venv', 'env'}

# Language mapping
LANGUAGE_EXTENSIONS = {
    '.py': 'Python',
    '.ipynb': 'Jupyter Notebook',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.jsx': 'React JSX',
    '.tsx': 'React TSX',
    '.java': 'Java',
    '.php': 'PHP',
    '.rb': 'Ruby',
    '.go': 'Go',
    '.rs': 'Rust',
    '.c': 'C',
    '.cpp': 'C++',
    '.h': 'C/C++ Header',
    '.hpp': 'C++ Header',
    '.cs': 'C#',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.scala': 'Scala',
    '.html': 'HTML',
    '.css': 'CSS',
    '.scss': 'SCSS',
    '.sass': 'Sass',
    '.less': 'Less',
    '.md': 'Markdown',
    '.json': 'JSON',
    '.yml': 'YAML',
    '.yaml': 'YAML',
    '.xml': 'XML',
    '.sql': 'SQL',
    '.sh': 'Shell',
    '.bash': 'Bash',
    '.ps1': 'PowerShell'
}

# Framework detection patterns
FRAMEWORK_PATTERNS = {
    'Python': {
        'Flask': ['from flask import', 'import flask'],
        'Django': ['from django import', 'import django', 'from django.'],
        'FastAPI': ['from fastapi import', 'import fastapi'],
        'Pytest': ['import pytest', 'from pytest import'],
        'SQLAlchemy': ['from sqlalchemy import', 'import sqlalchemy'],
        'PyTorch': ['import torch', 'from torch import'],
        'TensorFlow': ['import tensorflow', 'from tensorflow import'],
        'Pandas': ['import pandas', 'from pandas import'],
        'NumPy': ['import numpy', 'from numpy import']
    },
    'JavaScript': {
        'React': ['import React', 'from "react"', "from 'react'"],
        'Express': ['require("express")', "require('express')", 'import express'],
        'Vue': ['import Vue', 'from "vue"', "from 'vue'"],
        'Angular': ['@angular/core', 'from "@angular', "from '@angular"],
        'Next.js': ['from "next/', "from 'next/"],
        'Jest': ['import jest', 'from "jest"', "from 'jest'"],
        'jQuery': ['import $', 'import jQuery']
    }
}

class CodeParser:
    """
    Parses code files in a repository to extract:
    - Functions, classes and their methods
    - API routes
    - Frameworks and libraries used
    """
    
    def __init__(self, repo_path: str):
        """
        Initialize with repository path
        """
        self.repo_path = Path(repo_path)
        
    def get_relative_path(self, path: Path) -> str:
        """Convert absolute path to path relative to repo root"""
        return str(path.relative_to(self.repo_path))
        
    def should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on size or extension"""
        # Skip based on extension
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            return True
            
        # Skip if file is too large
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return True
            
        return False
        
    def should_skip_dir(self, dir_path: Path) -> bool:
        """Check if directory should be skipped"""
        return any(part in IGNORE_DIRS for part in dir_path.parts)
    
    def detect_language(self, file_path: Path) -> str:
        """Detect language based on file extension"""
        ext = file_path.suffix.lower()
        return LANGUAGE_EXTENSIONS.get(ext, "Unknown")
        
    def count_lines(self, file_path: Path) -> int:
        """Count lines in a file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def parse_python_file(self, file_path: Path) -> Dict:
        """
        Parse Python file to extract functions, classes, and potential API routes
        """
        result = {
            "functions": [],
            "classes": [],
            "api_routes": [],
            "imports": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse imports for framework detection
            import_pattern = r'^(?:from|import)\s+([a-zA-Z0-9_.]+)'
            imports = re.findall(import_pattern, content, re.MULTILINE)
            result["imports"] = imports
            
            # Parse Python AST to extract functions and classes
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Extract functions
                if isinstance(node, ast.FunctionDef):
                    docstring = ast.get_docstring(node) or ""
                    # Trim docstring to first 150 chars if too long
                    if docstring and len(docstring) > 150:
                        docstring = docstring[:150] + "..."
                        
                    func_info = {
                        "name": node.name,
                        "docstring": docstring,
                        "line": node.lineno
                    }
                    
                    # Check if this might be a route handler based on decorators
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr'):
                            if decorator.func.attr in ['route', 'get', 'post', 'put', 'delete', 'patch']:
                                # This is likely a Flask/FastAPI style route
                                path = ""
                                method = decorator.func.attr.upper() if decorator.func.attr != 'route' else 'GET'
                                
                                # Extract path from decorator args
                                if decorator.args:
                                    path = ast.literal_eval(decorator.args[0])
                                
                                # Extract HTTP method for @route decorators
                                if method == 'GET' and len(decorator.keywords) > 0:
                                    for keyword in decorator.keywords:
                                        if keyword.arg == 'methods':
                                            try:
                                                methods = ast.literal_eval(keyword.value)
                                                method = methods[0] if methods else 'GET'
                                            except:
                                                pass
                                
                                route_info = {
                                    "method": method,
                                    "path": path,
                                    "handler": node.name,
                                    "line": node.lineno
                                }
                                result["api_routes"].append(route_info)
                    
                    result["functions"].append(func_info)
                
                # Extract classes and their methods
                elif isinstance(node, ast.ClassDef):
                    methods = []
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            methods.append(item.name)
                    
                    class_info = {
                        "name": node.name,
                        "methods": methods,
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node) or ""
                    }
                    result["classes"].append(class_info)
            
            return result
            
        except SyntaxError:
            logger.warning(f"Syntax error in Python file: {file_path}")
            return result
        except Exception as e:
            logger.warning(f"Error parsing Python file {file_path}: {str(e)}")
            return result
    
    def parse_javascript_file(self, file_path: Path) -> Dict:
        """
        Parse JavaScript/TypeScript file to extract functions, classes, and API routes
        using regex patterns (less precise than AST but more versatile)
        """
        result = {
            "functions": [],
            "classes": [],
            "api_routes": [],
            "imports": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract imports for framework detection
            import_pattern = r'(?:import\s+.+\s+from\s+[\'"]([^\'"]+)[\'"]|require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\))'
            imports = re.findall(import_pattern, content)
            # Flatten the tuple list from re.findall
            imports = [imp[0] or imp[1] for imp in imports]
            result["imports"] = imports
            
            # Extract functions
            # Match: function name(...) {...}, const name = function(...) {...}, const name = (...) => {...}
            function_patterns = [
                r'function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)',
                r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*function\s*\(',
                r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*\([^)]*\)\s*=>'
            ]
            
            line_numbers = content.split('\n')
            for pattern in function_patterns:
                for match in re.finditer(pattern, content):
                    func_name = match.group(1)
                    # Find line number by counting newlines before match position
                    line_no = content[:match.start()].count('\n') + 1
                    
                    # Try to extract a simple comment above the function
                    docstring = ""
                    if line_no > 1:
                        # Check for JSDoc style comments
                        before_lines = content[:match.start()].split('\n')
                        comment_lines = []
                        for i in range(len(before_lines) - 1, max(0, len(before_lines) - 5), -1):
                            line = before_lines[i].strip()
                            if line.startswith('//') or line.startswith('*'):
                                comment_lines.insert(0, line.lstrip('/* '))
                            elif line.startswith('/**'):
                                comment_lines.insert(0, line.lstrip('/* '))
                                break
                            elif not line:
                                continue
                            else:
                                break
                        if comment_lines:
                            docstring = ' '.join(comment_lines)
                            if len(docstring) > 150:
                                docstring = docstring[:150] + "..."
                    
                    result["functions"].append({
                        "name": func_name,
                        "docstring": docstring,
                        "line": line_no
                    })
            
            # Extract ES6 classes
            class_pattern = r'class\s+([a-zA-Z0-9_$]+)'
            method_pattern = r'(?:async\s+)?([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*{'
            
            for match in re.finditer(class_pattern, content):
                class_name = match.group(1)
                class_start_pos = match.start()
                class_start_line = content[:class_start_pos].count('\n') + 1
                
                # Find class body by matching opening and closing braces
                brace_count = 0
                class_body_start = content.find('{', class_start_pos)
                class_body_end = class_body_start
                
                for i in range(class_body_start, len(content)):
                    if content[i] == '{':
                        brace_count += 1
                    elif content[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            class_body_end = i
                            break
                
                class_body = content[class_body_start:class_body_end]
                methods = re.findall(method_pattern, class_body)
                
                result["classes"].append({
                    "name": class_name,
                    "methods": methods,
                    "line": class_start_line
                })
            
            # Extract API routes
            # Express.js route patterns
            express_patterns = [
                r'(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'app\.use\s*\(\s*[\'"]([^\'"]+)[\'"]'
            ]
            
            for pattern in express_patterns:
                for match in re.finditer(pattern, content):
                    route_path = match.group(1)
                    line_no = content[:match.start()].count('\n') + 1
                    
                    # Determine HTTP method from the match
                    if 'get(' in match.group(0).lower():
                        method = 'GET'
                    elif 'post(' in match.group(0).lower():
                        method = 'POST'
                    elif 'put(' in match.group(0).lower():
                        method = 'PUT'
                    elif 'delete(' in match.group(0).lower():
                        method = 'DELETE'
                    elif 'patch(' in match.group(0).lower():
                        method = 'PATCH'
                    else:
                        method = 'USE'  # For app.use()
                    
                    # Try to extract handler function name
                    handler = "unknown_handler"
                    handler_match = re.search(r'\(\s*[\'"][^\'"]+[\'"]\s*,\s*([a-zA-Z0-9_$]+)', match.group(0))
                    if handler_match:
                        handler = handler_match.group(1)
                    
                    result["api_routes"].append({
                        "method": method,
                        "path": route_path,
                        "handler": handler,
                        "line": line_no
                    })
            
            return result
            
        except Exception as e:
            logger.warning(f"Error parsing JavaScript file {file_path}: {str(e)}")
            return result
    
    def detect_frameworks(self, file_contents: Dict[str, Dict], file_extensions: Dict[str, int]) -> Dict[str, List[str]]:
        """
        Detect frameworks used in the codebase based on imports and file patterns
        
        Args:
            file_contents: Dictionary mapping file paths to parsed content
            file_extensions: Dictionary counting file extensions
            
        Returns:
            Dictionary mapping languages to lists of frameworks
        """
        frameworks = defaultdict(set)
        
        # Detect from file extensions
        languages = {LANGUAGE_EXTENSIONS.get(ext, "Unknown") for ext in file_extensions.keys()}
        
        # Special case detection from config files
        config_files = [f for f in file_contents.keys() if Path(f).name in [
            'package.json', 'requirements.txt', 'pyproject.toml', 'pom.xml', 'build.gradle'
        ]]
        
        for config_file in config_files:
            if 'package.json' in config_file:
                try:
                    with open(os.path.join(self.repo_path, config_file), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    for dep in deps:
                        if dep == 'react':
                            frameworks['JavaScript'].add('React')
                        elif dep == 'vue':
                            frameworks['JavaScript'].add('Vue')
                        elif dep == 'express':
                            frameworks['JavaScript'].add('Express')
                        elif dep == 'next':
                            frameworks['JavaScript'].add('Next.js')
                        elif dep == 'angular' or dep.startswith('@angular/'):
                            frameworks['JavaScript'].add('Angular')
                except:
                    pass
                    
            elif 'requirements.txt' in config_file:
                try:
                    with open(os.path.join(self.repo_path, config_file), 'r', encoding='utf-8') as f:
                        requirements = f.read().lower()
                        
                    if 'django' in requirements:
                        frameworks['Python'].add('Django')
                    if 'flask' in requirements:
                        frameworks['Python'].add('Flask')
                    if 'fastapi' in requirements:
                        frameworks['Python'].add('FastAPI')
                    if 'pytest' in requirements:
                        frameworks['Python'].add('Pytest')
                    if 'tensorflow' in requirements:
                        frameworks['Python'].add('TensorFlow')
                    if 'torch' in requirements:
                        frameworks['Python'].add('PyTorch')
                    if 'pandas' in requirements:
                        frameworks['Python'].add('Pandas')
                except:
                    pass
        
        # Check imports in files
        for file_path, content in file_contents.items():
            file_lang = self.detect_language(Path(file_path))
            
            if file_lang in FRAMEWORK_PATTERNS:
                imports = content.get('imports', [])
                import_str = ' '.join(imports)
                
                for framework, patterns in FRAMEWORK_PATTERNS[file_lang].items():
                    for pattern in patterns:
                        if pattern in import_str:
                            frameworks[file_lang].add(framework)
                            break
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in frameworks.items() if v}
    
    def parse_repo(self, mode: str = "full") -> Dict:
        """
        Parse repository to extract code structure, functions, classes, and API routes
        
        Args:
            mode: Parsing mode - "quick", "full", or "selective"
            
        Returns:
            Dictionary with parsed repository information
        """
        repo_summary = {
            "project_name": self.repo_path.name,
            "languages": {},
            "file_count": 0,
            "source_file_count": 0,
            "folders": [],
            "files": [],
            "functions": [],
            "classes": [],
            "api_routes": [],
            "frameworks": {},
            "special_files": {}
        }
        
        # Track extensions for language distribution
        file_extensions = {}
        
        # Store parsed file contents for framework detection
        file_contents = {}
        
        # Determine max depth based on scan mode
        max_depth = None
        if mode == "quick":
            max_depth = 2
            
        # Set selective mode file extensions
        selective_extensions = None
        if mode == "selective":
            selective_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java'}
        
        # Track folders
        folders = []
        
        # Walk repository
        for root, dirs, files in os.walk(self.repo_path):
            rel_path = os.path.relpath(root, self.repo_path)
            if rel_path == ".":
                rel_path = ""
            
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self.should_skip_dir(Path(root) / d)]
            
            # Check depth limit for quick scan
            if max_depth is not None and rel_path.count(os.sep) >= max_depth:
                dirs[:] = []  # Don't go deeper
                continue
            
            # Add folder to list
            if rel_path:
                folders.append(rel_path)
            
            # Create folder info
            folder_info = {
                "path": rel_path,
                "files": []
            }
            
            # Process files
            for file_name in files:
                file_path = Path(root) / file_name
                rel_file_path = self.get_relative_path(file_path)
                
                # Skip files based on criteria
                if self.should_skip_file(file_path):
                    continue
                    
                # Skip files not in selective_extensions in selective mode
                if selective_extensions and file_path.suffix not in selective_extensions:
                    continue
                
                # Track file extension
                ext = file_path.suffix.lower()
                file_extensions[ext] = file_extensions.get(ext, 0) + 1
                
                # Parse file based on type
                file_info = {
                    "path": rel_file_path,
                    "size": file_path.stat().st_size,
                    "language": self.detect_language(file_path),
                    "line_count": self.count_lines(file_path)
                }
                
                # Add to folder files
                folder_info["files"].append(file_name)
                
                # Add to repo files
                repo_summary["files"].append(file_info)
                
                # Parse code in the file based on language
                if ext == '.py':
                    content = self.parse_python_file(file_path)
                    file_contents[rel_file_path] = content
                    
                    # Add functions with file path
                    for func in content["functions"]:
                        repo_summary["functions"].append({
                            "file": rel_file_path,
                            **func
                        })
                    
                    # Add classes with file path
                    for cls in content["classes"]:
                        repo_summary["classes"].append({
                            "file": rel_file_path,
                            **cls
                        })
                    
                    # Add API routes with file path
                    for route in content["api_routes"]:
                        repo_summary["api_routes"].append({
                            "file": rel_file_path,
                            **route
                        })
                
                elif ext in ['.js', '.ts', '.jsx', '.tsx']:
                    content = self.parse_javascript_file(file_path)
                    file_contents[rel_file_path] = content
                    
                    # Add functions with file path
                    for func in content["functions"]:
                        repo_summary["functions"].append({
                            "file": rel_file_path,
                            **func
                        })
                    
                    # Add classes with file path
                    for cls in content["classes"]:
                        repo_summary["classes"].append({
                            "file": rel_file_path,
                            **cls
                        })
                    
                    # Add API routes with file path
                    for route in content["api_routes"]:
                        repo_summary["api_routes"].append({
                            "file": rel_file_path,
                            **route
                        })
                
                # Check for special files
                if file_name.lower() == "readme.md":
                    repo_summary["special_files"]["readme"] = {
                        "path": rel_file_path,
                        "size": file_path.stat().st_size
                    }
                elif file_name.lower() in ["license", "license.txt", "license.md"]:
                    repo_summary["special_files"]["license"] = {
                        "path": rel_file_path,
                        "size": file_path.stat().st_size
                    }
                
                repo_summary["file_count"] += 1
                if ext in LANGUAGE_EXTENSIONS:
                    repo_summary["source_file_count"] += 1
            
            # Add folder info if it has files or we're in full mode
            if folder_info["files"] or mode == "full":
                repo_summary["folders"].append(folder_info)
        
        # Calculate language distribution
        languages = {}
        total_files = sum(file_extensions.values())
        for ext, count in file_extensions.items():
            if ext in LANGUAGE_EXTENSIONS:
                lang = LANGUAGE_EXTENSIONS[ext]
                languages[lang] = languages.get(lang, 0) + count
        
        # Calculate percentages
        repo_summary["languages"] = {
            lang: round((count / total_files) * 100, 1) 
            for lang, count in languages.items()
        }
        
        # Detect frameworks
        repo_summary["frameworks"] = self.detect_frameworks(file_contents, file_extensions)
        
        # Enforce limits on output size
        if len(repo_summary["functions"]) > 100:
            repo_summary["functions"] = repo_summary["functions"][:100]
            repo_summary["functions_truncated"] = True
            
        if len(repo_summary["classes"]) > 50:
            repo_summary["classes"] = repo_summary["classes"][:50]
            repo_summary["classes_truncated"] = True
            
        if len(repo_summary["api_routes"]) > 50:
            repo_summary["api_routes"] = repo_summary["api_routes"][:50]
            repo_summary["api_routes_truncated"] = True
            
        return repo_summary
