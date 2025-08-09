import os
import re
import json
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import httpx
from httpx import HTTPStatusError, RequestError
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
import base64

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("repo_analyzer")

# Constants
GITHUB_API_BASE = "https://api.github.com"
IGNORE_DIRS = {'.git', 'node_modules', 'dist', 'build', '__pycache__', 'venv', '.venv', 'env'}
IGNORE_FILES = {'.DS_Store', '.gitignore', '.env'}
SOURCE_EXTENSIONS = {
    '.py', '.js', '.java', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go', '.rs', 
    '.cs', '.cpp', '.c', '.h', '.hpp', '.swift', '.kt', '.scala', '.html', '.css',
    '.scss', '.sass', '.less'
}
CONFIG_FILES = {
    'requirements.txt', 'package.json', 'pyproject.toml', 'build.gradle', 'pom.xml',
    'Gemfile', 'Cargo.toml', '.gitignore', 'Dockerfile', 'docker-compose.yml', '.env.example'
}
ENTRY_POINT_FILES = {
    'main.py', 'app.py', 'index.js', 'server.js', 'app.js', 'index.html',
    'index.php', 'main.rs', 'Main.java', 'Program.cs'
}

# Paths
TEMP_DIR = Path(tempfile.gettempdir()) / "quickstack_repos"
DOCS_DIR = Path("docs")

class GitHubRepoAnalyzer:
    """
    GitHub Repository Analyzer.
    Downloads and analyzes GitHub repositories to extract structure and key information.
    """
    
    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize with optional GitHub token for private repo access
        """
        self.github_token = github_token
        self.headers = {}
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"
        
        # Create temp directory if it doesn't exist
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        DOCS_DIR.mkdir(parents=True, exist_ok=True)
        
    async def validate_github_url(self, url: str) -> Tuple[bool, str, str, str]:
        """
        Validate that a URL is a GitHub repository URL.
        Returns: (is_valid, error_message, username, repo_name)
        """
        parsed = urlparse(url)
        
        # Check if it's a GitHub URL
        if not parsed.netloc.endswith("github.com"):
            return False, "URL must be a GitHub repository URL", "", ""
        
        # Clean up URL
        if url.endswith('.git'):
            url = url[:-4]
        
        # Extract username and repository name
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            return False, "Invalid GitHub repository URL format", "", ""
        
        username, repo_name = path_parts[0], path_parts[1]
        
        # Remove .git suffix from repo name if present
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
            
        print(f"Validating GitHub repository: {username}/{repo_name}")
        
        # First try with token if available
        if self.github_token:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{GITHUB_API_BASE}/repos/{username}/{repo_name}", 
                        headers=self.headers,
                        timeout=10
                    )
                    
                if response.status_code == 200:
                    print(f"✓ Repository validated with token: {username}/{repo_name}")
                    return True, "", username, repo_name
                    
                # Try to handle specific error codes
                if response.status_code == 404:
                    return False, f"Repository not found: {username}/{repo_name}", username, repo_name
                elif response.status_code == 403:
                    print("⚠️ Rate limit or permission issue with token, trying public access...")
                    # Fall through to try without token
                elif response.status_code == 401:
                    print("⚠️ Token authentication failed, trying public access...")
                    # Fall through to try without token
                else:
                    print(f"⚠️ GitHub API error: HTTP {response.status_code}")
                    try:
                        error_detail = response.json()
                        if 'message' in error_detail:
                            print(f"API Error message: {error_detail['message']}")
                    except:
                        pass
                    # Fall through to try without token
            except Exception as e:
                print(f"⚠️ Error during token validation: {str(e)}")
                # Fall through to try without token
        
        # Try without token for public repos
        try:
            async with httpx.AsyncClient() as client:
                # Try with a more browser-like user agent
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                
                # First try API call
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{username}/{repo_name}", 
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"✓ Repository validated with public access: {username}/{repo_name}")
                    return True, "", username, repo_name
                
                # If API fails, try HEAD request to the main repo page
                if response.status_code in (403, 401, 404):
                    # Try direct web URL
                    web_url = f"https://github.com/{username}/{repo_name}"
                    web_response = await client.head(
                        web_url,
                        headers=headers,
                        timeout=10,
                        follow_redirects=True
                    )
                    
                    if web_response.status_code == 200:
                        print(f"✓ Repository exists (verified by web URL): {username}/{repo_name}")
                        return True, "", username, repo_name
                
                # Handle error details
                if response.status_code == 404:
                    return False, f"Repository not found: {username}/{repo_name}", username, repo_name
                elif response.status_code == 403:
                    error_detail = "Rate limit exceeded"
                    try:
                        error_json = response.json()
                        if 'message' in error_json:
                            error_detail = error_json['message']
                    except:
                        pass
                    return False, f"GitHub API: {error_detail}", username, repo_name
                elif response.status_code == 401:
                    return False, "Authentication required. This may be a private repository.", username, repo_name
                else:
                    return False, f"Error accessing repository: HTTP {response.status_code}", username, repo_name
                
        except httpx.RequestError as e:
            return False, f"Network error when contacting GitHub: {str(e)}", username, repo_name
        except Exception as e:
            return False, f"Error validating repository: {str(e)}", username, repo_name
    
    async def check_repo_size(self, username: str, repo_name: str) -> Tuple[int, str]:
        """
        Check the repository size using the GitHub API.
        Returns: (size_in_kb, size_warning)
        """
        warning = ""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{username}/{repo_name}", 
                    headers=self.headers,
                    timeout=10
                )
                
            if response.status_code == 200:
                data = response.json()
                size_kb = data.get("size", 0)  # Size in KB
                
                if size_kb > 500000:  # 500 MB
                    warning = f"Repository is extremely large ({size_kb // 1000} MB). Only partial parsing will be performed."
                elif size_kb > 100000:  # 100 MB
                    warning = f"Repository is large ({size_kb // 1000} MB). Analysis may take some time."
                    
                return size_kb, warning
            else:
                return 0, "Could not determine repository size"
                
        except httpx.RequestError:
            return 0, "Network error while checking repository size"
    
    async def download_repo_zip(self, username: str, repo_name: str) -> Tuple[str, str]:
        """
        Download a GitHub repository as a ZIP file.
        Returns: (local_path, error_message)
        """
        # Create a unique directory for this download
        unique_id = str(uuid.uuid4())[:8]
        repo_dir = TEMP_DIR / f"{repo_name}_{unique_id}"
        repo_dir.mkdir(parents=True, exist_ok=True)
        
        zip_path = repo_dir / f"{repo_name}.zip"
        
        try:
            # Common branch names to try
            branches_to_try = ["main", "master", "develop", "dev", "trunk"]
            
            async with httpx.AsyncClient() as client:
                success = False
                last_status_code = None
                last_error = None
                
                # Try direct API call first to get default branch info
                try:
                    api_url = f"{GITHUB_API_BASE}/repos/{username}/{repo_name}"
                    print(f"Checking repository API info at: {api_url}")
                    
                    # First try with token
                    if self.headers:
                        api_response = await client.get(
                            api_url, 
                            headers=self.headers,
                            timeout=10
                        )
                    else:
                        # Then try without token
                        api_response = await client.get(
                            api_url,
                            timeout=10
                        )
                    
                    if api_response.status_code == 200:
                        repo_data = api_response.json()
                        default_branch = repo_data.get("default_branch")
                        if default_branch:
                            # Move default branch to front of list
                            print(f"Found default branch: {default_branch}")
                            branches_to_try.insert(0, default_branch)
                            # Remove duplicates while preserving order
                            branches_to_try = list(dict.fromkeys(branches_to_try))
                            
                    elif api_response.status_code in (401, 403):
                        print(f"API access error {api_response.status_code}: {api_response.text}")
                    elif api_response.status_code == 404:
                        return "", f"Repository not found: {username}/{repo_name}"
                except Exception as e:
                    print(f"Error checking API: {str(e)}")
                
                print(f"Branches to try in order: {branches_to_try}")
                response = None
                
                # Try each branch name with various methods
                for branch in branches_to_try:
                    # Method 1: Direct ZIP download (no API required)
                    download_url = f"https://github.com/{username}/{repo_name}/archive/refs/heads/{branch}.zip"
                    print(f"Trying direct download from {download_url}")
                    
                    try:
                        # First try with auth headers if available
                        if self.headers:
                            response = await client.get(
                                download_url, 
                                headers=self.headers,
                                timeout=30,
                                follow_redirects=True
                            )
                        else:
                            # Try without authorization headers for public repos
                            response = await client.get(
                                download_url, 
                                timeout=30,
                                follow_redirects=True
                            )
                            
                        last_status_code = response.status_code
                        print(f"Download response: {response.status_code}")
                        
                        if response.status_code == 200:
                            success = True
                            print(f"✓ Successfully downloaded branch: {branch}")
                            break
                        
                        # Try with different user agent
                        if response.status_code in (401, 403, 404):
                            headers = {"User-Agent": "Mozilla/5.0"}
                            if self.headers:
                                headers.update(self.headers)
                                
                            response = await client.get(
                                download_url, 
                                headers=headers,
                                timeout=30,
                                follow_redirects=True
                            )
                            
                            last_status_code = response.status_code
                            if response.status_code == 200:
                                success = True
                                print(f"✓ Downloaded with user agent: {branch}")
                                break
                        
                    except Exception as e:
                        last_error = str(e)
                        print(f"Error trying {branch} branch: {str(e)}")
                        continue
                
                # Method 2: Try API download as a fallback
                if not success and self.github_token:
                    try:
                        print("Trying GitHub API contents download as fallback...")
                        
                        # Get the root directory contents 
                        api_contents_url = f"{GITHUB_API_BASE}/repos/{username}/{repo_name}/contents"
                        contents_response = await client.get(
                            api_contents_url,
                            headers=self.headers,
                            timeout=30
                        )
                        
                        if contents_response.status_code == 200:
                            # Create directory structure
                            extract_dir = repo_dir / f"{repo_name}-extracted"
                            extract_dir.mkdir(parents=True, exist_ok=True)
                            
                            # Process API content response
                            contents = contents_response.json()
                            
                            # Process first level of files
                            for item in contents:
                                if item["type"] == "file":
                                    # Download the file
                                    file_content = await client.get(
                                        item["download_url"],
                                        headers=self.headers,
                                        timeout=30
                                    )
                                    
                                    if file_content.status_code == 200:
                                        file_path = extract_dir / item["name"]
                                        with open(file_path, "wb") as f:
                                            f.write(file_content.content)
                            
                            # We've created a basic directory structure
                            success = True
                            return str(extract_dir), "Limited files downloaded through API due to ZIP download failure"
                    except Exception as e:
                        print(f"API contents download failed: {str(e)}")
                
                # Handle errors
                if not success:
                    if last_status_code in (401, 403):
                        return "", f"Authentication error (HTTP {last_status_code}): Repository access denied. It may be private and require authentication."
                    elif last_status_code == 404:
                        return "", f"Repository not found (HTTP 404): {username}/{repo_name} or the branch does not exist."
                    else:
                        return "", f"Error downloading repository: Could not find a valid branch. Status: {last_status_code}, Error: {last_error}"
                
                # Write the zip file
                with open(zip_path, "wb") as f:
                    f.write(response.content)
                
                # Extract zip file
                try:
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(repo_dir)
                except zipfile.BadZipFile as e:
                    return "", f"Invalid ZIP file received. The repository may be empty or restricted. Error: {str(e)}"
                
                # Find the extracted directory (should be repo_name-main or repo_name-master)
                extracted_dirs = [d for d in repo_dir.iterdir() if d.is_dir()]
                if not extracted_dirs:
                    return "", "Error extracting ZIP file: No directory found after extraction"
                
                return str(extracted_dirs[0]), ""
                
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            error_detail = f"HTTP {status_code}"
            try:
                error_json = e.response.json()
                if 'message' in error_json:
                    error_detail += f": {error_json['message']}"
            except:
                error_detail += f": {str(e)}"
                
            return "", f"GitHub API error ({error_detail})"
            
        except httpx.RequestError as e:
            return "", f"Network error downloading repository: {str(e)}"
            
        except zipfile.BadZipFile:
            return "", "Invalid ZIP file received. The repository may be empty or the URL may be incorrect."
            
        except Exception as e:
            return "", f"Error processing repository: {type(e).__name__}: {str(e)}"
    
    async def analyze_repo_structure(self, repo_path: str, scan_mode: str = "full") -> Dict:
        """
        Analyze the repository structure and extract key information.
        
        Args:
            repo_path: Path to the downloaded repository
            scan_mode: One of "quick", "full", or "selective"
            
        Returns:
            Dictionary with analysis results
        """
        repo_dir = Path(repo_path)
        
        # Basic repository info
        repo_info = {
            "name": repo_dir.name,
            "analysis_date": datetime.now().isoformat(),
            "scan_mode": scan_mode,
            "structure": {},
            "summary": {
                "file_count": 0,
                "dir_count": 0,
                "languages": set(),
                "entry_points": [],
                "config_files": [],
                "source_files_count": 0,
                "has_tests": False,
                "language_distribution": {}
            },
            "key_files": [],
            "code_elements": {}  # Will store the detailed code parsing results
        }
        
        # Track extensions for language detection
        extensions_count = {}
        
        # Process the repository based on scan mode
        max_depth = 1 if scan_mode == "quick" else None
        
        def should_process_file(file_path):
            """Determine if a file should be processed based on scan mode"""
            if scan_mode == "selective":
                return file_path.suffix in SOURCE_EXTENSIONS
            return True
        
        def should_ignore_path(path):
            """Check if a path should be ignored"""
            parts = path.parts
            for part in parts:
                if part in IGNORE_DIRS:
                    return True
            return False
        
        # Walk the repository
        repo_structure = {}
        for root, dirs, files in os.walk(repo_dir):
            rel_path = os.path.relpath(root, repo_dir)
            if rel_path == ".":
                rel_path = ""
            
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            
            # Check depth limit for quick scan
            if max_depth and rel_path.count(os.sep) >= max_depth:
                dirs[:] = []  # Don't go deeper
                continue
            
            path_info = {
                "type": "directory",
                "files": [],
                "directories": [d for d in dirs if not should_ignore_path(Path(root) / d)]
            }
            
            # Process files
            for file_name in files:
                if file_name in IGNORE_FILES:
                    continue
                    
                file_path = Path(root) / file_name
                if not should_process_file(file_path):
                    continue
                
                # Track statistics
                repo_info["summary"]["file_count"] += 1
                
                # Check file extension
                _, ext = os.path.splitext(file_name)
                if ext:
                    extensions_count[ext] = extensions_count.get(ext, 0) + 1
                    
                    # Count source files
                    if ext in SOURCE_EXTENSIONS:
                        repo_info["summary"]["source_files_count"] += 1
                        repo_info["summary"]["languages"].add(ext[1:])  # Remove the dot
                
                # Track special files
                if file_name in CONFIG_FILES:
                    repo_info["summary"]["config_files"].append(os.path.join(rel_path, file_name))
                    
                if file_name in ENTRY_POINT_FILES:
                    repo_info["summary"]["entry_points"].append(os.path.join(rel_path, file_name))
                
                # Add file to structure
                file_info = {
                    "type": "file",
                    "extension": ext[1:] if ext else "",
                    "size": os.path.getsize(file_path)
                }
                
                path_info["files"].append({
                    "name": file_name,
                    "info": file_info
                })
                
                # Check for test files
                if "test" in file_name.lower() or "spec" in file_name.lower():
                    repo_info["summary"]["has_tests"] = True
            
            # Add to structure if directory isn't empty or we're doing a full scan
            if path_info["files"] or path_info["directories"] or scan_mode == "full":
                # Store in structure using path as key
                if rel_path:
                    repo_structure[rel_path] = path_info
                else:
                    repo_structure["root"] = path_info
            
            # Count directories
            repo_info["summary"]["dir_count"] += 1
        
        # Convert sets to lists for JSON serialization
        repo_info["summary"]["languages"] = list(repo_info["summary"]["languages"])
        
        # Calculate language distribution
        total_files = sum(extensions_count.values())
        for ext, count in extensions_count.items():
            if ext[1:] in repo_info["summary"]["languages"]:  # Remove the dot
                percentage = (count / total_files) * 100 if total_files > 0 else 0
                repo_info["summary"]["language_distribution"][ext[1:]] = round(percentage, 1)
        
        # Find key files for deeper analysis
        await self.identify_key_files(repo_dir, repo_info)
        
        # Add structure to repo info
        repo_info["structure"] = repo_structure
        
        return repo_info
    
    async def identify_key_files(self, repo_dir: Path, repo_info: Dict) -> None:
        """
        Identify key files for deeper analysis and extract important information.
        """
        # Prioritize important files (entry points, config files, READMEs)
        key_files = []
        
        # Add README first if it exists
        for root, _, files in os.walk(repo_dir):
            for file in files:
                if file.lower() == "readme.md":
                    rel_path = os.path.relpath(os.path.join(root, file), repo_dir)
                    key_files.append({
                        "path": rel_path,
                        "type": "documentation",
                        "importance": "high"
                    })
        
        # Add entry points
        for entry_point in repo_info["summary"]["entry_points"]:
            key_files.append({
                "path": entry_point,
                "type": "entry_point",
                "importance": "high"
            })
        
        # Add config files
        for config_file in repo_info["summary"]["config_files"]:
            key_files.append({
                "path": config_file,
                "type": "configuration",
                "importance": "medium"
            })
            
        # Add key files to repo_info
        repo_info["key_files"] = key_files
        
        # Run deep code parsing on the repository
        from code_parser import CodeParser
        parser = CodeParser(str(repo_dir))
        code_elements = parser.parse_repo(mode=repo_info["scan_mode"])
        
        # Store code parsing results
        repo_info["code_elements"] = code_elements
    
    async def generate_repo_summary(self, repo_info: Dict, output_dir: Path) -> Path:
        """
        Generate a summary markdown file with repository analysis.
        Returns the path to the generated file.
        """
        # Create output directory if it doesn't exist
        output_path = output_dir / repo_info["name"]
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create summary markdown file
        summary_file = output_path / "summary.md"
        
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(f"# Repository Analysis: {repo_info['name']}\n\n")
            f.write(f"**Analysis Date:** {repo_info['analysis_date']}\n")
            f.write(f"**Scan Mode:** {repo_info['scan_mode']}\n\n")
            
            # Summary statistics
            f.write("## Summary Statistics\n\n")
            f.write(f"- **Total Files:** {repo_info['summary']['file_count']}\n")
            f.write(f"- **Source Files:** {repo_info['summary']['source_files_count']}\n")
            f.write(f"- **Directories:** {repo_info['summary']['dir_count']}\n")
            f.write(f"- **Has Tests:** {'Yes' if repo_info['summary']['has_tests'] else 'No'}\n\n")
            
            # Languages
            f.write("## Language Distribution\n\n")
            if repo_info["summary"]["language_distribution"]:
                for lang, percentage in repo_info["summary"]["language_distribution"].items():
                    f.write(f"- **{lang}:** {percentage}%\n")
            else:
                f.write("No programming languages detected.\n")
            f.write("\n")
            
            # Frameworks (if detected from code_elements)
            if "code_elements" in repo_info and "frameworks" in repo_info["code_elements"]:
                f.write("## Frameworks & Libraries\n\n")
                for language, frameworks in repo_info["code_elements"]["frameworks"].items():
                    f.write(f"### {language}\n")
                    for framework in frameworks:
                        f.write(f"- {framework}\n")
                f.write("\n")
            
            # Key Files
            f.write("## Key Files\n\n")
            if repo_info["key_files"]:
                for key_file in repo_info["key_files"]:
                    f.write(f"- **{key_file['path']}** ({key_file['type']})\n")
            else:
                f.write("No key files identified.\n")
            f.write("\n")
            
            # Entry Points
            f.write("## Entry Points\n\n")
            if repo_info["summary"]["entry_points"]:
                for entry_point in repo_info["summary"]["entry_points"]:
                    f.write(f"- {entry_point}\n")
            else:
                f.write("No clear entry points identified.\n")
            f.write("\n")
            
            # Configuration Files
            f.write("## Configuration Files\n\n")
            if repo_info["summary"]["config_files"]:
                for config_file in repo_info["summary"]["config_files"]:
                    f.write(f"- {config_file}\n")
            else:
                f.write("No configuration files found.\n")
            f.write("\n")
            
            # Add API Routes section if available
            if "code_elements" in repo_info and "api_routes" in repo_info["code_elements"] and repo_info["code_elements"]["api_routes"]:
                f.write("## API Routes\n\n")
                f.write("| Method | Path | Handler | File |\n")
                f.write("|--------|------|---------|------|\n")
                
                for route in repo_info["code_elements"]["api_routes"]:
                    method = route.get("method", "")
                    path = route.get("path", "")
                    handler = route.get("handler", "")
                    file = route.get("file", "")
                    f.write(f"| {method} | {path} | {handler} | {file} |\n")
                    
                if repo_info["code_elements"].get("api_routes_truncated", False):
                    f.write("\n*Note: API routes list was truncated due to large size.*\n")
                f.write("\n")
            
            # Add Functions section if available
            if "code_elements" in repo_info and "functions" in repo_info["code_elements"] and repo_info["code_elements"]["functions"]:
                f.write("## Key Functions\n\n")
                
                for func in repo_info["code_elements"]["functions"][:20]:  # Limit to 20 functions in the MD summary
                    name = func.get("name", "")
                    file = func.get("file", "")
                    docstring = func.get("docstring", "").replace("\n", " ")
                    f.write(f"### `{name}` in {file}\n")
                    if docstring:
                        f.write(f"{docstring}\n\n")
                    else:
                        f.write("*No description available*\n\n")
                    
                if len(repo_info["code_elements"].get("functions", [])) > 20:
                    f.write("\n*Note: Only showing 20 functions. See the full JSON for complete details.*\n\n")
            
            # Add Classes section if available
            if "code_elements" in repo_info and "classes" in repo_info["code_elements"] and repo_info["code_elements"]["classes"]:
                f.write("## Key Classes\n\n")
                
                for cls in repo_info["code_elements"]["classes"][:10]:  # Limit to 10 classes in the MD summary
                    name = cls.get("name", "")
                    file = cls.get("file", "")
                    methods = cls.get("methods", [])
                    f.write(f"### `{name}` in {file}\n")
                    if methods:
                        f.write("**Methods:** ")
                        f.write(", ".join(f"`{m}`" for m in methods))
                        f.write("\n\n")
                    else:
                        f.write("*No methods detected*\n\n")
                    
                if len(repo_info["code_elements"].get("classes", [])) > 10:
                    f.write("\n*Note: Only showing 10 classes. See the full JSON for complete details.*\n\n")
        
        # Create structure JSON file for potential programmatic use
        structure_file = output_path / "structure.json"
        with open(structure_file, "w", encoding="utf-8") as f:
            # Convert non-serializable objects before dumping
            serializable_info = json.loads(json.dumps(repo_info, default=lambda o: str(o)))
            json.dump(serializable_info, f, indent=2)
        
        # Create a separate code elements JSON file (for Gemini input)
        code_elements_file = output_path / "code_elements.json"
        if "code_elements" in repo_info:
            with open(code_elements_file, "w", encoding="utf-8") as f:
                serializable_elements = json.loads(json.dumps(repo_info["code_elements"], default=lambda o: str(o)))
                json.dump(serializable_elements, f, indent=2)
        
        return summary_file
        
    async def cleanup(self, repo_dir: str) -> None:
        """Remove temporary files after processing"""
        try:
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)
        except Exception as e:
            logger.error(f"Error cleaning up temporary files: {e}")
    
    async def download_and_analyze(self, 
                                github_url: str, 
                                scan_mode: str = "full",
                                cleanup_after: bool = True) -> Dict:
        """
        Main function to download and analyze a GitHub repository.
        
        Args:
            github_url: URL to the GitHub repository
            scan_mode: One of "quick", "full", or "selective"
            cleanup_after: Whether to clean up temporary files after processing
            
        Returns:
            Dictionary with analysis results and generated documentation paths
        """
        result = {
            "success": False,
            "message": "",
            "repo_name": "",
            "docs_path": "",
            "summary": {}
        }
        
        logger.info(f"Starting repository analysis for {github_url} with scan mode: {scan_mode}")
        logger.info(f"Using GitHub token: {'Yes' if self.github_token else 'No'}")
        
        # 1. Validate GitHub URL
        # Extract owner and repo directly from URL first
        parsed = urlparse(github_url)
        path_parts = parsed.path.strip("/").split("/")
        
        # Clean up URL for consistent processing
        if github_url.endswith('.git'):
            github_url = github_url[:-4]
            logger.info(f"Removed .git suffix from URL: {github_url}")
        
        # Check if we can extract username/repo directly from URL
        if len(path_parts) >= 2 and parsed.netloc.endswith("github.com"):
            username = path_parts[0]
            repo_name = path_parts[1]
            if repo_name.endswith('.git'):
                repo_name = repo_name[:-4]
                
            logger.info(f"Extracted from URL: {username}/{repo_name}")
            
            # Try to validate but continue even if rate limited for public repos
            try:
                logger.info(f"Validating GitHub repository: {username}/{repo_name}")
                is_valid, error_msg, api_username, api_repo_name = await self.validate_github_url(github_url)
                
                if not is_valid:
                    logger.warning(f"Validation failed: {error_msg}")
                    
                    if "Rate limit exceeded" in error_msg or "403" in error_msg or "401" in error_msg:
                        # For rate limiting or auth issues, continue with URL parsing results
                        logger.info(f"Rate limiting or auth issue - proceeding with URL extraction: {username}/{repo_name}")
                    else:
                        # For other issues (like 404 not found), return the error
                        logger.error(f"Repository validation failed: {error_msg}")
                        result["message"] = error_msg
                        return result
                else:
                    logger.info(f"Repository validation successful: {api_username}/{api_repo_name}")
                    # Use the validated username/repo from the API if available
                    if api_username and api_repo_name:
                        username = api_username
                        repo_name = api_repo_name
                        
            except Exception as e:
                logger.exception(f"Repository validation exception: {str(e)}")
                logger.info(f"Proceeding with URL extraction: {username}/{repo_name}")
        else:
            # Fallback to regular validation
            logger.info("URL format doesn't match expected pattern, using validation")
            is_valid, error_msg, username, repo_name = await self.validate_github_url(github_url)
            
            if not is_valid:
                logger.error(f"Repository validation failed: {error_msg}")
                result["message"] = error_msg
                return result
                
            logger.info(f"Repository validation successful: {username}/{repo_name}")
                
        result["repo_name"] = repo_name
        
        # 2. Check repository size
        try:
            logger.info(f"Checking repository size for {username}/{repo_name}")
            size_kb, size_warning = await self.check_repo_size(username, repo_name)
            if size_warning:
                logger.warning(size_warning)
                result["message"] = size_warning
        except Exception as e:
            logger.error(f"Error checking repository size: {str(e)}")
            # Continue despite size check error
            
        # 3. Download repository
        logger.info(f"Downloading repository: {username}/{repo_name}")
        repo_dir, error = await self.download_repo_zip(username, repo_name)
        if error:
            logger.error(f"Download error: {error}")
            result["message"] = error
            return result
            
        logger.info(f"Repository downloaded to: {repo_dir}")
        
        try:
            # 4. Analyze repository structure
            logger.info(f"Analyzing repository structure with scan mode: {scan_mode}")
            repo_info = await self.analyze_repo_structure(repo_dir, scan_mode)
            
            # Skip processing if no source files found
            if repo_info["summary"]["source_files_count"] == 0:
                logger.warning("Repository contains no source files. Analysis skipped.")
                result["message"] = "Repository contains no source files. Analysis skipped."
                return result
            
            # 5. Generate documentation
            logger.info("Generating repository documentation")
            summary_file = await self.generate_repo_summary(repo_info, DOCS_DIR)
            logger.info(f"Documentation generated at: {summary_file}")
            
            # 6. Prepare result
            result["success"] = True
            result["message"] = f"Repository successfully analyzed. Documentation generated."
            result["docs_path"] = str(summary_file)
            result["summary"] = {
                "file_count": repo_info["summary"]["file_count"],
                "source_files": repo_info["summary"]["source_files_count"],
                "languages": repo_info["summary"]["languages"],
                "has_tests": repo_info["summary"]["has_tests"]
            }
            
            logger.info(f"Analysis complete: {result['summary']} files, languages: {result['summary']['languages']}")
            
        except HTTPStatusError as e:
            status_code = e.response.status_code
            error_detail = f"HTTP {status_code}"
            try:
                error_json = e.response.json()
                if 'message' in error_json:
                    error_detail += f": {error_json['message']}"
            except:
                error_detail += f": {str(e)}"
                
            logger.error(f"GitHub API error: {error_detail}")
            result["message"] = f"GitHub API error: {error_detail}"
            
        except RequestError as e:
            logger.error(f"Network error: {str(e)}")
            result["message"] = f"Network error: {str(e)}"
            
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            logger.exception(f"Analysis error ({error_type}): {error_msg}")
            result["message"] = f"Error during analysis ({error_type}): {error_msg}"
        
        finally:
            # 7. Cleanup temporary files if requested
            if cleanup_after:
                logger.info(f"Cleaning up temporary files")
                try:
                    await self.cleanup(Path(repo_dir).parent)
                except Exception as e:
                    logger.error(f"Error during cleanup: {str(e)}")
        
        return result
