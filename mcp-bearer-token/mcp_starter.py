import asyncio
from typing import Annotated
import os
import json
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp import ErrorData, McpError
from mcp.server.auth.provider import AccessToken
from mcp.types import INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field
import threading
import time
import requests


import markdownify
import httpx
from httpx import HTTPStatusError, RequestError
import readabilipy

# --- Load environment variables ---
load_dotenv()

TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")

assert TOKEN is not None, "Please set AUTH_TOKEN in your .env file"
assert MY_NUMBER is not None, "Please set MY_NUMBER in your .env file"

# --- Auth Provider ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(
                token=token,
                client_id="puch-client",
                scopes=["*"],
                expires_at=None,
            )
        return None

# --- Rich Tool Description model ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str
    side_effects: str | None = None

# --- Fetch Utility Class ---
class Fetch:
    USER_AGENT = "Puch/1.0 (Autonomous)"

    @classmethod
    async def fetch_url(
        cls,
        url: str,
        user_agent: str,
        force_raw: bool = False,
    ) -> tuple[str, str]:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    headers={"User-Agent": user_agent},
                    timeout=30,
                )
            except httpx.HTTPError as e:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url}: {e!r}"))

            if response.status_code >= 400:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url} - status code {response.status_code}"))

            page_raw = response.text

        content_type = response.headers.get("content-type", "")
        is_page_html = "text/html" in content_type

        if is_page_html and not force_raw:
            return cls.extract_content_from_html(page_raw), ""

        return (
            page_raw,
            f"Content type {content_type} cannot be simplified to markdown, but here is the raw content:\n",
        )

    @staticmethod
    def extract_content_from_html(html: str) -> str:
        """Extract and convert HTML content to Markdown format."""
        ret = readabilipy.simple_json.simple_json_from_html_string(html, use_readability=True)
        if not ret or not ret.get("content"):
            return "<error>Page failed to be simplified from HTML</error>"
        content = markdownify.markdownify(ret["content"], heading_style=markdownify.ATX)
        return content

    # Search functionality removed

# --- MCP Server Setup ---
mcp = FastMCP(
    "GitHub Repo Analyzer MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN)
)

# --- Tool: validate (required by Puch) ---
@mcp.tool
async def validate() -> str:
    print(f"📣 TOOL EXECUTION: validate")
    return MY_NUMBER

# --- Simple echo tool for testing ---
@mcp.tool(description="Simple echo tool for testing")
async def echo(message: str) -> str:
    print(f"📣 TOOL EXECUTION: echo with message: {message}")
    return f"Echo: {message}"
    
# --- Diagnostics tool ---
@mcp.tool(description="Run diagnostics for connectivity issues")
async def diagnose() -> str:
    """Run diagnostics and return information about the environment"""
    import sys
    import platform
    import socket
    
    print("📣 TOOL EXECUTION: diagnose")
    
    # Get basic system info
    python_version = sys.version
    platform_info = platform.platform()
    
    # Get network info
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        ip_address = "Unknown"
    
    # Check GitHub access
    github_status = "Unknown"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("https://api.github.com", timeout=5)
            github_status = f"OK ({response.status_code})"
    except Exception as e:
        github_status = f"Error: {str(e)}"
    
    # Check environment variables
    env_vars = {
        "AUTH_TOKEN": "Present" if os.environ.get("AUTH_TOKEN") else "Missing",
        "MY_NUMBER": "Present" if os.environ.get("MY_NUMBER") else "Missing",
        "GEMINI_API_KEY": "Present" if os.environ.get("GEMINI_API_KEY") else "Missing",
        "GITHUB_TOKEN": "Present" if os.environ.get("GITHUB_TOKEN") else "Missing"
    }
    
    # Format response
    result = (
        f"🔍 **MCP Diagnostic Results**\n\n"
        f"**System Information**\n"
        f"- Python: {python_version.split()[0]}\n"
        f"- Platform: {platform_info}\n"
        f"- Hostname: {hostname}\n"
        f"- IP Address: {ip_address}\n\n"
        f"**Connectivity**\n"
        f"- GitHub API: {github_status}\n\n"
        f"**Environment Variables**\n"
        f"- AUTH_TOKEN: {env_vars['AUTH_TOKEN']}\n"
        f"- MY_NUMBER: {env_vars['MY_NUMBER']}\n"
        f"- GEMINI_API_KEY: {env_vars['GEMINI_API_KEY']}\n"
        f"- GITHUB_TOKEN: {env_vars['GITHUB_TOKEN']}\n\n"
        f"**Server Information**\n"
        f"- Server URL: http://0.0.0.0:8086/mcp\n"
        f"- MCP Version: 1.12.4\n"
        f"- FastMCP Version: 2.11.2\n\n"
        f"If you're experiencing issues with quickstack_repo_docs, try using `/mcp diagnose` first to verify connectivity."
    )
    
    return result

# --- GitHub Check Tool ---
@mcp.tool(description="Check if a GitHub repository exists and is accessible")
async def github_check(repo_url: str) -> str:
    """
    Verify that a GitHub repository exists and is accessible
    
    Args:
        repo_url: URL of the GitHub repository (e.g., https://github.com/username/repo)
        
    Returns:
        A message indicating whether the repository exists and can be accessed
    """
    print(f"📣 TOOL EXECUTION: github_check with repo_url: {repo_url}")
    
    # Extract username and repo name from URL
    parts = repo_url.strip('/').split('/')
    
    if 'github.com' not in parts:
        return "❌ Not a GitHub URL. Please provide a valid GitHub repository URL."
    
    try:
        # Find github.com in the URL parts
        github_index = parts.index('github.com')
        if len(parts) <= github_index + 2:
            return "❌ Invalid GitHub URL format. Please use format: https://github.com/username/repo"
        
        username = parts[github_index + 1]
        repo_name = parts[github_index + 2]
        
        # Remove .git suffix if present
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        
        # Format the canonical GitHub URL
        canonical_url = f"https://github.com/{username}/{repo_name}"
        
        # 1. Check the web URL
        async with httpx.AsyncClient() as client:
            print(f"Checking web URL: {canonical_url}")
            web_response = await client.head(canonical_url, follow_redirects=True, timeout=10)
            web_status = web_response.status_code
            
            # 2. Check the API URL
            api_url = f"https://api.github.com/repos/{username}/{repo_name}"
            print(f"Checking API URL: {api_url}")
            api_response = await client.get(api_url, timeout=10)
            api_status = api_response.status_code
            
            # 3. Check ZIP download for main branch
            zip_url = f"https://github.com/{username}/{repo_name}/archive/refs/heads/main.zip"
            print(f"Checking ZIP URL: {zip_url}")
            try:
                zip_response = await client.head(zip_url, timeout=10)
                zip_status = zip_response.status_code
            except:
                zip_status = "Error"
                
        # Format the results
        result = (
            f"🔍 **GitHub Repository Check**\n\n"
            f"**Repository:** {username}/{repo_name}\n"
            f"**Web Access:** {'✅ Available' if web_status == 200 else f'❌ Error ({web_status})'}\n"
            f"**API Access:** {'✅ Available' if api_status == 200 else f'❌ Error ({api_status})'}\n"
            f"**ZIP Download:** {'✅ Available' if zip_status == 200 or zip_status == 302 else f'❌ Error ({zip_status})'}\n\n"
        )
        
        if web_status == 200 and (api_status == 200 or api_status == 403):
            result += "✅ Repository exists and is accessible. You can use quickstack_repo_docs with this repository."
        else:
            result += "❌ There are issues accessing this repository. Please check the URL or try a different repository."
            
        return result
        
    except Exception as e:
        error_type = type(e).__name__
        error_message = str(e)
        return f"❌ Error checking repository: {error_type}: {error_message}"

# --- No job finder tool ---


# Only GitHub repository analyzer tools are enabled

# --- GitHub Repository Analyzer Tool ---
from repo_analyzer import GitHubRepoAnalyzer
from gemini_docs_generator import generate_docs_for_repo

GITHUB_REPO_ANALYZER_DESCRIPTION = RichToolDescription(
    description="Download, analyze and parse GitHub repositories to understand their structure, code elements, and API routes.",
    use_when="Use when you need to analyze a GitHub repository's structure, identify key files, extract functions/classes, or get a summary of technologies used.",
    side_effects="The repository will be downloaded temporarily and detailed documentation will be generated for code structure and API routes."
)

@mcp.tool(description=GITHUB_REPO_ANALYZER_DESCRIPTION.model_dump_json())
async def analyze_github_repo(
    repo_url: Annotated[str, Field(description="GitHub repository URL (https://github.com/username/repo)")],
    scan_mode: Annotated[str, Field(description="Scan mode: 'quick' (top-level only), 'full' (complete repo), or 'selective' (only source files)")] = "full",
    github_token: Annotated[str | None, Field(description="GitHub token for private repos (optional)")] = None
) -> str:
    """
    Download, analyze and parse a GitHub repository to extract structure, code elements and API routes.
    
    Args:
        repo_url: URL to the GitHub repository
        scan_mode: Analysis depth - quick (top-level), full (complete), or selective (only source files)
        github_token: Optional token for private repositories
    
    Returns:
        Analysis summary and documentation paths
    """
    # Validate scan mode
    if scan_mode not in ["quick", "full", "selective"]:
        raise McpError(ErrorData(code=INVALID_PARAMS, 
                                message="Invalid scan mode. Must be 'quick', 'full', or 'selective'."))
    
    # Use GEMINI_API_KEY from environment if github_token not provided
    if not github_token and "GEMINI_API_KEY" in os.environ:
        github_token = os.environ.get("GEMINI_API_KEY")
    
    # Create analyzer instance
    analyzer = GitHubRepoAnalyzer(github_token=github_token)
    
    try:
        # Download and analyze repository
        result = await analyzer.download_and_analyze(
            github_url=repo_url,
            scan_mode=scan_mode,
            cleanup_after=True
        )
        
        if not result["success"]:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=result["message"]))
        
        # Format the response
        languages = ", ".join(result["summary"]["languages"]) if result["summary"]["languages"] else "None detected"
        
        # Extract documentation paths
        docs_path = result.get('docs_path', '')
        code_elements_path = docs_path.replace('summary.md', 'code_elements.json') if docs_path else ''
        
        # Format frameworks information if available
        frameworks_info = ""
        if "code_elements" in result and "frameworks" in result["code_elements"]:
            frameworks_info = "\n\n**Frameworks/Libraries:**\n"
            for lang, frameworks in result["code_elements"]["frameworks"].items():
                frameworks_info += f"- {lang}: {', '.join(frameworks)}\n"
        
        # Format API routes if available
        api_routes_info = ""
        if "code_elements" in result and "api_routes" in result["code_elements"] and result["code_elements"]["api_routes"]:
            api_routes_info = "\n\n**API Routes Detected:** Yes"
            route_count = len(result["code_elements"]["api_routes"])
            if route_count > 0:
                api_routes_info += f" ({route_count} routes found)"
        
        # Build complete response
        response = (
            f"📁 **Repository Analysis Complete**\n\n"
            f"**Repository:** {result['repo_name']}\n"
            f"**Files:** {result['summary']['file_count']} total, {result['summary']['source_files']} source files\n"
            f"**Languages:** {languages}\n"
            f"**Has Tests:** {'Yes' if result['summary']['has_tests'] else 'No'}"
            f"{frameworks_info}"
            f"{api_routes_info}\n\n"
            f"**Documentation Generated:**\n"
            f"- Summary: {docs_path}\n"
            f"- Code Elements: {code_elements_path}\n\n"
            f"_Note: {result['message']}_\n\n"
            f"To generate professional documentation using Gemini AI, run:\n"
            f"```\ngenerate_repo_docs(repo_name=\"{result['repo_name']}\", code_elements_path=\"{code_elements_path}\")\n```"
        )
        
        return response
        
    except Exception as e:
        error_msg = f"Error analyzing repository: {str(e)}"
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=error_msg))

# --- Gemini Documentation Generator Tool ---
GEMINI_DOCS_GENERATOR_DESCRIPTION = RichToolDescription(
    description="Generate professional documentation for a GitHub repository using Gemini AI.",
    use_when="Use after analyzing a GitHub repository to create README.md, API.md, and ARCHITECTURE.md documentation files.",
    side_effects="Makes API calls to Gemini and generates markdown documentation files in the docs directory."
)

@mcp.tool(description=GEMINI_DOCS_GENERATOR_DESCRIPTION.model_dump_json())
async def generate_repo_docs(
    repo_name: Annotated[str, Field(description="Name of the repository to generate documentation for")],
    code_elements_path: Annotated[str, Field(description="Path to the code_elements.json file generated by the repo analyzer")]
) -> str:
    """
    Generate professional documentation for a repository using Gemini AI.
    
    Args:
        repo_name: Name of the repository
        code_elements_path: Path to the code_elements.json file from the repo analyzer
        
    Returns:
        Summary of the generated documentation
    """
    try:
        # Check if GEMINI_API_KEY is available
        if not os.environ.get("GEMINI_API_KEY"):
            raise McpError(ErrorData(code=INVALID_PARAMS, 
                           message="Gemini API key is missing. Please set GEMINI_API_KEY in the .env file."))
        
        # Check if the code_elements.json file exists
        if not os.path.exists(code_elements_path):
            raise McpError(ErrorData(code=INVALID_PARAMS, 
                           message=f"Code elements file not found: {code_elements_path}"))
        
        # Generate documentation
        success, message, generated_files = await generate_docs_for_repo(repo_name, code_elements_path)
        
        if not success:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=message))
        
        # Get list of generated files
        files_list = "\n".join([f"- `{filename}`" for filename in generated_files.keys()])
        
        # Extract the documentation directory
        docs_dir = os.path.dirname(list(generated_files.values())[0]) if generated_files else ""
        
        # Try to load the code elements to include summary info
        repo_summary = ""
        try:
            with open(code_elements_path, 'r', encoding='utf-8') as f:
                code_elements = json.load(f)
                
            # Extract summary information
            lang_info = ""
            if "languages" in code_elements and code_elements["languages"]:
                languages = [f"{lang} ({pct}%)" for lang, pct in code_elements["languages"].items()]
                lang_info = f"**Languages:** {', '.join(languages)}\n"
                
            frameworks_info = ""
            if "frameworks" in code_elements and code_elements["frameworks"]:
                framework_list = []
                for lang, frameworks in code_elements["frameworks"].items():
                    framework_list.append(f"{lang}: {', '.join(frameworks)}")
                frameworks_info = f"**Frameworks:** {'; '.join(framework_list)}\n"
                
            file_info = ""
            if "file_count" in code_elements:
                source_files = code_elements.get("source_file_count", "N/A")
                file_info = f"**Files:** {code_elements['file_count']} total, {source_files} source files\n"
                
            repo_summary = f"{lang_info}{frameworks_info}{file_info}"
        except:
            pass
        
        # Build response
        response = (
            f"📚 **Documentation Generated Successfully**\n\n"
            f"**Repository:** {repo_name}\n"
            f"{repo_summary}\n"
            f"**Files Generated:**\n{files_list}\n\n"
            f"**Location:** {docs_dir}\n\n"
            f"_Note: {message}_"
        )
        
        return response
        
    except McpError:
        raise
    except Exception as e:
        error_msg = f"Error generating documentation: {str(e)}"
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=error_msg))

# --- QuickStack GitHub Analyzer Tool for Puch AI ---
@mcp.tool(description="Generate and send documentation from a GitHub repository")
async def quickstack_repo_docs(
    repo_url: Annotated[str, Field(description="GitHub repository URL (https://github.com/username/repo)")],
    scan_mode: Annotated[str, Field(description="Scan mode: 'quick', 'full', or 'selective'")] = "full",
    github_token: Annotated[str, Field(description="GitHub token (optional for public repos)")] = None
) -> str:
    """
    Downloads a GitHub repository, analyzes its code, and sends the generated documentation via WhatsApp.
    
    Args:
        repo_url: URL of the GitHub repository (e.g., https://github.com/username/repo)
        scan_mode: Scan mode - 'quick', 'full', or 'selective' (default: full)
        github_token: Optional GitHub token for private repos or to avoid rate limits
        
    Returns:
        Generated documentation content and a success message
    """
    try:
        # Phase 1: Log the request details for debugging
        print(f"📣 TOOL EXECUTION: quickstack_repo_docs")
        print(f"📣 Parameters: repo_url='{repo_url}', scan_mode='{scan_mode}', github_token={'provided' if github_token else 'not provided'}")
        
        # Phase 2: Download and analyze the repository
        print(f"🔍 Analyzing repository: {repo_url} with scan mode: {scan_mode}")
        
        # Clean up repository URL (remove .git if present)
        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]
            print(f"Removed .git suffix, using: {repo_url}")
        
        # Extract owner and repo name from URL for proper API access
        # Format should be: https://github.com/owner/repo
        parts = repo_url.strip('/').split('/')
        
        # Better URL parsing to handle various formats
        owner = None
        repo_name = None
        
        if 'github.com' in parts:
            # Find the index of github.com
            github_index = parts.index('github.com')
            if len(parts) > github_index + 2:
                owner = parts[github_index + 1]
                repo_name = parts[github_index + 2]
                repo_url = f"https://github.com/{owner}/{repo_name}"
                print(f"Extracted owner: {owner}, repo: {repo_name}")
                print(f"Normalized repository URL: {repo_url}")
            else:
                return f"❌ Invalid GitHub URL format. Please use format: https://github.com/username/repo"
        else:
            return f"❌ Not a GitHub URL. Please provide a valid GitHub repository URL."
        
        # Try first with environment variables if no token provided
        env_token = None
        if not github_token:
            env_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GEMINI_API_KEY")
            if env_token:
                print(f"Using token from environment variables")
                github_token = env_token
        
        # DIRECT URL DOWNLOAD - Bypass API for public repos
        print(f"Attempting direct repository download...")
        
        # Direct download URL for common branch names
        branches = ["main", "master", "develop"]
        download_url = None
        download_content = None
        
        # Try to directly download the ZIP without using the GitHub API
        try:
            async with httpx.AsyncClient() as client:
                for branch in branches:
                    test_url = f"https://github.com/{owner}/{repo_name}/archive/refs/heads/{branch}.zip"
                    print(f"Trying branch: {branch} at {test_url}")
                    try:
                        headers = {"User-Agent": "Mozilla/5.0"}
                        if github_token:
                            headers["Authorization"] = f"token {github_token}"
                            
                        response = await client.head(test_url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            download_url = test_url
                            print(f"✓ Found downloadable branch: {branch}")
                            break
                    except Exception as e:
                        print(f"Error checking branch {branch}: {str(e)}")
                        continue
        except Exception as e:
            print(f"Error during direct download check: {str(e)}")
                
        # Now initialize the analyzer with appropriate token
        if github_token:
            analyzer = GitHubRepoAnalyzer(github_token=github_token)
            print("Using GitHubRepoAnalyzer with token")
        else:
            # Try without a token for public repos
            analyzer = GitHubRepoAnalyzer()
            print("Using GitHubRepoAnalyzer without token (for public repos)")
        
        # Download and analyze repository
        print(f"Starting repository download and analysis...")
        result = await analyzer.download_and_analyze(
            github_url=repo_url,
            scan_mode=scan_mode,
            cleanup_after=True
        )
        
        if not result or not result.get("success"):
            error_msg = result.get('message', 'Unknown error') if result else 'No result returned'
            return f"❌ Repository analysis failed: {error_msg}"
        
        # Extract code elements path for documentation generation
        docs_path = result.get('docs_path', '')
        repo_name = result.get('repo_name', '')
        code_elements_path = docs_path.replace('summary.md', 'code_elements.json') if docs_path else ''
        
        print(f"Docs path: {docs_path}")
        print(f"Code elements path: {code_elements_path}")
        
        if not code_elements_path:
            return f"❌ Code elements path could not be determined. Analysis may be incomplete."
        
        if not os.path.exists(code_elements_path):
            return f"❌ Code elements file not found at {code_elements_path}. Analysis may be incomplete."
        
        # Phase 3 & 4: Generate documentation using Gemini
        print(f"📝 Generating documentation for {repo_name}")
        docs_success, docs_message, generated_files = await generate_docs_for_repo(
            repo_name, 
            code_elements_path
        )
        
        if not docs_success:
            return f"❌ Documentation generation failed: {docs_message}"
        
        # Phase 5: Send documentation content back to WhatsApp
        doc_contents = {}
        
        # Read each documentation file
        for filename, filepath in generated_files.items():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    doc_contents[filename] = f.read()
            except Exception as e:
                print(f"Error reading {filename}: {str(e)}")
        
        # Format the response for WhatsApp with documentation content
        # Include README.md content first as it's most important
        readme_content = doc_contents.get('README.md', '')
        api_content = doc_contents.get('API.md', '')
        arch_content = doc_contents.get('ARCHITECTURE.md', '')
        
        # Get languages information
        languages = ", ".join(result["summary"]["languages"]) if result["summary"]["languages"] else "None detected"
        
        # Create a summary section
        summary = (
            f"✅ **QuickStack Analysis Complete**\n\n"
            f"📁 Repository: {repo_name}\n"
            f"📊 Languages: {languages}\n"
            f"📈 Files: {result['summary']['file_count']} total, {result['summary']['source_files']} source\n"
            f"📚 Docs Generated: {', '.join(generated_files.keys())}\n\n"
        )
        
        # Send the documentation content
        # Limit content length to avoid WhatsApp message limits
        max_section_length = 1500  # Characters per section
        
        # Format README content
        if readme_content:
            # If README is too long, truncate it
            if len(readme_content) > max_section_length:
                readme_content = readme_content[:max_section_length] + "\n\n... (content truncated, see full docs in docs folder)"
            
            readme_section = f"# 📄 README\n\n{readme_content}\n\n"
        else:
            readme_section = ""
            
        # Format API content - send only if it's not too big
        api_section = ""
        if api_content and len(api_content) < max_section_length:
            api_section = f"# 📚 API Documentation\n\n{api_content}\n\n"
        elif api_content:
            api_section = "# 📚 API Documentation\n\n(API documentation is available but too large to display here)\n\n"
            
        # Combine the content for the response
        response = summary + readme_section + api_section
        
        # If we have architecture diagrams, mention them
        if arch_content:
            response += "\n# 🏗️ Architecture\n\nArchitecture diagrams were generated but can't be displayed in WhatsApp.\n"
            
        # Add link to full documentation
        response += f"\n📂 Full documentation saved to: {os.path.dirname(list(generated_files.values())[0])}"
        
        return response
        
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        error_detail = f"HTTP {status_code}"
        try:
            error_json = e.response.json()
            if 'message' in error_json:
                error_detail += f": {error_json['message']}"
        except:
            error_detail += f": {str(e)}"
            
        print(f"HTTPStatusError: {error_detail}")
        
        if status_code == 401:
            return f"❌ GitHub API authentication error ({error_detail}). Please provide a valid GitHub token."
        elif status_code == 403:
            return f"❌ GitHub API rate limit or permission error ({error_detail}). Consider providing a GitHub token."
        elif status_code == 404:
            return f"❌ Repository not found ({error_detail}). Please check the URL and ensure the repository exists."
        else:
            return f"❌ GitHub API error ({error_detail})"
    
    except httpx.RequestError as e:
        print(f"RequestError: {str(e)}")
        return f"❌ Network error when accessing GitHub: {str(e)}. Please check your connection."
            
    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__
        print(f"Error processing repository: {error_type}: {error_message}")
        
        if "401" in error_message or "403" in error_message:
            return f"❌ GitHub API authentication error: {error_message}. Please provide a valid GitHub token."
        elif "404" in error_message:
            return f"❌ Repository not found: {error_message}. Please check the URL and ensure the repository exists."
        elif "timed out" in error_message.lower():
            return f"❌ Request timed out: {error_message}. The repository might be too large or GitHub servers might be busy."
        elif "rate limit" in error_message.lower():
            return f"❌ GitHub API rate limit exceeded: {error_message}. Please provide a GitHub token."
        else:
            return f"❌ Error processing repository ({error_type}): {error_message}"

# --- Run MCP Server ---
async def main():
    print("🚀 Starting MCP server on http://0.0.0.0:8086/mcp")
    print(f"💡 Registered tools: validate, analyze_github_repo, generate_repo_docs, quickstack_repo_docs")
    print(f"🔑 Using AUTH_TOKEN: {TOKEN[:5]}...")
    print(f"📱 Using MY_NUMBER: {MY_NUMBER}")
    print(f"🌐 Using GitHub token: {'Yes' if os.environ.get('GITHUB_TOKEN') else 'No'}")
    print(f"🧠 Using Gemini API key: {'Yes' if os.environ.get('GEMINI_API_KEY') else 'No'}")
    
    # Using /mcp path to match Puch AI connection URL
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086, path="/mcp")
# --- Keep-alive function ---
def keep_alive():
    url = "https://github-repo-doc-genretor.onrender.com"  # Replace with your Render app URL
    while True:
        try:
            response = requests.get(url, timeout=10)
            print(f"🔄 Keep-alive ping sent. Status: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Keep-alive ping failed: {e}")
        time.sleep(120)  # 2 minutes

if __name__ == "__main__":
    threading.Thread(target=keep_alive, daemon=True).start()
    asyncio.run(main())
