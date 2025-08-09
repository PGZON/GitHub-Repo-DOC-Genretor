import os
import json
import logging
import httpx
import asyncio
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("gemini_docs_generator")

# Constants
DOCS_DIR = Path("docs")
DEFAULT_MAX_OUTPUT_TOKENS = 8192
FILE_SEPARATOR_PATTERN = r"---FILE:\s*([^-]+)---"

class GeminiDocsGenerator:
    """
    Uses Gemini API to generate documentation from repository analysis JSON.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize with Gemini API key (from .env or directly provided)
        """
        # Load environment if no key provided
        if api_key is None:
            load_dotenv()
            api_key = os.environ.get("GEMINI_API_KEY")
            
        if not api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY in .env or pass directly.")
            
        self.api_key = api_key
        self.gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
    
    async def generate_documentation(self, 
                              code_elements_json_path: str, 
                              repo_name: str,
                              max_retries: int = 2) -> Tuple[bool, str, Dict[str, str]]:
        """
        Generate documentation from code elements JSON using Gemini API
        
        Args:
            code_elements_json_path: Path to the code elements JSON file from repo analyzer
            repo_name: Name of the repository
            max_retries: Maximum number of retries on error
            
        Returns:
            Tuple of (success, message, generated_files)
        """
        # Load code elements JSON
        try:
            with open(code_elements_json_path, 'r', encoding='utf-8') as f:
                code_elements = json.load(f)
        except Exception as e:
            return False, f"Error loading code elements JSON: {str(e)}", {}
            
        # Check if JSON has enough content to generate docs
        if not self._validate_code_elements(code_elements):
            return False, "Insufficient code elements to generate documentation", {}
            
        # Prepare prompt for Gemini
        prompt = self._create_gemini_prompt(code_elements, repo_name)
        
        # Call Gemini API
        generated_docs = {}
        success = False
        error_message = ""
        
        for attempt in range(max_retries + 1):
            try:
                raw_response = await self._call_gemini_api(prompt)
                
                # Parse the response to extract file sections
                generated_files = self._parse_gemini_response(raw_response)
                
                if len(generated_files) >= 3:  # Expecting README.md, API.md, ARCHITECTURE.md
                    generated_docs = generated_files
                    success = True
                    break
                else:
                    error_message = f"Incomplete response from Gemini: Got {len(generated_files)} files, expected at least 3"
                    
                    if attempt < max_retries:
                        # Try with a simplified prompt for the retry
                        prompt = self._create_gemini_prompt(code_elements, repo_name, simplified=True)
                        logger.info(f"Retrying with simplified prompt (attempt {attempt + 1}/{max_retries})")
                    
            except Exception as e:
                error_message = f"Error calling Gemini API: {str(e)}"
                logger.error(error_message)
                if attempt < max_retries:
                    logger.info(f"Retrying... (attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(1)  # Wait before retry
        
        # Save generated documentation files if successful
        if success:
            # Create a timestamped folder name to avoid overwriting
            timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            folder_name = f"{repo_name}_{timestamp}"
            output_dir = DOCS_DIR / folder_name
            
            try:
                # Ensure docs directory exists
                DOCS_DIR.mkdir(parents=True, exist_ok=True)
                # Create project-specific output directory
                output_dir.mkdir(parents=True, exist_ok=True)
                
                saved_files = {}
                for filename, content in generated_docs.items():
                    file_path = output_dir / filename
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        saved_files[filename] = str(file_path)
                    except Exception as e:
                        error_msg = f"Error saving {filename}: {e}"
                        logger.error(error_msg)
                        return False, error_msg, generated_docs
                
                return True, f"Documentation generated successfully in {output_dir}", saved_files
            except Exception as e:
                error_msg = f"Error creating documentation directory: {e}"
                logger.error(error_msg)
                return False, error_msg, {}
        
        return False, error_message, {}
    
    def _validate_code_elements(self, code_elements: Dict) -> bool:
        """Validate that code elements JSON has enough information to generate docs"""
        # At minimum, we need project name and some files
        if not code_elements.get("project_name"):
            return False
            
        # Ensure there are at least some files to document
        file_count = len(code_elements.get("files", []))
        if file_count == 0:
            return False
            
        return True
        
    def _create_gemini_prompt(self, code_elements: Dict, repo_name: str, simplified: bool = False) -> str:
        """
        Create a detailed prompt for Gemini to generate documentation
        
        Args:
            code_elements: The code elements dictionary
            repo_name: Name of the repository
            simplified: Whether to use a simplified prompt (for retries)
            
        Returns:
            Prompt string
        """
        # Convert code elements to JSON string
        code_elements_json = json.dumps(code_elements, indent=2)
        
        # If the JSON is too large, truncate it to focus on the most important parts
        if len(code_elements_json) > 100000 and simplified:
            # Keep only essential sections for simplified version
            simplified_elements = {
                "project_name": code_elements.get("project_name", repo_name),
                "languages": code_elements.get("languages", {}),
                "file_count": code_elements.get("file_count", 0),
                "source_file_count": code_elements.get("source_file_count", 0),
                "frameworks": code_elements.get("frameworks", {}),
                "api_routes": code_elements.get("api_routes", [])[:20],  # Limit to 20 routes
                "functions": code_elements.get("functions", [])[:20],    # Limit to 20 functions
                "classes": code_elements.get("classes", [])[:10],        # Limit to 10 classes
                "special_files": code_elements.get("special_files", {})
            }
            code_elements_json = json.dumps(simplified_elements, indent=2)
        
        # Basic prompt template
        prompt = f"""You are a senior technical documentation generator.
Your job is to create professional, accurate, and concise documentation for software projects.

The following JSON describes the repository structure, code elements, functions, classes and API routes for a project named "{repo_name}":

{code_elements_json}

Based on this, produce three separate markdown files:

1. README.md – Project overview, key features, installation instructions, and usage examples.
2. API.md – API endpoints documentation with parameters and example requests/responses.
3. ARCHITECTURE.md – Technical architecture explanation with Mermaid.js diagrams.

Follow these specific rules:
- Use clear headings, bullet points, and tables for readability.
- Include example commands in code blocks using triple backticks.
- Use Mermaid.js for diagrams in the ARCHITECTURE.md file.
- ONLY document what is explicitly in the JSON data - do not invent or hallucinate additional features.
- Keep the documentation professional and concise.

For Mermaid diagrams, use this syntax:
```mermaid
graph TD
    A[Component A] --> B[Component B]
    B --> C[Component C]
```

Return each file with a clearly marked header like this:
---FILE: README.md---
[Content of README.md]
---FILE: API.md---
[Content of API.md]
---FILE: ARCHITECTURE.md---
[Content of ARCHITECTURE.md]

Do not add anything outside these file sections.
"""

        # Add instructions for handling incomplete data
        if simplified:
            prompt += """

Note: This is a retry request with simplified data. Even if the JSON is incomplete, please produce the best possible documentation based on what's available. Focus on clarity and accuracy over completeness.
"""
            
        return prompt
        
    async def _call_gemini_api(self, prompt: str) -> str:
        """
        Call the Gemini API to generate documentation
        
        Args:
            prompt: The prompt to send to Gemini
            
        Returns:
            Raw text response from Gemini
        """
        request_url = f"{self.gemini_url}?key={self.api_key}"
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.2,  # Lower temperature for more consistent output
                "maxOutputTokens": DEFAULT_MAX_OUTPUT_TOKENS,
                "topK": 40,
                "topP": 0.95
            },
            "safetySettings": [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                }
            ]
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(request_url, json=payload)
                
                if response.status_code != 200:
                    error_details = response.text[:200] + "..." if len(response.text) > 200 else response.text
                    raise Exception(f"API Error ({response.status_code}): {error_details}")
                    
                data = response.json()
                
                # Extract text from Gemini response
                candidates = data.get("candidates", [])
                if not candidates:
                    raise Exception("No response candidates received")
                    
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                
                if not parts:
                    raise Exception("No content parts received")
                    
                return parts[0].get("text", "")
                
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
            
    def _parse_gemini_response(self, raw_response: str) -> Dict[str, str]:
        """
        Parse the Gemini response to extract file sections
        
        Args:
            raw_response: Raw text response from Gemini
            
        Returns:
            Dictionary mapping filenames to content
        """
        result = {}
        
        # Find all file sections
        file_sections = re.split(FILE_SEPARATOR_PATTERN, raw_response)
        
        # Skip the first element which is empty or intro text
        for i in range(1, len(file_sections), 2):
            if i+1 < len(file_sections):
                filename = file_sections[i].strip()
                content = file_sections[i+1].strip()
                result[filename] = content
        
        return result


async def generate_docs_for_repo(repo_name: str, code_elements_path: str) -> Tuple[bool, str, Dict[str, str]]:
    """
    Helper function to generate documentation for a repository
    
    Args:
        repo_name: Name of the repository
        code_elements_path: Path to the code elements JSON file
        
    Returns:
        Tuple of (success, message, generated_files)
    """
    try:
        # Check if file exists
        if not os.path.exists(code_elements_path):
            return False, f"Code elements file not found: {code_elements_path}", {}
            
        # Check if file is readable
        try:
            with open(code_elements_path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError:
            return False, f"Invalid JSON in code elements file: {code_elements_path}", {}
        except Exception as e:
            return False, f"Error reading code elements file: {str(e)}", {}
        
        # Check if docs directory is writable
        try:
            if not os.path.exists(DOCS_DIR):
                os.makedirs(DOCS_DIR)
            test_file = DOCS_DIR / ".test_write_permission"
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            return False, f"Error: Cannot write to docs directory: {str(e)}", {}
        
        # Create the generator and generate documentation
        generator = GeminiDocsGenerator()
        return await generator.generate_documentation(code_elements_path, repo_name)
    except Exception as e:
        return False, f"Error generating documentation: {str(e)}", {}
