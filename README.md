# GitHub-Repo-DOC-Genretor

Welcome to **GitHub-Repo-DOC-Genretor**, an MCP server tool designed for the Puch AI Hackathon!  
This project analyzes GitHub repositories and automatically generates concise summaries and documentation to help developers and teams quickly understand any codebase.

## 🚀 Project Overview

**GitHub-Repo-DOC-Genretor** is a Python-powered MCP server that leverages AI to:
- Analyze the structure and metadata of a GitHub repository
- Generate human-readable project summaries and documentation
- Help streamline onboarding and project understanding for teams and contributors

Originally built as part of the Puch AI Hackathon, this tool aims to make open source collaboration easier by providing instant documentation for any repo.

## ✨ Features

- **Automated Repo Summary:** Produces an AI-generated summary of any GitHub repository.
- **Docstring Extraction:** Extracts and includes Python docstrings from modules, classes, and functions to enhance documentation.
- **Customizable Output:** Supports different summary/detail levels as needed.
- **Easy Integration:** Can be run as a server for integration with other tools or used standalone via CLI.

## Quick Setup Guide

### Step 1: Install Dependencies

First, make sure you have Python 3.11 or higher installed. Then:

```bash
# Create virtual environment
uv venv

# Install all required packages
uv sync

# Activate the environment
source .venv/bin/activate
```

### Step 2: Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env
```

Then edit `.env` and add your details:

```env
AUTH_TOKEN=your_secret_token_here
MY_NUMBER=919876543210
```

**Important Notes:**
- `AUTH_TOKEN`: This is your secret token for authentication. Keep it safe!
- `MY_NUMBER`: Your WhatsApp number in format `{country_code}{number}` (e.g., `919876543210` for +91-9876543210)

### Step 3: Run the Server

```bash
cd mcp-bearer-token
python mcp_starter.py
```

You'll see: `🚀 Starting MCP server on http://0.0.0.0:8086`

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request to suggest changes or add features.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

**Built for Puch AI Hackathon — Empowering open source with AI ✨**
