import requests

repo_url = "https://github.com/raveendratal/ravi_azureadbadf"
print(f"Testing repository: {repo_url}")

# Check if the repository exists
response = requests.head(repo_url)
print(f"Repository head check status: {response.status_code}")

# Get repository information from GitHub API
api_url = "https://api.github.com/repos/raveendratal/ravi_azureadbadf"
response = requests.get(api_url)
print(f"API status: {response.status_code}")

if response.status_code == 200:
    data = response.json()
    default_branch = data.get("default_branch")
    print(f"Default branch: {default_branch}")
    
    # Check if we can download a ZIP file
    for branch in ["main", "master", default_branch]:
        if not branch:
            continue
        download_url = f"https://github.com/raveendratal/ravi_azureadbadf/archive/refs/heads/{branch}.zip"
        try:
            zip_response = requests.head(download_url)
            print(f"Branch {branch} ZIP status: {zip_response.status_code}")
        except Exception as e:
            print(f"Error checking {branch}: {str(e)}")
else:
    print(f"API error: {response.text}")
