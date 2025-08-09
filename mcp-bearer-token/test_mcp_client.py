import asyncio
import json
import os
import httpx

async def test_mcp_call():
    url = "http://localhost:8086/mcp"
    headers = {
        "Authorization": "Bearer token_123_123",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
    
    # Test the echo function first
    echo_payload = {
        "jsonrpc": "2.0",
        "method": "echo",
        "params": {
            "message": "Testing MCP connection"
        },
        "id": 1
    }
    
    print("Testing echo function...")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            response = await client.post(url, json=echo_payload, headers=headers)
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Now test the quickstack_repo_docs function
    repo_payload = {
        "jsonrpc": "2.0",
        "method": "quickstack_repo_docs",
        "params": {
            "repo_url": "https://github.com/raveendratal/ravi_azureadbadf",
            "scan_mode": "quick"
        },
        "id": 2
    }
    
    print("\nTesting quickstack_repo_docs function...")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            response = await client.post(url, json=repo_payload, headers=headers)
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:500]}...")  # Truncate long responses
            
            # If we got a JSON response, parse it and look for errors
            if response.headers.get("content-type") == "application/json":
                try:
                    json_response = response.json()
                    if "error" in json_response:
                        print(f"\nERROR DETAILS:")
                        print(f"Code: {json_response['error'].get('code')}")
                        print(f"Message: {json_response['error'].get('message')}")
                except Exception as e:
                    print(f"Error parsing JSON: {str(e)}")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_mcp_call())
