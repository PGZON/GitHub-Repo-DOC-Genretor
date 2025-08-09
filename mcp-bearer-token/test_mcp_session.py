import asyncio
import httpx
import json
import uuid

async def test_mcp_tool():
    base_url = "http://localhost:8086/mcp"
    auth_token = "token_123_123"
    
    # Create a unique session ID
    session_id = str(uuid.uuid4())
    
    # Common headers
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Step 1: Create a session
        print("Step 1: Creating session...")
        try:
            session_response = await client.post(
                f"{base_url}/",
                headers=headers
            )
            print(f"Session creation status: {session_response.status_code}")
            print(f"Response: {session_response.text}")
            
            # Step 2: List available tools
            print("\nStep 2: Listing tools...")
            list_tools_payload = {
                "jsonrpc": "2.0",
                "method": "listTools",
                "id": "list-tools-1"
            }
            
            list_tools_response = await client.post(
                f"{base_url}/",
                headers=headers,
                json=list_tools_payload
            )
            print(f"List tools status: {list_tools_response.status_code}")
            
            # Parse tools response
            tools_data = list_tools_response.json()
            if "result" in tools_data:
                tools = tools_data["result"]
                print(f"Available tools: {[t.get('name', 'unknown') for t in tools]}")
                
                # Check if quickstack_repo_docs is available
                tool_names = [t.get("name") for t in tools]
                if "quickstack_repo_docs" in tool_names:
                    print("✅ quickstack_repo_docs tool is available")
                else:
                    print("❌ quickstack_repo_docs tool is NOT available")
                    print(f"Available tools: {tool_names}")
            else:
                print("❌ Could not get tool list")
                print(f"Response: {tools_data}")
                return
                
            # Step 3: Call the quickstack_repo_docs tool
            print("\nStep 3: Calling quickstack_repo_docs...")
            tool_payload = {
                "jsonrpc": "2.0",
                "method": "callTool",
                "params": {
                    "name": "quickstack_repo_docs",
                    "parameters": {
                        "repo_url": "https://github.com/raveendratal/ravi_azureadbadf",
                        "scan_mode": "quick"
                    }
                },
                "id": "call-tool-1"
            }
            
            tool_response = await client.post(
                f"{base_url}/",
                headers=headers,
                json=tool_payload
            )
            print(f"Tool call status: {tool_response.status_code}")
            
            if tool_response.status_code == 200:
                result = tool_response.json()
                print("\nResponse summary:")
                if "error" in result:
                    print(f"❌ Error: {result['error'].get('message', 'Unknown error')}")
                elif "result" in result:
                    print(f"✅ Success: {result['result'][:200]}...")
                else:
                    print(f"⚠️ Unexpected response: {result}")
            else:
                print(f"❌ Request failed: {tool_response.text}")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            
if __name__ == "__main__":
    asyncio.run(test_mcp_tool())
