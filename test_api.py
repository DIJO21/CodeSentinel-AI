import httpx
import json

def test_webhook():
    url = "http://localhost:8000/api/v1/webhook"
    
    # Mock GitHub Pull Request payload
    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "diff_url": "https://github.com/octocat/Hello-World/pull/42.diff"
        },
        "repository": {
            "full_name": "octocat/Hello-World"
        }
    }

    headers = {
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json"
    }

    print(f"Sending mock GitHub webhook payload to {url}...")
    try:
        response = httpx.post(url, json=payload, headers=headers)
        print(f"Status Code: {response.status_code}")
        print("Response JSON:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print("\n❌ Error connecting to FastAPI backend.")
        print("Make sure you run the server first: .venv\\Scripts\\uvicorn.exe src.backend.main:app --reload")

if __name__ == "__main__":
    test_webhook()
