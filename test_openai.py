from openai import AzureOpenAI
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

print("Testing Azure OpenAI connection...")
print(f"Endpoint: {os.getenv('AZURE_OPENAI_ENDPOINT')}")
print(f"Deployment: {os.getenv('AZURE_OPENAI_DEPLOYMENT')}")
print(f"API Version: {os.getenv('AZURE_OPENAI_API_VERSION')}")

try:
    client = AzureOpenAI(
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        api_key=os.getenv("AZURE_OPENAI_KEY"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION")
    )
    
    response = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        messages=[
            {"role": "user", "content": "Say 'Hello, Azure OpenAI is working!' in JSON format with a 'message' field."}
        ],
        temperature=0.1,
        max_tokens=50
    )
    
    print("Success! Raw response:")
    print(response.choices[0].message.content)
    
except Exception as e:
    print(f"Error: {e}")
    print(f"Error type: {type(e)}")