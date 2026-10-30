import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

def get_llm():
    """Return the configured LLM. Change this file to swap models."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not set in .env")
    

    return ChatGoogleGenerativeAI(
        model = "gemini-3.5-flash",
        google_api_key = api_key,
        temperature = 0,  # Reduces randomness for more consistent responses
    )



