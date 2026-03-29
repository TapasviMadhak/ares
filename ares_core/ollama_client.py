"""
Ollama AI Integration for ARES
Handles communication with local Ollama instance
"""

import json
from typing import Optional, List, Dict, Any, AsyncIterator
from loguru import logger
import httpx
from .config import settings


class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, host: str = None, model: str = None):
        self.host = host or settings.ollama_host
        self.model = model or settings.ollama_model
        self.client = httpx.AsyncClient(timeout=120.0)
        logger.info(f"Initialized Ollama client: {self.host} with model {self.model}")
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        stream: bool = False,
        **kwargs
    ) -> str | AsyncIterator[str]:
        """
        Generate completion from Ollama
        
        Args:
            prompt: User prompt
            system: System prompt
            temperature: Sampling temperature
            stream: Whether to stream response
            **kwargs: Additional Ollama parameters
        
        Returns:
            Generated text or async iterator if streaming
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": temperature,
                **kwargs
            }
        }
        
        if system:
            payload["system"] = system
        
        try:
            if stream:
                return self._stream_generate(payload)
            else:
                response = await self.client.post(
                    f"{self.host}/api/generate",
                    json=payload
                )
                response.raise_for_status()
                result = response.json()
                return result.get("response", "")
                
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise
    
    async def _stream_generate(self, payload: Dict[str, Any]) -> AsyncIterator[str]:
        """Stream generation responses"""
        async with self.client.stream(
            "POST",
            f"{self.host}/api/generate",
            json=payload
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if chunk := data.get("response"):
                            yield chunk
                    except json.JSONDecodeError:
                        continue
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        stream: bool = False,
        **kwargs
    ) -> str | AsyncIterator[str]:
        """
        Chat with Ollama using conversation history
        
        Args:
            messages: List of {role: str, content: str} messages
            temperature: Sampling temperature
            stream: Whether to stream response
            **kwargs: Additional Ollama parameters
        
        Returns:
            Generated response or async iterator
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": temperature,
                **kwargs
            }
        }
        
        try:
            if stream:
                return self._stream_chat(payload)
            else:
                response = await self.client.post(
                    f"{self.host}/api/chat",
                    json=payload
                )
                response.raise_for_status()
                result = response.json()
                return result.get("message", {}).get("content", "")
                
        except Exception as e:
            logger.error(f"Ollama chat failed: {e}")
            raise
    
    async def _stream_chat(self, payload: Dict[str, Any]) -> AsyncIterator[str]:
        """Stream chat responses"""
        async with self.client.stream(
            "POST",
            f"{self.host}/api/chat",
            json=payload
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if message := data.get("message"):
                            if content := message.get("content"):
                                yield content
                    except json.JSONDecodeError:
                        continue
    
    async def embeddings(self, text: str) -> List[float]:
        """
        Generate embeddings for text
        
        Args:
            text: Input text
        
        Returns:
            Embedding vector
        """
        payload = {
            "model": self.model,
            "prompt": text
        }
        
        try:
            response = await self.client.post(
                f"{self.host}/api/embeddings",
                json=payload
            )
            response.raise_for_status()
            result = response.json()
            return result.get("embedding", [])
            
        except Exception as e:
            logger.error(f"Ollama embeddings failed: {e}")
            raise
    
    async def list_models(self) -> List[Dict[str, Any]]:
        """List available models"""
        try:
            response = await self.client.get(f"{self.host}/api/tags")
            response.raise_for_status()
            result = response.json()
            return result.get("models", [])
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []
    
    async def check_model(self) -> bool:
        """Check if configured model is available"""
        models = await self.list_models()
        available = any(m.get("name") == self.model for m in models)
        if not available:
            logger.warning(f"Model {self.model} not found. Available: {[m.get('name') for m in models]}")
        return available
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Global client instance
_ollama_client: Optional[OllamaClient] = None


def get_ollama_client() -> OllamaClient:
    """Get or create global Ollama client"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client
