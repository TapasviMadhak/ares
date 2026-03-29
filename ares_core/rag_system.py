"""
RAG (Retrieval-Augmented Generation) System for Security Knowledge
Provides context-aware security information to the AI
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import asyncio
from sqlalchemy.orm import Session
from loguru import logger
import numpy as np

from .database import get_db_session
from .models import KnowledgeBase
from .ollama_client import get_ollama_client


@dataclass
class KnowledgeDocument:
    """A knowledge base document"""
    id: int
    title: str
    content: str
    content_type: str
    source: Optional[str] = None
    embedding: Optional[List[float]] = None
    relevance_score: Optional[float] = None


class RAGSystem:
    """
    Retrieval-Augmented Generation system for security knowledge
    
    Stores and retrieves relevant security information to augment AI responses
    """
    
    def __init__(self):
        self.ollama_client = get_ollama_client()
        logger.info("Initialized RAG system")
    
    async def add_knowledge(
        self,
        title: str,
        content: str,
        content_type: str,
        source: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> int:
        """
        Add knowledge to the database
        
        Args:
            title: Document title
            content: Document content
            content_type: Type of content (cve, technique, tool, etc.)
            source: Optional source URL/reference
            tags: Optional tags
        
        Returns:
            Knowledge base entry ID
        """
        # Generate embedding
        embedding = await self.ollama_client.embeddings(content)
        
        with get_db_session() as db:
            kb_entry = KnowledgeBase(
                title=title,
                content=content,
                content_type=content_type,
                source=source,
                tags=tags or [],
                embedding=embedding  # Store as JSON array
            )
            db.add(kb_entry)
            db.flush()
            entry_id = kb_entry.id
            logger.info(f"Added knowledge: {title} (type: {content_type})")
            return entry_id
    
    async def search(
        self,
        query: str,
        content_type: Optional[str] = None,
        top_k: int = 5
    ) -> List[KnowledgeDocument]:
        """
        Search knowledge base using semantic similarity
        
        Args:
            query: Search query
            content_type: Optional filter by content type
            top_k: Number of results to return
        
        Returns:
            List of relevant knowledge documents
        """
        # Generate query embedding
        query_embedding = await self.ollama_client.embeddings(query)
        
        with get_db_session() as db:
            # Get all knowledge entries (filtered by type if specified)
            query_builder = db.query(KnowledgeBase)
            if content_type:
                query_builder = query_builder.filter(
                    KnowledgeBase.content_type == content_type
                )
            
            entries = query_builder.all()
            
            if not entries:
                logger.warning(f"No knowledge entries found for type: {content_type}")
                return []
            
            # Calculate similarity scores
            results = []
            for entry in entries:
                if entry.embedding:
                    similarity = self._cosine_similarity(
                        query_embedding,
                        entry.embedding
                    )
                    results.append((entry, similarity))
            
            # Sort by similarity and take top_k
            results.sort(key=lambda x: x[1], reverse=True)
            results = results[:top_k]
            
            # Convert to KnowledgeDocument objects
            documents = [
                KnowledgeDocument(
                    id=entry.id,
                    title=entry.title,
                    content=entry.content,
                    content_type=entry.content_type,
                    source=entry.source,
                    embedding=entry.embedding,
                    relevance_score=score
                )
                for entry, score in results
            ]
            
            logger.debug(f"Found {len(documents)} relevant documents for query")
            return documents
    
    async def get_relevant_context(
        self,
        query: str,
        content_types: Optional[List[str]] = None,
        max_context_length: int = 2000
    ) -> str:
        """
        Get relevant context for augmenting AI prompt
        
        Args:
            query: Query to search for
            content_types: Optional list of content types to search
            max_context_length: Maximum context length in characters
        
        Returns:
            Formatted context string
        """
        all_documents = []
        
        if content_types:
            for content_type in content_types:
                docs = await self.search(query, content_type=content_type, top_k=3)
                all_documents.extend(docs)
        else:
            all_documents = await self.search(query, top_k=5)
        
        if not all_documents:
            return ""
        
        # Build context string
        context_parts = ["## Relevant Security Knowledge:\n"]
        current_length = len(context_parts[0])
        
        for doc in all_documents:
            doc_text = f"\n### {doc.title} ({doc.content_type})\n{doc.content}\n"
            
            if current_length + len(doc_text) > max_context_length:
                break
            
            context_parts.append(doc_text)
            current_length += len(doc_text)
        
        context = "".join(context_parts)
        logger.debug(f"Built context with {len(all_documents)} documents ({len(context)} chars)")
        return context
    
    def _cosine_similarity(
        self,
        embedding1: List[float],
        embedding2: List[float]
    ) -> float:
        """
        Calculate cosine similarity between two embeddings
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
        
        Returns:
            Similarity score (0 to 1)
        """
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)
        
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(dot_product / (norm1 * norm2))
    
    async def populate_default_knowledge(self):
        """Populate knowledge base with default security information"""
        
        default_knowledge = [
            {
                "title": "SQL Injection Overview",
                "content": """SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer. 
                Attackers can manipulate SQL queries by injecting malicious SQL code through user input fields.
                
                Common indicators:
                - Error messages revealing database structure
                - Different responses for true/false conditions
                - Time delays in responses (for blind SQLi)
                
                Test payloads:
                - ' OR '1'='1
                - ' OR '1'='1' --
                - ' UNION SELECT NULL--
                - '; WAITFOR DELAY '00:00:05'--
                """,
                "content_type": "technique",
                "source": "OWASP"
            },
            {
                "title": "Cross-Site Scripting (XSS) Overview",
                "content": """XSS allows attackers to inject malicious scripts into web pages viewed by other users.
                
                Types:
                1. Reflected XSS: Malicious script is reflected off the web server
                2. Stored XSS: Malicious script is stored on the server
                3. DOM-based XSS: Vulnerability exists in client-side code
                
                Test payloads:
                - <script>alert('XSS')</script>
                - <img src=x onerror=alert('XSS')>
                - "><script>alert(String.fromCharCode(88,83,83))</script>
                - <svg/onload=alert('XSS')>
                """,
                "content_type": "technique",
                "source": "OWASP"
            },
            {
                "title": "CSRF (Cross-Site Request Forgery)",
                "content": """CSRF forces an authenticated user to execute unwanted actions on a web application.
                
                Indicators of vulnerability:
                - No CSRF tokens in forms
                - Predictable CSRF tokens
                - CSRF token not validated
                - State-changing GET requests
                
                Protection mechanisms to check:
                - CSRF tokens (synchronizer token pattern)
                - SameSite cookie attribute
                - Custom request headers
                - Referer validation
                """,
                "content_type": "technique",
                "source": "OWASP"
            },
            {
                "title": "SSRF (Server-Side Request Forgery)",
                "content": """SSRF allows an attacker to make requests from a vulnerable server to internal or external resources.
                
                Common targets:
                - Internal network (169.254.169.254 for cloud metadata)
                - Localhost services (127.0.0.1)
                - Internal IP ranges (10.x.x.x, 192.168.x.x)
                
                Test payloads:
                - http://localhost
                - http://127.0.0.1
                - http://169.254.169.254/latest/meta-data/
                - file:///etc/passwd
                """,
                "content_type": "technique",
                "source": "OWASP"
            },
            {
                "title": "Authentication Bypass Techniques",
                "content": """Common authentication vulnerabilities:
                
                1. Weak password policies
                2. Insecure session management
                3. Missing account lockout
                4. JWT vulnerabilities (algorithm confusion, weak secrets)
                5. OAuth misconfigurations
                
                Tests to perform:
                - Brute force attacks
                - Session fixation
                - JWT token manipulation
                - Password reset vulnerabilities
                - Multi-factor authentication bypass
                """,
                "content_type": "technique",
                "source": "Security Best Practices"
            },
            {
                "title": "Security Headers",
                "content": """Important security headers to check:
                
                - Content-Security-Policy: Prevents XSS
                - X-Frame-Options: Prevents clickjacking
                - Strict-Transport-Security: Enforces HTTPS
                - X-Content-Type-Options: Prevents MIME sniffing
                - X-XSS-Protection: XSS filter (legacy)
                - Referrer-Policy: Controls referrer information
                - Permissions-Policy: Controls browser features
                
                Missing or misconfigured headers indicate security weaknesses.
                """,
                "content_type": "technique",
                "source": "OWASP Secure Headers"
            }
        ]
        
        logger.info("Populating knowledge base with default security information...")
        
        for knowledge in default_knowledge:
            try:
                await self.add_knowledge(**knowledge)
            except Exception as e:
                logger.error(f"Failed to add knowledge '{knowledge['title']}': {e}")
        
        logger.info(f"Added {len(default_knowledge)} default knowledge entries")


# Global RAG system instance
_rag_system: Optional[RAGSystem] = None


def get_rag_system() -> RAGSystem:
    """Get or create global RAG system"""
    global _rag_system
    if _rag_system is None:
        _rag_system = RAGSystem()
    return _rag_system
