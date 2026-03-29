"""
Context Management for ARES AI
Handles conversation history and context windows for security testing sessions
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
from loguru import logger


@dataclass
class Message:
    """Represents a single message in conversation history"""
    role: str  # 'system', 'user', 'assistant'
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to Ollama message format"""
        return {
            "role": self.role,
            "content": self.content
        }


@dataclass
class ScanContext:
    """Context for a security scan session"""
    scan_id: str
    target_url: str
    discovered_endpoints: List[str] = field(default_factory=list)
    vulnerabilities_found: List[Dict] = field(default_factory=list)
    tested_payloads: Dict[str, List[str]] = field(default_factory=dict)
    technologies_detected: List[str] = field(default_factory=list)
    current_phase: str = "reconnaissance"
    
    def to_context_string(self) -> str:
        """Convert to human-readable context string"""
        return f"""
Current Scan Context:
- Target: {self.target_url}
- Phase: {self.current_phase}
- Endpoints Discovered: {len(self.discovered_endpoints)}
- Vulnerabilities Found: {len(self.vulnerabilities_found)}
- Technologies: {', '.join(self.technologies_detected) if self.technologies_detected else 'Unknown'}
        """.strip()


class ContextManager:
    """
    Manages conversation history and context for AI-powered security testing
    
    Handles:
    - Conversation history with token limits
    - Scan context tracking
    - Context window optimization
    - Memory management for long sessions
    """
    
    def __init__(
        self,
        scan_id: str,
        target_url: str,
        max_tokens: int = 4096,
        system_prompt: str = None
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.max_tokens = max_tokens
        
        # Conversation history
        self.messages: List[Message] = []
        
        # Scan context
        self.context = ScanContext(
            scan_id=scan_id,
            target_url=target_url
        )
        
        # System prompt
        if system_prompt:
            self.add_message("system", system_prompt)
        
        logger.info(f"Initialized context manager for scan {scan_id}")
    
    def add_message(
        self,
        role: str,
        content: str,
        metadata: Dict[str, Any] = None
    ) -> Message:
        """
        Add a message to conversation history
        
        Args:
            role: Message role ('system', 'user', 'assistant')
            content: Message content
            metadata: Optional metadata
        
        Returns:
            Created message
        """
        message = Message(
            role=role,
            content=content,
            metadata=metadata or {}
        )
        self.messages.append(message)
        
        # Check if we need to trim history
        self._maybe_trim_history()
        
        logger.debug(f"Added {role} message ({len(content)} chars)")
        return message
    
    def get_messages(
        self,
        include_system: bool = True,
        last_n: Optional[int] = None
    ) -> List[Dict[str, str]]:
        """
        Get messages in Ollama format
        
        Args:
            include_system: Whether to include system messages
            last_n: Only return last N messages
        
        Returns:
            List of message dictionaries
        """
        messages = self.messages
        
        if not include_system:
            messages = [m for m in messages if m.role != 'system']
        
        if last_n:
            messages = messages[-last_n:]
        
        return [m.to_dict() for m in messages]
    
    def update_scan_context(
        self,
        discovered_endpoints: List[str] = None,
        vulnerabilities: List[Dict] = None,
        technologies: List[str] = None,
        phase: str = None
    ):
        """Update scan context with new information"""
        if discovered_endpoints:
            self.context.discovered_endpoints.extend(discovered_endpoints)
            logger.debug(f"Added {len(discovered_endpoints)} endpoints to context")
        
        if vulnerabilities:
            self.context.vulnerabilities_found.extend(vulnerabilities)
            logger.info(f"Added {len(vulnerabilities)} vulnerabilities to context")
        
        if technologies:
            for tech in technologies:
                if tech not in self.context.technologies_detected:
                    self.context.technologies_detected.append(tech)
        
        if phase:
            self.context.current_phase = phase
            logger.info(f"Phase changed to: {phase}")
    
    def add_payload_test(self, vuln_type: str, payload: str):
        """Record a tested payload"""
        if vuln_type not in self.context.tested_payloads:
            self.context.tested_payloads[vuln_type] = []
        self.context.tested_payloads[vuln_type].append(payload)
    
    def get_context_summary(self) -> str:
        """Get a summary of current context"""
        return self.context.to_context_string()
    
    def build_prompt_with_context(self, prompt: str) -> str:
        """
        Build a prompt with current scan context
        
        Args:
            prompt: Base prompt
        
        Returns:
            Prompt with context information
        """
        context_str = self.get_context_summary()
        
        return f"{context_str}\n\n{prompt}"
    
    def _estimate_tokens(self, text: str) -> int:
        """
        Rough token estimation (1 token ≈ 4 characters)
        
        Args:
            text: Text to estimate
        
        Returns:
            Estimated token count
        """
        return len(text) // 4
    
    def _calculate_total_tokens(self) -> int:
        """Calculate total tokens in conversation history"""
        total = 0
        for message in self.messages:
            total += self._estimate_tokens(message.content)
        return total
    
    def _maybe_trim_history(self):
        """Trim conversation history if it exceeds token limit"""
        total_tokens = self._calculate_total_tokens()
        
        if total_tokens <= self.max_tokens:
            return
        
        logger.warning(f"Context too long ({total_tokens} tokens), trimming...")
        
        # Keep system messages and recent messages
        system_messages = [m for m in self.messages if m.role == 'system']
        other_messages = [m for m in self.messages if m.role != 'system']
        
        # Keep last 50% of non-system messages
        keep_count = len(other_messages) // 2
        trimmed_messages = other_messages[-keep_count:]
        
        self.messages = system_messages + trimmed_messages
        
        new_total = self._calculate_total_tokens()
        logger.info(f"Trimmed history: {total_tokens} -> {new_total} tokens")
    
    def get_relevant_vulnerabilities(self, vuln_type: str = None) -> List[Dict]:
        """
        Get vulnerabilities from context, optionally filtered by type
        
        Args:
            vuln_type: Optional vulnerability type filter
        
        Returns:
            List of vulnerability dictionaries
        """
        if vuln_type:
            return [
                v for v in self.context.vulnerabilities_found
                if v.get('type') == vuln_type
            ]
        return self.context.vulnerabilities_found
    
    def has_tested_payload(self, vuln_type: str, payload: str) -> bool:
        """Check if a payload has already been tested"""
        return payload in self.context.tested_payloads.get(vuln_type, [])
    
    def save_to_json(self, filepath: str):
        """Save context to JSON file"""
        data = {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'messages': [
                {
                    'role': m.role,
                    'content': m.content,
                    'timestamp': m.timestamp.isoformat(),
                    'metadata': m.metadata
                }
                for m in self.messages
            ],
            'context': {
                'discovered_endpoints': self.context.discovered_endpoints,
                'vulnerabilities_found': self.context.vulnerabilities_found,
                'tested_payloads': self.context.tested_payloads,
                'technologies_detected': self.context.technologies_detected,
                'current_phase': self.context.current_phase
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved context to {filepath}")
    
    @classmethod
    def load_from_json(cls, filepath: str) -> 'ContextManager':
        """Load context from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        manager = cls(
            scan_id=data['scan_id'],
            target_url=data['target_url']
        )
        
        # Restore messages
        for msg_data in data['messages']:
            message = Message(
                role=msg_data['role'],
                content=msg_data['content'],
                timestamp=datetime.fromisoformat(msg_data['timestamp']),
                metadata=msg_data['metadata']
            )
            manager.messages.append(message)
        
        # Restore context
        ctx_data = data['context']
        manager.context.discovered_endpoints = ctx_data['discovered_endpoints']
        manager.context.vulnerabilities_found = ctx_data['vulnerabilities_found']
        manager.context.tested_payloads = ctx_data['tested_payloads']
        manager.context.technologies_detected = ctx_data['technologies_detected']
        manager.context.current_phase = ctx_data['current_phase']
        
        logger.info(f"Loaded context from {filepath}")
        return manager
    
    def clear_history(self, keep_system: bool = True):
        """
        Clear conversation history
        
        Args:
            keep_system: Whether to keep system messages
        """
        if keep_system:
            self.messages = [m for m in self.messages if m.role == 'system']
        else:
            self.messages = []
        
        logger.info("Cleared conversation history")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get context statistics"""
        return {
            'total_messages': len(self.messages),
            'total_tokens': self._calculate_total_tokens(),
            'max_tokens': self.max_tokens,
            'utilization': f"{(self._calculate_total_tokens() / self.max_tokens * 100):.1f}%",
            'endpoints_discovered': len(self.context.discovered_endpoints),
            'vulnerabilities_found': len(self.context.vulnerabilities_found),
            'payloads_tested': sum(len(p) for p in self.context.tested_payloads.values()),
            'current_phase': self.context.current_phase
        }
