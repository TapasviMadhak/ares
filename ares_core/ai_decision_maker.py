"""
AI-powered decision making engine for autonomous penetration testing.

This module uses LLMs to:
1. Analyze vulnerability scan results
2. Prioritize targets and attack vectors
3. Suggest exploit chains and tool sequences
4. Make autonomous decisions during semi-automated mode
5. Learn from successful/failed attempts
"""

from typing import List, Dict, Optional, Any
from enum import Enum
import json
from loguru import logger
from datetime import datetime

from ares_core.config import settings
from ares_core.ollama_client import get_ollama_client
from ares_core.context_manager import ContextManager
from ares_core.prompts import VULNERABILITY_ANALYSIS_PROMPT, DECISION_MAKING_PROMPT


class DecisionType(Enum):
    """Types of decisions the AI can make"""
    CONTINUE_SCAN = "continue_scan"
    EXPLOIT_VULNERABILITY = "exploit_vulnerability"
    ENUMERATE_TARGET = "enumerate_target"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    PIVOT_NETWORK = "pivot_network"
    EXTRACT_DATA = "extract_data"
    ABORT_SCAN = "abort_scan"


class RiskLevel(Enum):
    """Risk levels for AI actions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AIDecisionMaker:
    """
    AI-powered decision making for autonomous penetration testing.
    
    Uses LLM reasoning to analyze scan results, prioritize actions,
    and make intelligent decisions about next steps.
    """
    
    def __init__(self, scan_id: str):
        """
        Initialize decision maker for a specific scan.
        
        Args:
            scan_id: Unique identifier for the scan session
        """
        self.scan_id = scan_id
        self.ollama = get_ollama_client()
        # Simple context without target_url requirement for decision making
        self.context = ContextManager(scan_id, target_url="decision_context")
        self.decision_history: List[Dict[str, Any]] = []
        
        logger.info(f"Initialized AI Decision Maker for scan {scan_id}")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze discovered vulnerabilities and prioritize them.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Analysis results with prioritized vulnerabilities
        """
        if not vulnerabilities:
            return {
                "status": "no_vulns",
                "message": "No vulnerabilities to analyze",
                "priorities": []
            }
        
        # Prepare vulnerability summary
        vuln_summary = self._format_vulnerabilities(vulnerabilities)
        
        # Build analysis prompt
        prompt = VULNERABILITY_ANALYSIS_PROMPT.format(
            vulnerability_count=len(vulnerabilities),
            vulnerability_list=vuln_summary,
            scan_context=self._get_scan_context()
        )
        
        # Add to conversation context
        self.context.add_message("user", prompt)
        
        # Get AI analysis
        try:
            response = await self.ollama.generate(
                prompt=self.context.get_prompt_with_history(),
                system="You are an expert penetration tester analyzing vulnerability scan results."
            )
            
            # Store AI response
            self.context.add_message("assistant", response)
            
            # Parse analysis results
            analysis = self._parse_analysis(response, vulnerabilities)
            
            logger.info(f"Analyzed {len(vulnerabilities)} vulnerabilities, prioritized {len(analysis['priorities'])}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "priorities": []
            }
    
    async def make_decision(
        self,
        current_state: Dict[str, Any],
        available_actions: List[str],
        constraints: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make an autonomous decision about next action.
        
        Args:
            current_state: Current scan state (found vulns, tested endpoints, etc.)
            available_actions: List of possible next actions
            constraints: Optional constraints (time, scope, risk tolerance)
            
        Returns:
            Decision with action, rationale, and risk assessment
        """
        # Build decision prompt
        prompt = DECISION_MAKING_PROMPT.format(
            current_state=json.dumps(current_state, indent=2),
            available_actions=", ".join(available_actions),
            constraints=json.dumps(constraints or {}, indent=2),
            scan_history=self._get_decision_history()
        )
        
        self.context.add_message("user", prompt)
        
        try:
            response = await self.ollama.generate(
                prompt=self.context.get_prompt_with_history(),
                system="You are an autonomous penetration testing AI making strategic decisions."
            )
            
            self.context.add_message("assistant", response)
            
            # Parse decision
            decision = self._parse_decision(response, available_actions)
            
            # Store in history
            self.decision_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "state": current_state,
                "decision": decision,
                "constraints": constraints
            })
            
            logger.info(f"Decision: {decision['action']} (confidence: {decision['confidence']})")
            
            return decision
            
        except Exception as e:
            logger.error(f"Decision making failed: {e}")
            return {
                "action": "abort_scan",
                "rationale": f"Error in decision making: {e}",
                "confidence": 0.0,
                "risk_level": RiskLevel.HIGH.value
            }
    
    async def suggest_exploit_chain(
        self,
        target_goal: str,
        vulnerabilities: List[Dict[str, Any]],
        available_tools: List[str]
    ) -> Dict[str, Any]:
        """
        Suggest a chain of exploits to achieve a specific goal.
        
        Args:
            target_goal: Goal to achieve (e.g., "remote code execution", "data exfiltration")
            vulnerabilities: Available vulnerabilities to chain
            available_tools: Available exploitation tools
            
        Returns:
            Suggested exploit chain with steps and tools
        """
        prompt = f"""
Given the following vulnerabilities and tools, suggest an exploit chain to achieve: {target_goal}

Available vulnerabilities:
{self._format_vulnerabilities(vulnerabilities)}

Available tools:
{", ".join(available_tools)}

Provide a step-by-step exploit chain that:
1. Uses the available vulnerabilities
2. Chains them logically
3. Specifies which tools to use at each step
4. Includes success indicators to verify each step
5. Suggests fallback options if a step fails

Format as JSON with structure:
{{
    "chain": [
        {{
            "step": 1,
            "action": "...",
            "vulnerability": "...",
            "tools": ["..."],
            "success_indicator": "...",
            "fallback": "..."
        }}
    ],
    "estimated_success": 0.0-1.0,
    "risk_assessment": "low|medium|high|critical",
    "prerequisites": ["..."]
}}
"""
        
        self.context.add_message("user", prompt)
        
        try:
            response = await self.ollama.generate(
                prompt=self.context.get_prompt_with_history(),
                system="You are an expert exploit developer creating attack chains."
            )
            
            self.context.add_message("assistant", response)
            
            # Parse exploit chain
            chain = self._parse_json_response(response)
            
            logger.info(f"Suggested exploit chain with {len(chain.get('chain', []))} steps")
            
            return chain
            
        except Exception as e:
            logger.error(f"Exploit chain suggestion failed: {e}")
            return {
                "chain": [],
                "error": str(e),
                "estimated_success": 0.0,
                "risk_assessment": "unknown"
            }
    
    async def prioritize_targets(
        self,
        discovered_endpoints: List[Dict[str, Any]],
        scan_objective: str
    ) -> List[Dict[str, Any]]:
        """
        Prioritize discovered endpoints for testing.
        
        Args:
            discovered_endpoints: List of discovered URLs/endpoints
            scan_objective: Scan objective (broad scan, specific vuln, etc.)
            
        Returns:
            Prioritized list of endpoints with testing rationale
        """
        endpoint_summary = "\n".join([
            f"- {ep.get('url', 'unknown')} ({ep.get('method', 'GET')}) - {ep.get('parameters', 'no params')}"
            for ep in discovered_endpoints[:50]  # Limit to first 50
        ])
        
        prompt = f"""
Given the scan objective: {scan_objective}

Discovered endpoints:
{endpoint_summary}

Prioritize these endpoints for security testing. Consider:
1. Attack surface (number of parameters, complexity)
2. Likely business logic importance
3. Authentication requirements
4. Potential for high-impact vulnerabilities
5. Historical vulnerability patterns in similar endpoints

Return top 20 prioritized endpoints with reasoning.
Format as JSON array with: {{"url": "...", "priority": 1-10, "rationale": "...", "test_types": ["..."]}}
"""
        
        try:
            response = await self.ollama.generate(
                prompt=prompt,
                system="You are a web application security expert prioritizing attack targets."
            )
            
            # Parse prioritized list
            prioritized = self._parse_json_response(response)
            
            if isinstance(prioritized, list):
                logger.info(f"Prioritized {len(prioritized)} endpoints")
                return prioritized[:20]  # Top 20
            
            return []
            
        except Exception as e:
            logger.error(f"Target prioritization failed: {e}")
            return discovered_endpoints[:20]  # Fallback to first 20
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities for LLM consumption"""
        formatted = []
        for i, vuln in enumerate(vulnerabilities[:20], 1):  # Limit to top 20
            formatted.append(
                f"{i}. {vuln.get('vuln_type', 'Unknown')} "
                f"[{vuln.get('severity', 'unknown').upper()}] "
                f"at {vuln.get('url', 'unknown')} "
                f"(confidence: {vuln.get('confidence', 0.5):.2f})\n"
                f"   Details: {vuln.get('description', 'No description')[:100]}..."
            )
        return "\n".join(formatted)
    
    def _get_scan_context(self) -> str:
        """Get relevant scan context for decision making"""
        return f"Scan ID: {self.scan_id}, Decisions made: {len(self.decision_history)}"
    
    def _get_decision_history(self) -> str:
        """Get summary of previous decisions"""
        if not self.decision_history:
            return "No previous decisions"
        
        recent = self.decision_history[-5:]  # Last 5 decisions
        summary = []
        for d in recent:
            summary.append(
                f"- {d['timestamp']}: {d['decision'].get('action', 'unknown')} "
                f"(confidence: {d['decision'].get('confidence', 0.0):.2f})"
            )
        return "\n".join(summary)
    
    def _parse_analysis(
        self,
        response: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse AI analysis response"""
        # Try to extract JSON if present
        analysis = self._parse_json_response(response)
        
        if analysis and "priorities" in analysis:
            return analysis
        
        # Fallback: create simple priority based on severity
        priorities = sorted(
            vulnerabilities,
            key=lambda v: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                    v.get("severity", "low").lower(), 0
                ),
                v.get("confidence", 0.5)
            ),
            reverse=True
        )
        
        return {
            "status": "success",
            "analysis": response,
            "priorities": priorities[:10]  # Top 10
        }
    
    def _parse_decision(
        self,
        response: str,
        available_actions: List[str]
    ) -> Dict[str, Any]:
        """Parse decision from AI response"""
        # Try to extract JSON
        decision = self._parse_json_response(response)
        
        if decision and "action" in decision:
            return decision
        
        # Fallback: extract action from text
        response_lower = response.lower()
        for action in available_actions:
            if action.lower() in response_lower:
                return {
                    "action": action,
                    "rationale": response[:500],
                    "confidence": 0.6,
                    "risk_level": RiskLevel.MEDIUM.value
                }
        
        # Default: continue scan
        return {
            "action": "continue_scan",
            "rationale": "Could not determine specific action, continuing scan",
            "confidence": 0.5,
            "risk_level": RiskLevel.LOW.value
        }
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse JSON from response"""
        try:
            # Try direct parse
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            import re
            json_pattern = r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```'
            matches = re.findall(json_pattern, response, re.DOTALL)
            
            if matches:
                try:
                    return json.loads(matches[0])
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in text
            try:
                start = response.find('{')
                end = response.rfind('}') + 1
                if start >= 0 and end > start:
                    return json.loads(response[start:end])
            except (json.JSONDecodeError, ValueError):
                pass
        
        return None
    
    def get_decision_summary(self) -> Dict[str, Any]:
        """Get summary of all decisions made"""
        return {
            "scan_id": self.scan_id,
            "total_decisions": len(self.decision_history),
            "decisions": self.decision_history,
            "context_size": len(self.context.messages)
        }
    
    async def explain_decision(self, decision: Dict[str, Any]) -> str:
        """
        Generate human-readable explanation of a decision.
        
        Args:
            decision: Decision dict to explain
            
        Returns:
            Natural language explanation
        """
        prompt = f"""
Explain this penetration testing decision in simple terms for a security report:

Action: {decision.get('action', 'unknown')}
Rationale: {decision.get('rationale', 'No rationale provided')}
Confidence: {decision.get('confidence', 0.0):.0%}
Risk Level: {decision.get('risk_level', 'unknown')}

Provide a clear, concise explanation (2-3 sentences) suitable for a technical report.
"""
        
        try:
            explanation = await self.ollama.generate(
                prompt=prompt,
                system="You are a security analyst writing clear explanations."
            )
            return explanation.strip()
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return f"Decision: {decision.get('action', 'unknown')} - {decision.get('rationale', 'No details')}"


# Convenience function
def get_decision_maker(scan_id: str) -> AIDecisionMaker:
    """
    Get decision maker instance for a scan.
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        AIDecisionMaker instance
    """
    return AIDecisionMaker(scan_id)
