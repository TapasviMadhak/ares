"""
AI-Powered Tool Selector

Intelligently selects security tools based on:
- Target reconnaissance data
- Discovered vulnerabilities
- Attack surface analysis
- Historical effectiveness
- Current scan phase

Uses Ollama AI to make context-aware tool selection decisions.
"""

import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from loguru import logger

from ares_core.ollama_client import get_ollama_client
from ares_core.config import settings
from ares_core.database import get_db_session
from ares_core.models import Scan, Vulnerability, AIDecision

from .hexstrike_client import get_hexstrike_client


class ToolSelector:
    """
    AI-powered tool selection engine.
    
    Analyzes scan context and intelligently selects appropriate security
    tools from Hexstrike-AI's 150+ tool arsenal.
    
    Features:
    - Context-aware tool selection
    - Multi-phase attack planning
    - Tool chaining and dependencies
    - Historical effectiveness tracking
    - Adaptive strategy based on results
    """
    
    # Tool categories mapped to scan phases
    PHASE_TOOL_CATEGORIES = {
        "reconnaissance": [
            "network_scanning",
            "subdomain_enumeration",
            "port_scanning",
            "service_detection",
            "dns_enumeration",
        ],
        "enumeration": [
            "web_scanning",
            "directory_enumeration",
            "api_discovery",
            "technology_detection",
            "ssl_analysis",
        ],
        "vulnerability_scanning": [
            "vulnerability_scanning",
            "web_vulnerability_scanning",
            "misconfiguration_detection",
            "cloud_security_scanning",
            "container_scanning",
        ],
        "exploitation": [
            "credential_testing",
            "sql_injection",
            "xss_testing",
            "command_injection",
            "file_inclusion",
        ],
        "post_exploitation": [
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration",
            "persistence",
        ],
    }
    
    def __init__(self, scan_id: Optional[str] = None):
        """
        Initialize ToolSelector.
        
        Args:
            scan_id: Associated scan ID for context and history
        """
        self.scan_id = scan_id
        self._tool_effectiveness: Dict[str, float] = {}
        self._used_tools: Set[str] = set()
        
        logger.info(f"Initialized ToolSelector for scan: {scan_id}")
    
    async def select_tools(
        self,
        context: Dict[str, Any],
        phase: str = "reconnaissance",
        max_tools: int = 5,
        exclude_tools: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Select appropriate tools based on scan context.
        
        Args:
            context: Scan context including:
                - target: Target URL/IP
                - discovered_services: List of discovered services
                - discovered_endpoints: List of discovered endpoints
                - vulnerabilities: Previously found vulnerabilities
                - technologies: Detected technologies
                - phase: Current scan phase
            phase: Current scan phase
            max_tools: Maximum number of tools to select
            exclude_tools: Tools to exclude from selection
            
        Returns:
            List of selected tools with parameters:
            [
                {
                    "tool_name": "nmap_scan",
                    "parameters": {"target": "10.0.0.1", "scan_type": "full"},
                    "priority": 1,
                    "rationale": "Initial port scanning to discover services"
                },
                ...
            ]
        """
        logger.info(f"Selecting tools for phase: {phase}")
        
        exclude_tools = exclude_tools or []
        
        # Get available tools from Hexstrike
        hexstrike = await get_hexstrike_client()
        available_tools = await hexstrike.list_tools()
        
        # Filter by phase-relevant categories
        relevant_categories = self.PHASE_TOOL_CATEGORIES.get(phase, [])
        phase_tools = [
            tool for tool in available_tools
            if tool.get("category") in relevant_categories
            and tool.get("name") not in exclude_tools
            and tool.get("name") not in self._used_tools
        ]
        
        logger.debug(f"Found {len(phase_tools)} tools relevant to phase '{phase}'")
        
        if not phase_tools:
            logger.warning(f"No tools available for phase: {phase}")
            return []
        
        # Build AI prompt for tool selection
        prompt = self._build_selection_prompt(
            context=context,
            phase=phase,
            available_tools=phase_tools,
            max_tools=max_tools,
        )
        
        # Get AI decision
        ollama = await get_ollama_client()
        
        try:
            response = await ollama.chat(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert penetration tester selecting security tools. "
                            "Analyze the scan context and select the most appropriate tools. "
                            "Respond ONLY with valid JSON - no markdown, no explanations."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,  # Lower temperature for more deterministic selection
                stream=False,
            )
            
            # Parse AI response
            ai_response = response.get("message", {}).get("content", "")
            selected_tools = self._parse_ai_response(ai_response, phase_tools)
            
            # Log decision to database
            await self._log_decision(
                phase=phase,
                context=context,
                selected_tools=selected_tools,
                ai_response=ai_response,
            )
            
            # Track used tools
            for tool in selected_tools:
                self._used_tools.add(tool["tool_name"])
            
            logger.success(f"Selected {len(selected_tools)} tools: {[t['tool_name'] for t in selected_tools]}")
            
            return selected_tools
        
        except Exception as e:
            logger.error(f"Tool selection failed: {e}")
            # Fallback to rule-based selection
            return self._fallback_selection(phase_tools, phase, max_tools)
    
    def _build_selection_prompt(
        self,
        context: Dict[str, Any],
        phase: str,
        available_tools: List[Dict[str, Any]],
        max_tools: int,
    ) -> str:
        """Build prompt for AI tool selection"""
        
        # Format available tools
        tools_list = []
        for tool in available_tools:
            tools_list.append({
                "name": tool.get("name"),
                "category": tool.get("category"),
                "description": tool.get("description"),
                "parameters": list(tool.get("parameters", {}).keys()) if tool.get("parameters") else []
            })
        
        prompt = f"""Select the {max_tools} most appropriate security tools for the current scan phase.

**Scan Context:**
- Target: {context.get('target', 'Unknown')}
- Phase: {phase}
- Discovered Services: {context.get('discovered_services', [])}
- Discovered Endpoints: {context.get('discovered_endpoints', [])}
- Technologies: {context.get('technologies', [])}
- Previous Vulnerabilities: {len(context.get('vulnerabilities', []))} found

**Available Tools:**
{json.dumps(tools_list, indent=2)}

**Selection Criteria:**
1. Relevance to current phase ({phase})
2. Effectiveness against detected technologies
3. Coverage of attack surface
4. Tool dependency and sequencing
5. Time efficiency

**Required Output Format (JSON only, no markdown):**
{{
  "selected_tools": [
    {{
      "tool_name": "tool_name_here",
      "parameters": {{"param1": "value1", "param2": "value2"}},
      "priority": 1,
      "rationale": "Brief explanation for selection"
    }}
  ]
}}

Respond with JSON only. No markdown formatting. No code blocks."""
        
        return prompt
    
    def _parse_ai_response(
        self,
        ai_response: str,
        available_tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Parse AI response and validate tool selections.
        
        Args:
            ai_response: Raw AI response text
            available_tools: List of available tools for validation
            
        Returns:
            List of validated tool selections
        """
        try:
            # Clean up response - remove markdown code blocks if present
            response_text = ai_response.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            # Parse JSON
            data = json.loads(response_text)
            
            selected = data.get("selected_tools", [])
            
            # Validate tool names
            available_names = {tool["name"] for tool in available_tools}
            validated = []
            
            for tool_selection in selected:
                tool_name = tool_selection.get("tool_name")
                if tool_name in available_names:
                    validated.append(tool_selection)
                else:
                    logger.warning(f"AI selected unavailable tool: {tool_name}")
            
            return validated
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response was: {ai_response}")
            return []
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return []
    
    def _fallback_selection(
        self,
        available_tools: List[Dict[str, Any]],
        phase: str,
        max_tools: int,
    ) -> List[Dict[str, Any]]:
        """
        Rule-based fallback selection when AI fails.
        
        Args:
            available_tools: List of available tools
            phase: Current scan phase
            max_tools: Maximum tools to select
            
        Returns:
            List of selected tools
        """
        logger.info("Using rule-based fallback tool selection")
        
        # Priority tools for each phase
        priority_tools = {
            "reconnaissance": ["nmap_scan", "rustscan_fast_scan", "masscan_high_speed"],
            "enumeration": ["gobuster_scan", "ffuf_scan", "nuclei_scan"],
            "vulnerability_scanning": ["nuclei_scan", "nikto_scan", "wapiti_scan"],
            "exploitation": ["sqlmap_scan", "hydra_attack", "metasploit_exploit"],
            "post_exploitation": ["linpeas_scan", "winpeas_scan"],
        }
        
        phase_priorities = priority_tools.get(phase, [])
        
        selected = []
        for tool in available_tools:
            if len(selected) >= max_tools:
                break
            
            tool_name = tool.get("name")
            
            # Check if tool is in priority list
            if tool_name in phase_priorities:
                selected.append({
                    "tool_name": tool_name,
                    "parameters": {},  # Will be filled by orchestrator
                    "priority": phase_priorities.index(tool_name) + 1,
                    "rationale": f"Priority tool for {phase} phase"
                })
        
        # If not enough priority tools, add others
        if len(selected) < max_tools:
            for tool in available_tools:
                if len(selected) >= max_tools:
                    break
                
                tool_name = tool.get("name")
                if tool_name not in [t["tool_name"] for t in selected]:
                    selected.append({
                        "tool_name": tool_name,
                        "parameters": {},
                        "priority": len(selected) + 1,
                        "rationale": f"Category-based selection for {phase}"
                    })
        
        return selected
    
    async def _log_decision(
        self,
        phase: str,
        context: Dict[str, Any],
        selected_tools: List[Dict[str, Any]],
        ai_response: str,
    ):
        """
        Log AI decision to database for learning.
        
        Args:
            phase: Scan phase
            context: Scan context
            selected_tools: Selected tools
            ai_response: Raw AI response
        """
        if not self.scan_id:
            return
        
        try:
            with get_db_session() as db:
                decision = AIDecision(
                    scan_id=self.scan_id,
                    decision_type="tool_selection",
                    phase=phase,
                    context=context,
                    decision={
                        "selected_tools": selected_tools,
                        "ai_response": ai_response,
                    },
                    timestamp=datetime.now(),
                )
                db.add(decision)
                db.commit()
                
                logger.debug(f"Logged tool selection decision for scan {self.scan_id}")
        
        except Exception as e:
            logger.error(f"Failed to log decision: {e}")
    
    async def update_effectiveness(
        self,
        tool_name: str,
        success: bool,
        findings_count: int = 0,
    ):
        """
        Update tool effectiveness tracking.
        
        Args:
            tool_name: Name of the tool
            success: Whether execution was successful
            findings_count: Number of findings/vulnerabilities discovered
        """
        # Calculate effectiveness score
        score = 0.0
        if success:
            score = 0.5 + (min(findings_count, 10) / 20)  # 0.5 for success, up to 1.0 for findings
        
        # Update running average
        current_score = self._tool_effectiveness.get(tool_name, 0.5)
        new_score = (current_score * 0.7) + (score * 0.3)  # Weighted average
        
        self._tool_effectiveness[tool_name] = new_score
        
        logger.debug(f"Updated effectiveness for {tool_name}: {new_score:.2f}")
    
    async def get_recommendations(
        self,
        target_type: str,
        discovered_info: Dict[str, Any],
    ) -> List[str]:
        """
        Get tool recommendations based on target type and discovered information.
        
        Args:
            target_type: Type of target (web, network, api, cloud, etc.)
            discovered_info: Information discovered so far
            
        Returns:
            List of recommended tool names
        """
        recommendations = []
        
        # Web application tools
        if target_type == "web":
            recommendations.extend([
                "nuclei_scan",
                "gobuster_scan",
                "nikto_scan",
                "sqlmap_scan",
            ])
        
        # Network/Infrastructure tools
        elif target_type == "network":
            recommendations.extend([
                "nmap_scan",
                "masscan_high_speed",
                "rustscan_fast_scan",
            ])
        
        # API tools
        elif target_type == "api":
            recommendations.extend([
                "nuclei_scan",
                "ffuf_scan",
                "arjun_parameter_discovery",
            ])
        
        # Cloud tools
        elif target_type == "cloud":
            recommendations.extend([
                "prowler_scan",
                "scout_suite_assessment",
                "cloudmapper_analysis",
            ])
        
        # Container/Kubernetes tools
        elif target_type == "container":
            recommendations.extend([
                "trivy_scan",
                "kube_hunter_scan",
                "docker_bench_security_scan",
            ])
        
        # Technology-specific recommendations
        technologies = discovered_info.get("technologies", [])
        
        if "WordPress" in technologies:
            recommendations.append("wpscan_wordpress_scan")
        
        if "Drupal" in technologies:
            recommendations.append("droopescan_cms_scan")
        
        if "Java" in technologies:
            recommendations.append("java_deserialization_scan")
        
        if "PHP" in technologies:
            recommendations.extend(["php_info_scan", "php_filter_scan"])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for tool in recommendations:
            if tool not in seen:
                seen.add(tool)
                unique_recommendations.append(tool)
        
        logger.info(f"Generated {len(unique_recommendations)} recommendations for {target_type}")
        
        return unique_recommendations
    
    def reset_usage(self):
        """Reset used tools tracking (e.g., for new scan phase)"""
        self._used_tools.clear()
        logger.debug("Reset tool usage tracking")
