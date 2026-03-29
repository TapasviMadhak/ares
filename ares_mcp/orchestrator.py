"""
Multi-Tool Orchestrator

Orchestrates complex security testing workflows by:
- Chaining multiple tools in logical sequences
- Managing dependencies between tool executions
- Caching results in Redis for performance
- Adapting strategy based on intermediate results
- Storing execution history in database

Implements autonomous attack scenarios where the AI chains tools
based on reconnaissance findings.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from loguru import logger
import redis.asyncio as aioredis

from ares_core.config import settings
from ares_core.database import get_db_session
from ares_core.models import Scan, ScanLog, Vulnerability, VulnerabilitySeverity
from ares_core.ollama_client import get_ollama_client

from .hexstrike_client import get_hexstrike_client, ToolExecutionError
from .tool_selector import ToolSelector


class OrchestrationStatus(str, Enum):
    """Orchestration status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolDependency(str, Enum):
    """Tool dependency types"""
    SEQUENTIAL = "sequential"  # Must run after previous tool
    CONDITIONAL = "conditional"  # Run only if condition met
    PARALLEL = "parallel"  # Can run in parallel
    OPTIONAL = "optional"  # Run if time permits


class Orchestrator:
    """
    Multi-tool orchestration engine for complex attack workflows.
    
    Features:
    - Intelligent tool chaining based on results
    - Redis caching for tool outputs
    - Adaptive strategy selection
    - Parallel execution where possible
    - Comprehensive logging and history
    - Graceful error handling and recovery
    """
    
    def __init__(
        self,
        scan_id: str,
        target: str,
        max_concurrent_tools: int = 3,
        cache_ttl: int = 3600,
    ):
        """
        Initialize Orchestrator.
        
        Args:
            scan_id: Unique scan identifier
            target: Target URL/IP address
            max_concurrent_tools: Maximum parallel tool executions
            cache_ttl: Redis cache TTL in seconds
        """
        self.scan_id = scan_id
        self.target = target
        self.max_concurrent_tools = max_concurrent_tools
        self.cache_ttl = cache_ttl
        
        self.status = OrchestrationStatus.PENDING
        self.tool_selector = ToolSelector(scan_id=scan_id)
        
        # Execution state
        self.execution_history: List[Dict[str, Any]] = []
        self.discovered_vulnerabilities: List[Dict[str, Any]] = []
        self.scan_context: Dict[str, Any] = {
            "target": target,
            "discovered_services": [],
            "discovered_endpoints": [],
            "technologies": [],
            "vulnerabilities": [],
            "phase": "reconnaissance",
        }
        
        # Redis client (initialized later)
        self._redis: Optional[aioredis.Redis] = None
        
        logger.info(f"Initialized Orchestrator for scan {scan_id}, target: {target}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._init_redis()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self._redis = await aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
            await self._redis.ping()
            logger.debug("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Caching disabled.")
            self._redis = None
    
    async def cleanup(self):
        """Cleanup resources"""
        if self._redis:
            await self._redis.close()
            logger.debug("Redis connection closed")
    
    async def execute_workflow(
        self,
        workflow_type: str = "full_scan",
        custom_tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a complete security testing workflow.
        
        Args:
            workflow_type: Type of workflow to execute:
                - "full_scan": Complete reconnaissance to exploitation
                - "quick_scan": Fast reconnaissance and vulnerability scan
                - "deep_scan": Thorough testing with all available tools
                - "custom": Use custom_tools list
            custom_tools: Custom list of tools for "custom" workflow
            
        Returns:
            Workflow execution summary with findings
        """
        logger.info(f"Starting {workflow_type} workflow for {self.target}")
        
        self.status = OrchestrationStatus.RUNNING
        start_time = datetime.now()
        
        try:
            # Update scan status in database
            await self._update_scan_status("running")
            
            # Execute workflow phases
            if workflow_type == "full_scan":
                await self._execute_full_scan()
            elif workflow_type == "quick_scan":
                await self._execute_quick_scan()
            elif workflow_type == "deep_scan":
                await self._execute_deep_scan()
            elif workflow_type == "custom" and custom_tools:
                await self._execute_custom_workflow(custom_tools)
            else:
                raise ValueError(f"Unknown workflow type: {workflow_type}")
            
            self.status = OrchestrationStatus.COMPLETED
            await self._update_scan_status("completed")
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Generate summary
            summary = {
                "scan_id": self.scan_id,
                "target": self.target,
                "workflow_type": workflow_type,
                "status": self.status.value,
                "execution_time": execution_time,
                "tools_executed": len(self.execution_history),
                "vulnerabilities_found": len(self.discovered_vulnerabilities),
                "scan_context": self.scan_context,
                "execution_history": self.execution_history,
            }
            
            logger.success(
                f"Workflow completed: {len(self.execution_history)} tools executed, "
                f"{len(self.discovered_vulnerabilities)} vulnerabilities found in {execution_time:.2f}s"
            )
            
            return summary
        
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            self.status = OrchestrationStatus.FAILED
            await self._update_scan_status("failed")
            raise
    
    async def _execute_full_scan(self):
        """Execute complete reconnaissance to exploitation workflow"""
        
        phases = [
            ("reconnaissance", 3),
            ("enumeration", 3),
            ("vulnerability_scanning", 5),
            ("exploitation", 2),
        ]
        
        for phase_name, max_tools in phases:
            logger.info(f"=== Phase: {phase_name.upper()} ===")
            
            self.scan_context["phase"] = phase_name
            
            # Select tools for this phase
            selected_tools = await self.tool_selector.select_tools(
                context=self.scan_context,
                phase=phase_name,
                max_tools=max_tools,
            )
            
            if not selected_tools:
                logger.warning(f"No tools selected for phase: {phase_name}")
                continue
            
            # Execute tools and update context
            await self._execute_phase_tools(selected_tools, phase_name)
            
            # Adapt strategy based on findings
            await self._adapt_strategy(phase_name)
            
            # Log phase completion
            await self._log_scan_event(
                f"Completed phase: {phase_name}",
                level="info",
                category="orchestration",
            )
    
    async def _execute_quick_scan(self):
        """Execute quick reconnaissance and vulnerability scan"""
        
        phases = [
            ("reconnaissance", 1),
            ("vulnerability_scanning", 2),
        ]
        
        for phase_name, max_tools in phases:
            self.scan_context["phase"] = phase_name
            
            selected_tools = await self.tool_selector.select_tools(
                context=self.scan_context,
                phase=phase_name,
                max_tools=max_tools,
            )
            
            if selected_tools:
                await self._execute_phase_tools(selected_tools, phase_name)
    
    async def _execute_deep_scan(self):
        """Execute thorough testing with extensive tool coverage"""
        
        phases = [
            ("reconnaissance", 5),
            ("enumeration", 5),
            ("vulnerability_scanning", 10),
            ("exploitation", 5),
            ("post_exploitation", 3),
        ]
        
        for phase_name, max_tools in phases:
            self.scan_context["phase"] = phase_name
            
            selected_tools = await self.tool_selector.select_tools(
                context=self.scan_context,
                phase=phase_name,
                max_tools=max_tools,
            )
            
            if selected_tools:
                await self._execute_phase_tools(selected_tools, phase_name)
                await self._adapt_strategy(phase_name)
    
    async def _execute_custom_workflow(self, tools: List[str]):
        """Execute custom tool sequence"""
        
        logger.info(f"Executing custom workflow with {len(tools)} tools")
        
        for tool_name in tools:
            # Get tool info
            hexstrike = await get_hexstrike_client()
            tool_info = await hexstrike.get_tool_info(tool_name)
            
            if not tool_info:
                logger.warning(f"Tool not found: {tool_name}")
                continue
            
            # Build parameters using AI
            parameters = await self._build_tool_parameters(tool_name, tool_info)
            
            # Execute tool
            result = await self._execute_single_tool(tool_name, parameters)
            
            if result:
                await self._process_tool_result(result)
    
    async def _execute_phase_tools(
        self,
        selected_tools: List[Dict[str, Any]],
        phase: str,
    ):
        """
        Execute tools for a specific phase.
        
        Args:
            selected_tools: List of selected tools with parameters
            phase: Current phase name
        """
        logger.info(f"Executing {len(selected_tools)} tools for phase: {phase}")
        
        # Sort by priority
        selected_tools.sort(key=lambda t: t.get("priority", 999))
        
        # Group tools by dependency type
        parallel_tools = []
        sequential_tools = []
        
        for tool_spec in selected_tools:
            dependency = tool_spec.get("dependency", "sequential")
            if dependency == "parallel":
                parallel_tools.append(tool_spec)
            else:
                sequential_tools.append(tool_spec)
        
        # Execute parallel tools concurrently
        if parallel_tools:
            await self._execute_parallel_tools(parallel_tools)
        
        # Execute sequential tools one by one
        for tool_spec in sequential_tools:
            tool_name = tool_spec["tool_name"]
            parameters = tool_spec.get("parameters", {})
            
            # Build complete parameters if not provided
            if not parameters:
                hexstrike = await get_hexstrike_client()
                tool_info = await hexstrike.get_tool_info(tool_name)
                if tool_info:
                    parameters = await self._build_tool_parameters(tool_name, tool_info)
            
            # Execute tool
            result = await self._execute_single_tool(tool_name, parameters)
            
            if result:
                # Process results and update context
                await self._process_tool_result(result)
    
    async def _execute_parallel_tools(
        self,
        tools: List[Dict[str, Any]],
    ):
        """Execute multiple tools in parallel with concurrency limit"""
        
        logger.info(f"Executing {len(tools)} tools in parallel (max concurrent: {self.max_concurrent_tools})")
        
        semaphore = asyncio.Semaphore(self.max_concurrent_tools)
        
        async def execute_with_semaphore(tool_spec: Dict[str, Any]):
            async with semaphore:
                tool_name = tool_spec["tool_name"]
                parameters = tool_spec.get("parameters", {})
                
                if not parameters:
                    hexstrike = await get_hexstrike_client()
                    tool_info = await hexstrike.get_tool_info(tool_name)
                    if tool_info:
                        parameters = await self._build_tool_parameters(tool_name, tool_info)
                
                return await self._execute_single_tool(tool_name, parameters)
        
        results = await asyncio.gather(
            *[execute_with_semaphore(tool) for tool in tools],
            return_exceptions=True,
        )
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Parallel tool execution failed: {result}")
            elif result:
                await self._process_tool_result(result)
    
    async def _execute_single_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a single tool with caching.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            Tool execution result or None if failed
        """
        # Generate cache key
        cache_key = self._generate_cache_key(tool_name, parameters)
        
        # Check cache
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            logger.info(f"Using cached result for {tool_name}")
            return cached_result
        
        logger.info(f"Executing tool: {tool_name}")
        
        start_time = datetime.now()
        
        try:
            # Execute tool via Hexstrike client
            hexstrike = await get_hexstrike_client()
            result = await hexstrike.execute_tool(tool_name, parameters)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Add metadata
            result["tool_name"] = tool_name
            result["parameters"] = parameters
            result["execution_time"] = execution_time
            result["timestamp"] = datetime.now().isoformat()
            result["scan_id"] = self.scan_id
            
            # Cache result
            await self._cache_result(cache_key, result)
            
            # Update execution history
            self.execution_history.append({
                "tool_name": tool_name,
                "parameters": parameters,
                "success": result.get("success", False),
                "execution_time": execution_time,
                "timestamp": result["timestamp"],
            })
            
            # Update tool effectiveness
            findings_count = len(result.get("vulnerabilities", []))
            await self.tool_selector.update_effectiveness(
                tool_name=tool_name,
                success=result.get("success", False),
                findings_count=findings_count,
            )
            
            # Log to database
            await self._log_scan_event(
                message=f"Executed tool: {tool_name}",
                level="info" if result.get("success") else "warning",
                category="tool_execution",
                details={
                    "tool_name": tool_name,
                    "execution_time": execution_time,
                    "success": result.get("success", False),
                },
            )
            
            return result
        
        except ToolExecutionError as e:
            logger.error(f"Tool execution failed for {tool_name}: {e}")
            
            await self._log_scan_event(
                message=f"Tool execution failed: {tool_name}",
                level="error",
                category="tool_execution",
                details={"tool_name": tool_name, "error": str(e)},
            )
            
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error executing {tool_name}: {e}")
            return None
    
    async def _build_tool_parameters(
        self,
        tool_name: str,
        tool_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build tool parameters using AI based on scan context.
        
        Args:
            tool_name: Name of the tool
            tool_info: Tool metadata
            
        Returns:
            Dictionary of tool parameters
        """
        # Get required parameters from tool info
        required_params = tool_info.get("parameters", {})
        
        # Build prompt for AI
        prompt = f"""Generate parameters for security tool execution.

Tool: {tool_name}
Description: {tool_info.get('description', '')}

Required Parameters:
{json.dumps(required_params, indent=2)}

Scan Context:
{json.dumps(self.scan_context, indent=2)}

Generate appropriate parameter values based on the scan context.
Respond ONLY with valid JSON - no markdown, no explanations.

Format:
{{
  "parameter_name": "value",
  ...
}}
"""
        
        try:
            ollama = await get_ollama_client()
            response = await ollama.chat(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security testing expert. Generate tool parameters. Respond with JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                stream=False,
            )
            
            ai_response = response.get("message", {}).get("content", "")
            
            # Clean and parse response
            response_text = ai_response.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            parameters = json.loads(response_text)
            
            # Ensure target is included
            if "target" not in parameters and "host" not in parameters:
                parameters["target"] = self.target
            
            return parameters
        
        except Exception as e:
            logger.error(f"Failed to build parameters for {tool_name}: {e}")
            # Return minimal parameters
            return {"target": self.target}
    
    async def _process_tool_result(self, result: Dict[str, Any]):
        """
        Process tool execution result and update scan context.
        
        Args:
            result: Tool execution result
        """
        if not result.get("success"):
            return
        
        output = result.get("output", "")
        tool_name = result.get("tool_name", "")
        
        # Extract vulnerabilities
        vulnerabilities = result.get("vulnerabilities", [])
        if vulnerabilities:
            self.discovered_vulnerabilities.extend(vulnerabilities)
            self.scan_context["vulnerabilities"].extend(vulnerabilities)
            
            # Save to database
            await self._save_vulnerabilities(vulnerabilities)
        
        # Extract discovered services
        services = result.get("services", [])
        if services:
            for service in services:
                if service not in self.scan_context["discovered_services"]:
                    self.scan_context["discovered_services"].append(service)
        
        # Extract endpoints
        endpoints = result.get("endpoints", [])
        if endpoints:
            for endpoint in endpoints:
                if endpoint not in self.scan_context["discovered_endpoints"]:
                    self.scan_context["discovered_endpoints"].append(endpoint)
        
        # Extract technologies
        technologies = result.get("technologies", [])
        if technologies:
            for tech in technologies:
                if tech not in self.scan_context["technologies"]:
                    self.scan_context["technologies"].append(tech)
        
        logger.debug(f"Updated scan context from {tool_name} results")
    
    async def _adapt_strategy(self, current_phase: str):
        """
        Adapt testing strategy based on current findings.
        
        Args:
            current_phase: Current scan phase
        """
        logger.info("Adapting strategy based on findings...")
        
        # Analyze findings to determine if we should adjust approach
        vuln_count = len(self.discovered_vulnerabilities)
        
        if vuln_count > 10:
            logger.info("High vulnerability count detected - prioritizing exploitation phase")
            # Could adjust next phase tools here
        
        # Check for high-severity vulnerabilities
        high_severity_count = sum(
            1 for v in self.discovered_vulnerabilities
            if v.get("severity") in ["CRITICAL", "HIGH"]
        )
        
        if high_severity_count > 0:
            logger.warning(f"Found {high_severity_count} high-severity vulnerabilities")
            # Could trigger immediate exploitation attempts
    
    def _generate_cache_key(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """Generate cache key for tool execution"""
        params_str = json.dumps(parameters, sort_keys=True)
        return f"ares:tool:{self.scan_id}:{tool_name}:{hash(params_str)}"
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached tool result from Redis"""
        if not self._redis:
            return None
        
        try:
            cached = await self._redis.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.debug(f"Cache read failed: {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache tool result in Redis"""
        if not self._redis:
            return
        
        try:
            await self._redis.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(result),
            )
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")
    
    async def _update_scan_status(self, status: str):
        """Update scan status in database"""
        try:
            with get_db_session() as db:
                scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
                if scan:
                    scan.status = status
                    scan.updated_at = datetime.now()
                    db.commit()
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")
    
    async def _log_scan_event(
        self,
        message: str,
        level: str = "info",
        category: str = "general",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log scan event to database"""
        try:
            with get_db_session() as db:
                log_entry = ScanLog(
                    scan_id=self.scan_id,
                    level=level,
                    message=message,
                    category=category,
                    details=details or {},
                    timestamp=datetime.now(),
                )
                db.add(log_entry)
                db.commit()
        except Exception as e:
            logger.error(f"Failed to log scan event: {e}")
    
    async def _save_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Save discovered vulnerabilities to database"""
        try:
            with get_db_session() as db:
                for vuln_data in vulnerabilities:
                    vuln = Vulnerability(
                        scan_id=self.scan_id,
                        title=vuln_data.get("title", "Unknown Vulnerability"),
                        description=vuln_data.get("description", ""),
                        severity=vuln_data.get("severity", "INFO"),
                        cvss_score=vuln_data.get("cvss_score"),
                        cwe_id=vuln_data.get("cwe_id"),
                        url=vuln_data.get("url", self.target),
                        evidence=vuln_data.get("evidence", {}),
                        remediation=vuln_data.get("remediation"),
                        discovered_at=datetime.now(),
                    )
                    db.add(vuln)
                
                db.commit()
                logger.info(f"Saved {len(vulnerabilities)} vulnerabilities to database")
        
        except Exception as e:
            logger.error(f"Failed to save vulnerabilities: {e}")
