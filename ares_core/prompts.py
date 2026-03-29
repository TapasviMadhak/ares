"""
Prompt Templates for AI-Powered Security Testing
"""

from typing import Dict, List, Any
from enum import Enum


class PromptType(Enum):
    """Types of prompts for different phases"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    EXPLOITATION = "exploitation"
    REPORT_GENERATION = "report_generation"
    DECISION_MAKING = "decision_making"


class SecurityPromptTemplates:
    """Security-focused prompt templates"""
    
    SYSTEM_PROMPT = """You are ARES (Automated Red-Teaming Evaluation System), an expert AI security researcher specializing in web application penetration testing. 

Your capabilities include:
- Identifying OWASP Top 10 vulnerabilities
- Advanced attack vector analysis (SSRF, XXE, Deserialization, SSTI, Race Conditions)
- Intelligent payload generation and fuzzing
- Security misconfiguration detection
- Business logic flaw analysis

You are ethical, thorough, and precise. You only test applications you have explicit authorization to test. Your goal is to find vulnerabilities to help improve security, not to cause harm.

When analyzing security issues:
1. Be specific about the vulnerability type and CVSS score
2. Provide clear proof-of-concept steps
3. Suggest remediation strategies
4. Prioritize findings by severity and exploitability
5. Avoid false positives by validating findings

Respond in JSON format when requested for structured data."""

    RECONNAISSANCE_PROMPT = """Analyze the following web application target and create a comprehensive reconnaissance plan:

Target URL: {target_url}
Technologies Detected: {technologies}
Available Information: {context}

Tasks:
1. Identify all endpoints, forms, and API routes
2. Map the application structure and data flow
3. Detect authentication mechanisms and session management
4. Find interesting parameters and input points
5. Identify potential attack surfaces

Provide your analysis and a prioritized list of areas to test. Focus on high-risk components first."""

    VULNERABILITY_ANALYSIS_PROMPT = """You are analyzing a web application for security vulnerabilities.

Context:
- URL: {url}
- Method: {method}
- Parameters: {parameters}
- Response Status: {status_code}
- Response Headers: {headers}
- Response Body (truncated): {body}
- Previous Findings: {findings}

Analyze this HTTP interaction for potential vulnerabilities. Consider:
1. SQL Injection (error-based, boolean-based, time-based)
2. Cross-Site Scripting (reflected, stored, DOM-based)
3. CSRF vulnerabilities
4. Authentication/Authorization flaws
5. SSRF possibilities
6. XXE vulnerabilities
7. Insecure deserialization
8. Path traversal / LFI
9. Command injection
10. Open redirect
11. CORS misconfigurations
12. Security header issues

For each potential vulnerability:
- Specify the type and severity (Critical/High/Medium/Low)
- Explain the indicator that suggests this vulnerability
- Recommend a specific payload or test to confirm
- Estimate confidence level (High/Medium/Low)

Respond in JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "severity": "High",
            "confidence": "Medium",
            "indicator": "what suggests this vulnerability",
            "recommended_test": "specific payload or test",
            "details": "explanation"
        }}
    ],
    "next_action": "what to test next"
}}"""

    PAYLOAD_GENERATION_PROMPT = """Generate intelligent payloads to test for {vulnerability_type}.

Context:
- Target: {url}
- Parameter: {parameter}
- Context: {context}
- Input Validation Observed: {validation}
- WAF/Filters Detected: {waf_info}

Requirements:
1. Generate 10-15 varied payloads
2. Include basic and advanced evasion techniques
3. Consider the application context (e.g., inside HTML tag, JavaScript, SQL)
4. Adapt to detected filters/WAF
5. Include both common and creative payloads

Return as JSON:
{{
    "payloads": [
        {{
            "payload": "actual payload string",
            "technique": "technique description",
            "expected_result": "what indicates success"
        }}
    ]
}}"""

    EXPLOITATION_STRATEGY_PROMPT = """A potential {vulnerability_type} vulnerability has been identified.

Details:
- URL: {url}
- Parameter: {parameter}
- Confidence: {confidence}
- Initial Evidence: {evidence}

Create an exploitation strategy:
1. How to confirm the vulnerability exists (proof-of-concept)
2. Steps to demonstrate impact (without causing harm)
3. What data can be extracted or actions performed
4. Potential for privilege escalation or lateral movement
5. Safe exploitation boundaries

Provide a step-by-step safe exploitation plan. Remember: we're demonstrating risk, not causing damage."""

    DECISION_MAKING_PROMPT = """You are controlling an autonomous penetration testing session.

Current State:
- Target: {target}
- Scan Progress: {progress}%
- Vulnerabilities Found: {vulns_found}
- Time Elapsed: {time_elapsed}
- Resources Used: {resources}

Available Actions:
{available_actions}

Recent Results:
{recent_results}

Decide the next best action to maximize vulnerability discovery while respecting:
- Rate limits and stealth requirements
- Time and resource constraints
- Prioritizing high-value targets
- Avoiding duplicate work

Respond in JSON:
{{
    "next_action": "action_id",
    "reasoning": "why this action",
    "parameters": {{}},
    "priority": "High/Medium/Low",
    "estimated_time": "seconds"
}}"""

    FALSE_POSITIVE_CHECK_PROMPT = """Verify if this is a true vulnerability or false positive.

Finding:
- Type: {vuln_type}
- Location: {url}
- Evidence: {evidence}
- Payload Used: {payload}
- Response: {response}

Verification Criteria:
1. Does the response clearly indicate vulnerability?
2. Could this be expected application behavior?
3. Are there alternative explanations?
4. Can we reproduce it consistently?
5. Does it pose actual security risk?

Respond with:
{{
    "is_true_positive": true/false,
    "confidence": "0-100",
    "reasoning": "detailed explanation",
    "additional_tests": ["tests to confirm"]
}}"""

    REPORT_GENERATION_PROMPT = """Generate a comprehensive security assessment report.

Scan Details:
- Target: {target}
- Duration: {duration}
- Pages Scanned: {pages_scanned}
- Vulnerabilities Found: {total_vulns}

Findings:
{findings_json}

Create a professional report including:
1. Executive Summary (non-technical overview)
2. Vulnerability Summary (categorized by severity)
3. Detailed Findings (each with description, impact, PoC, remediation)
4. Risk Assessment
5. Remediation Priority Roadmap
6. Appendix (methodology, scope, tools used)

Format as markdown for easy conversion to PDF/HTML."""

    LEARNING_PROMPT = """Analyze this penetration testing session for learning.

Session Summary:
- Successful Attacks: {successful_attacks}
- Failed Attacks: {failed_attacks}
- Novel Findings: {novel_findings}
- Techniques Used: {techniques}

Questions:
1. What worked well and why?
2. What failed and why?
3. Are there patterns in successful vs failed attacks?
4. What new techniques should we try next time?
5. How can we improve detection accuracy?

Provide insights to improve future testing strategies."""

    @staticmethod
    def get_prompt(prompt_type: PromptType, **kwargs) -> str:
        """Get formatted prompt by type"""
        prompts = {
            PromptType.RECONNAISSANCE: SecurityPromptTemplates.RECONNAISSANCE_PROMPT,
            PromptType.VULNERABILITY_DETECTION: SecurityPromptTemplates.VULNERABILITY_ANALYSIS_PROMPT,
            PromptType.EXPLOITATION: SecurityPromptTemplates.EXPLOITATION_STRATEGY_PROMPT,
            PromptType.REPORT_GENERATION: SecurityPromptTemplates.REPORT_GENERATION_PROMPT,
            PromptType.DECISION_MAKING: SecurityPromptTemplates.DECISION_MAKING_PROMPT,
        }
        
        template = prompts.get(prompt_type, "")
        try:
            return template.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing required parameter for prompt: {e}")
    
    @staticmethod
    def get_system_prompt() -> str:
        """Get the system prompt"""
        return SecurityPromptTemplates.SYSTEM_PROMPT

# Additional direct exports for ai_decision_maker.py
VULNERABILITY_ANALYSIS_PROMPT = """
You are analyzing vulnerability scan results for a web application penetration test.

Vulnerability Count: {vulnerability_count}
Scan Context: {scan_context}

Discovered Vulnerabilities:
{vulnerability_list}

Your task:
1. Analyze each vulnerability's severity, exploitability, and business impact
2. Prioritize vulnerabilities for exploitation (highest impact first)
3. Identify vulnerabilities that can be chained together
4. Suggest which vulnerabilities to exploit first and why

Provide your analysis in JSON format:
{{
    "priorities": [
        {{
            "vuln_id": "...",
            "priority_score": 1-10,
            "rationale": "why this is high priority",
            "exploit_difficulty": "trivial|easy|moderate|hard|very_hard",
            "chain_potential": "can this be chained with others?",
            "recommended_action": "what to do with this vuln"
        }}
    ],
    "exploit_chains": [
        {{
            "vulns": ["id1", "id2"],
            "goal": "what this chain achieves",
            "steps": ["step 1", "step 2"]
        }}
    ],
    "summary": "overall assessment"
}}
"""

DECISION_MAKING_PROMPT = """
You are an autonomous penetration testing AI making strategic decisions.

Current State:
{current_state}

Available Actions:
{available_actions}

Constraints:
{constraints}

Previous Decisions:
{scan_history}

Analyze the current state and decide the best next action. Consider:
1. Which action maximizes information gain or impact?
2. What are the risks vs rewards?
3. Are we making progress toward objectives?
4. Should we pivot strategy based on findings?

Provide your decision in JSON format:
{{
    "action": "chosen action from available actions",
    "rationale": "why this action makes sense",
    "confidence": 0.0-1.0,
    "risk_level": "low|medium|high|critical",
    "expected_outcome": "what we expect to achieve",
    "fallback_action": "what to do if this fails",
    "estimated_time": "estimated time in seconds"
}}
"""

