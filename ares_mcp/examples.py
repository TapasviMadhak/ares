#!/usr/bin/env python3
"""
ARES MCP Integration - Example Usage

Demonstrates how to use the Hexstrike-AI MCP integration module.

Examples:
1. Basic tool execution
2. AI-powered tool selection
3. Full orchestrated workflow
4. Custom attack scenarios
"""

import asyncio
import sys
from datetime import datetime
from loguru import logger

# Add ARES to path
sys.path.insert(0, '/mnt/d_drive/ares')

from ares_mcp import HexstrikeClient, ToolSelector, Orchestrator
from ares_core.config import settings
from ares_core.database import get_db_session, init_db
from ares_core.models import Scan, ScanStatus, ScanMode


async def example_1_basic_tool_execution():
    """Example 1: Basic tool execution using HexstrikeClient"""
    
    print("\n" + "="*80)
    print("Example 1: Basic Tool Execution")
    print("="*80)
    
    async with HexstrikeClient() as client:
        # Check server health
        healthy = await client.health_check()
        print(f"\n✓ Hexstrike server health: {'OK' if healthy else 'FAILED'}")
        
        if not healthy:
            print("⚠️  Hexstrike server not reachable. Make sure it's running.")
            return
        
        # List available tools
        tools = await client.list_tools()
        print(f"\n✓ Available tools: {len(tools)}")
        
        # Show tool categories
        categories = await client.get_tool_categories()
        print("\n📂 Tool Categories:")
        for category, tool_list in categories.items():
            print(f"   - {category}: {len(tool_list)} tools")
        
        # Execute a simple Nmap scan
        print("\n🔧 Executing Nmap scan on localhost...")
        result = await client.execute_tool(
            tool_name="nmap_scan",
            parameters={
                "target": "127.0.0.1",
                "scan_type": "quick",
                "ports": "80,443,8000,8888",
            }
        )
        
        print(f"\n✓ Scan completed: {result['success']}")
        print(f"⏱️  Execution time: {result['execution_time']:.2f}s")
        if result['output']:
            print(f"\n📄 Output (first 500 chars):\n{result['output'][:500]}")


async def example_2_ai_tool_selection():
    """Example 2: AI-powered tool selection"""
    
    print("\n" + "="*80)
    print("Example 2: AI-Powered Tool Selection")
    print("="*80)
    
    # Create scan context
    scan_context = {
        "target": "https://example.com",
        "discovered_services": ["http", "https", "ssh"],
        "discovered_endpoints": ["/api", "/admin", "/login"],
        "technologies": ["PHP", "MySQL", "Apache"],
        "vulnerabilities": [],
        "phase": "reconnaissance"
    }
    
    print(f"\n📍 Target: {scan_context['target']}")
    print(f"🔍 Phase: {scan_context['phase']}")
    print(f"💻 Technologies: {', '.join(scan_context['technologies'])}")
    
    # Initialize tool selector
    selector = ToolSelector(scan_id="example_scan_001")
    
    # Select tools for reconnaissance phase
    print("\n🤖 AI selecting tools for reconnaissance phase...")
    selected_tools = await selector.select_tools(
        context=scan_context,
        phase="reconnaissance",
        max_tools=3,
    )
    
    print(f"\n✓ Selected {len(selected_tools)} tools:")
    for i, tool in enumerate(selected_tools, 1):
        print(f"\n   {i}. {tool['tool_name']} (Priority: {tool['priority']})")
        print(f"      Rationale: {tool['rationale']}")
        print(f"      Parameters: {tool.get('parameters', {})}")
    
    # Get recommendations based on target type
    print("\n💡 Getting tool recommendations for web application...")
    recommendations = await selector.get_recommendations(
        target_type="web",
        discovered_info=scan_context,
    )
    
    print(f"\n✓ Recommended tools: {', '.join(recommendations[:5])}")


async def example_3_full_orchestration():
    """Example 3: Full orchestrated workflow"""
    
    print("\n" + "="*80)
    print("Example 3: Full Orchestrated Workflow")
    print("="*80)
    
    # Initialize database
    init_db()
    
    # Create scan record
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    target = "http://testphp.vulnweb.com"  # Vulnerable test site
    
    print(f"\n🎯 Target: {target}")
    print(f"🔑 Scan ID: {scan_id}")
    
    # Create scan in database
    with get_db_session() as db:
        scan = Scan(
            id=scan_id,
            target_url=target,
            scan_mode=ScanMode.FULLY_AUTOMATED,
            status=ScanStatus.PENDING,
            created_at=datetime.now(),
        )
        db.add(scan)
        db.commit()
        print("✓ Scan record created in database")
    
    # Execute workflow
    print("\n🚀 Starting full scan workflow...")
    print("   This will execute multiple phases:")
    print("   1. Reconnaissance")
    print("   2. Enumeration")
    print("   3. Vulnerability Scanning")
    print("   4. Exploitation")
    
    async with Orchestrator(
        scan_id=scan_id,
        target=target,
        max_concurrent_tools=3,
    ) as orchestrator:
        
        try:
            summary = await orchestrator.execute_workflow(
                workflow_type="quick_scan",  # Use quick_scan for demo
            )
            
            print("\n" + "="*80)
            print("Workflow Summary")
            print("="*80)
            print(f"✓ Status: {summary['status']}")
            print(f"⏱️  Total execution time: {summary['execution_time']:.2f}s")
            print(f"🔧 Tools executed: {summary['tools_executed']}")
            print(f"🐛 Vulnerabilities found: {summary['vulnerabilities_found']}")
            
            if summary['execution_history']:
                print("\n📋 Execution History:")
                for i, entry in enumerate(summary['execution_history'], 1):
                    status_icon = "✓" if entry['success'] else "✗"
                    print(f"   {i}. {status_icon} {entry['tool_name']} ({entry['execution_time']:.2f}s)")
            
            if summary.get('scan_context', {}).get('discovered_services'):
                print(f"\n🔍 Discovered Services: {summary['scan_context']['discovered_services']}")
            
            if summary.get('scan_context', {}).get('technologies'):
                print(f"💻 Detected Technologies: {summary['scan_context']['technologies']}")
        
        except Exception as e:
            print(f"\n❌ Workflow failed: {e}")
            logger.exception("Workflow error")


async def example_4_custom_workflow():
    """Example 4: Custom attack scenario"""
    
    print("\n" + "="*80)
    print("Example 4: Custom Attack Scenario")
    print("="*80)
    
    scan_id = f"custom_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    target = "192.168.1.0/24"
    
    print(f"\n🎯 Target: {target}")
    print(f"📋 Scenario: Network reconnaissance and vulnerability assessment")
    
    # Define custom tool sequence
    custom_tools = [
        "nmap_scan",           # Initial port scan
        "rustscan_fast_scan",  # Fast port discovery
        "nuclei_scan",         # Vulnerability scanning
        "nikto_scan",          # Web server testing
    ]
    
    print(f"\n🔧 Custom tool sequence: {' → '.join(custom_tools)}")
    
    async with Orchestrator(
        scan_id=scan_id,
        target=target,
        max_concurrent_tools=2,
    ) as orchestrator:
        
        try:
            summary = await orchestrator.execute_workflow(
                workflow_type="custom",
                custom_tools=custom_tools,
            )
            
            print(f"\n✓ Custom workflow completed")
            print(f"⏱️  Execution time: {summary['execution_time']:.2f}s")
            print(f"🐛 Vulnerabilities: {summary['vulnerabilities_found']}")
        
        except Exception as e:
            print(f"\n❌ Custom workflow failed: {e}")


async def example_5_batch_execution():
    """Example 5: Batch tool execution"""
    
    print("\n" + "="*80)
    print("Example 5: Batch Tool Execution")
    print("="*80)
    
    async with HexstrikeClient() as client:
        # Prepare batch of tool executions
        tool_requests = [
            ("nmap_scan", {"target": "127.0.0.1", "ports": "80"}),
            ("rustscan_fast_scan", {"target": "127.0.0.1"}),
            # Add more tools as needed
        ]
        
        print(f"\n🔧 Executing {len(tool_requests)} tools in parallel...")
        
        results = await client.execute_tools_batch(
            tool_requests=tool_requests,
            max_concurrent=3,
        )
        
        print(f"\n✓ Batch execution completed")
        for i, result in enumerate(results, 1):
            status = "✓" if result['success'] else "✗"
            print(f"   {i}. {status} {result['tool_name']} ({result['execution_time']:.2f}s)")


async def main():
    """Run all examples"""
    
    print("\n" + "="*80)
    print("🎯 ARES MCP Integration - Usage Examples")
    print("="*80)
    print("\nThis script demonstrates the Hexstrike-AI MCP integration.")
    print("Make sure the Hexstrike server is running at http://127.0.0.1:8888")
    
    examples = [
        ("Basic Tool Execution", example_1_basic_tool_execution),
        ("AI-Powered Tool Selection", example_2_ai_tool_selection),
        ("Full Orchestrated Workflow", example_3_full_orchestration),
        ("Custom Attack Scenario", example_4_custom_workflow),
        ("Batch Tool Execution", example_5_batch_execution),
    ]
    
    print("\n📚 Available Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"   {i}. {name}")
    
    print("\n" + "="*80)
    
    # Run examples
    choice = input("\nSelect example to run (1-5, or 'all'): ").strip()
    
    if choice.lower() == 'all':
        for name, example_func in examples:
            await example_func()
            await asyncio.sleep(2)  # Brief pause between examples
    elif choice.isdigit() and 1 <= int(choice) <= len(examples):
        idx = int(choice) - 1
        await examples[idx][1]()
    else:
        print("Invalid choice. Running Example 1 by default.")
        await example_1_basic_tool_execution()
    
    print("\n" + "="*80)
    print("✅ Examples completed!")
    print("="*80 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        logger.exception("Example execution failed")
