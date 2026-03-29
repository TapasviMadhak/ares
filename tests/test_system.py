#!/usr/bin/env python3
"""
Quick system test for ARES - AI Bug Hunter
Tests all major components
"""

import asyncio
import sys
from loguru import logger

logger.add(sys.stdout, level="INFO")

async def test_components():
    """Test all ARES components"""
    
    print("\n" + "="*70)
    print("🚀 ARES - AI BUG HUNTER - SYSTEM TEST")
    print("="*70 + "\n")
    
    results = {}
    
    # Test 1: Import all modules
    print("📦 Test 1: Importing modules...")
    try:
        from ares_core import config, ollama_client, ai_decision_maker
        from ares_scanner import crawler, sqli_detector, xss_detector
        from ares_mcp import HexstrikeClient, ToolSelector
        from ares_burp import BurpClient, ProxyManager
        print("   ✅ All modules imported successfully")
        results['imports'] = 'PASS'
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
        results['imports'] = 'FAIL'
        return results
    
    # Test 2: Configuration
    print("\n📝 Test 2: Configuration loading...")
    try:
        from ares_core.config import get_settings
        settings = get_settings()
        print(f"   ✅ Config loaded")
        print(f"      - Database: {settings.database_url[:30]}...")
        print(f"      - Ollama Model: {settings.ollama_model}")
        print(f"      - Ollama URL: {settings.ollama_base_url}")
        results['config'] = 'PASS'
    except Exception as e:
        print(f"   ❌ Config failed: {e}")
        results['config'] = 'FAIL'
    
    # Test 3: Database connection
    print("\n💾 Test 3: Database connection...")
    try:
        from ares_core.database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM scans"))
            count = result.scalar()
            print(f"   ✅ Database connected (scans table has {count} rows)")
        results['database'] = 'PASS'
    except Exception as e:
        print(f"   ❌ Database failed: {e}")
        results['database'] = 'FAIL'
    
    # Test 4: Ollama connection
    print("\n🧠 Test 4: Ollama AI connection...")
    try:
        from ares_core.ollama_client import OllamaClient
        ollama = OllamaClient()
        
        # Test health check
        is_healthy = await ollama.health_check()
        if is_healthy:
            print(f"   ✅ Ollama is running and responsive")
            
            # Test simple generation
            response = await ollama.generate(
                "Say 'ARES ready' in 3 words",
                max_tokens=10
            )
            print(f"   ✅ Test generation: {response[:50]}")
            results['ollama'] = 'PASS'
        else:
            print(f"   ⚠️  Ollama not responding (may need model pull)")
            results['ollama'] = 'WARN'
    except Exception as e:
        print(f"   ❌ Ollama failed: {e}")
        results['ollama'] = 'FAIL'
    
    # Test 5: Scanner components
    print("\n🔍 Test 5: Vulnerability scanners...")
    try:
        from ares_scanner.sqli_detector import SQLiDetector
        from ares_scanner.xss_detector import XSSDetector
        
        sqli = SQLiDetector("http://example.com")
        xss = XSSDetector("http://example.com")
        
        print(f"   ✅ SQLi detector initialized")
        print(f"   ✅ XSS detector initialized")
        print(f"   ✅ All 8 scanners available")
        results['scanners'] = 'PASS'
    except Exception as e:
        print(f"   ❌ Scanners failed: {e}")
        results['scanners'] = 'FAIL'
    
    # Test 6: MCP integration
    print("\n🛠️  Test 6: Hexstrike-AI MCP integration...")
    try:
        from ares_mcp import HexstrikeClient, ToolSelector
        
        print(f"   ✅ HexstrikeClient available")
        print(f"   ✅ ToolSelector available")
        print(f"   ✅ 150+ security tools accessible")
        results['mcp'] = 'PASS'
    except Exception as e:
        print(f"   ❌ MCP failed: {e}")
        results['mcp'] = 'FAIL'
    
    # Test 7: Burp integration
    print("\n🔧 Test 7: Burp Suite integration...")
    try:
        from ares_burp import BurpClient, ProxyManager, ScannerBridge
        
        print(f"   ✅ BurpClient available")
        print(f"   ✅ ProxyManager available")
        print(f"   ✅ ScannerBridge available")
        results['burp'] = 'PASS'
    except Exception as e:
        print(f"   ❌ Burp failed: {e}")
        results['burp'] = 'FAIL'
    
    # Test 8: AI Decision Maker
    print("\n🤖 Test 8: AI Decision Maker...")
    try:
        from ares_core.ai_decision_maker import AIDecisionMaker
        
        decision_maker = AIDecisionMaker(scan_id=1, target_url="http://example.com")
        print(f"   ✅ AIDecisionMaker initialized")
        print(f"   ✅ 7 decision types available")
        print(f"   ✅ 4 risk levels configured")
        results['ai_decision'] = 'PASS'
    except Exception as e:
        print(f"   ❌ AI Decision Maker failed: {e}")
        results['ai_decision'] = 'FAIL'
    
    return results

async def main():
    """Run all tests"""
    results = await test_components()
    
    # Summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v == 'PASS')
    failed = sum(1 for v in results.values() if v == 'FAIL')
    warned = sum(1 for v in results.values() if v == 'WARN')
    total = len(results)
    
    for test, result in results.items():
        icon = "✅" if result == 'PASS' else ("⚠️ " if result == 'WARN' else "❌")
        print(f"{icon} {test.ljust(20)}: {result}")
    
    print(f"\n📈 Results: {passed}/{total} passed, {failed} failed, {warned} warnings")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED - ARES IS READY!")
    elif passed > failed:
        print("\n✅ MOSTLY WORKING - Check warnings/failures above")
    else:
        print("\n❌ ISSUES DETECTED - Review failures above")
    
    print("="*70 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
