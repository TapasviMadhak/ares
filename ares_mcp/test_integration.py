#!/usr/bin/env python3
"""
ARES MCP Integration - Quick Test

Tests the basic functionality of the MCP integration module.
Run this to verify everything is working correctly.
"""

import asyncio
import sys
from loguru import logger

# Add ARES to path
sys.path.insert(0, '/mnt/d_drive/ares')

from ares_mcp import HexstrikeClient


async def test_connection():
    """Test 1: Connection to Hexstrike server"""
    print("\n" + "="*60)
    print("TEST 1: Hexstrike Server Connection")
    print("="*60)
    
    try:
        async with HexstrikeClient() as client:
            healthy = await client.health_check()
            
            if healthy:
                print("✅ PASS: Hexstrike server is reachable and healthy")
                return True
            else:
                print("❌ FAIL: Hexstrike server returned unhealthy status")
                return False
    
    except Exception as e:
        print(f"❌ FAIL: Could not connect to Hexstrike server")
        print(f"   Error: {e}")
        print("\n💡 Make sure Hexstrike server is running:")
        print("   cd /mnt/d_drive/ares/ares_mcp/hexstrike-ai/")
        print("   python3 hexstrike_server.py")
        return False


async def test_tool_discovery():
    """Test 2: Tool discovery"""
    print("\n" + "="*60)
    print("TEST 2: Tool Discovery")
    print("="*60)
    
    try:
        async with HexstrikeClient() as client:
            tools = await client.list_tools()
            
            if tools and len(tools) > 0:
                print(f"✅ PASS: Discovered {len(tools)} tools")
                
                # Show categories
                categories = await client.get_tool_categories()
                print(f"   Categories: {len(categories)}")
                for cat in list(categories.keys())[:5]:
                    print(f"      - {cat}: {len(categories[cat])} tools")
                
                return True
            else:
                print("❌ FAIL: No tools discovered")
                return False
    
    except Exception as e:
        print(f"❌ FAIL: Tool discovery failed")
        print(f"   Error: {e}")
        return False


async def test_tool_search():
    """Test 3: Tool search functionality"""
    print("\n" + "="*60)
    print("TEST 3: Tool Search")
    print("="*60)
    
    try:
        async with HexstrikeClient() as client:
            # Search for nmap
            results = await client.search_tools("nmap")
            
            if results:
                print(f"✅ PASS: Found {len(results)} tools matching 'nmap'")
                for tool in results[:3]:
                    print(f"      - {tool['name']}")
                return True
            else:
                print("❌ FAIL: No tools found for 'nmap'")
                return False
    
    except Exception as e:
        print(f"❌ FAIL: Tool search failed")
        print(f"   Error: {e}")
        return False


async def test_imports():
    """Test 4: Import all modules"""
    print("\n" + "="*60)
    print("TEST 4: Module Imports")
    print("="*60)
    
    try:
        from ares_mcp import HexstrikeClient, ToolSelector, Orchestrator
        from ares_mcp.hexstrike_client import get_hexstrike_client
        
        print("✅ PASS: All modules imported successfully")
        print("   - HexstrikeClient")
        print("   - ToolSelector")
        print("   - Orchestrator")
        return True
    
    except ImportError as e:
        print(f"❌ FAIL: Import error")
        print(f"   Error: {e}")
        return False


async def test_ai_integration():
    """Test 5: AI integration (Ollama)"""
    print("\n" + "="*60)
    print("TEST 5: AI Integration (Ollama)")
    print("="*60)
    
    try:
        from ares_core.ollama_client import get_ollama_client
        
        client = await get_ollama_client()
        
        # Try to check if model is available
        available = await client.check_model()
        
        if available:
            print("✅ PASS: Ollama client initialized successfully")
            print(f"   Model: {client.model}")
            return True
        else:
            print("⚠️  WARN: Ollama client initialized but model not available")
            print(f"   Model: {client.model}")
            print("\n💡 Make sure Ollama is running:")
            print("   ollama serve")
            return False
    
    except Exception as e:
        print(f"⚠️  WARN: AI integration test skipped")
        print(f"   Error: {e}")
        print("\n💡 Make sure Ollama is installed and running:")
        print("   ollama serve")
        return False


async def test_redis():
    """Test 6: Redis connection"""
    print("\n" + "="*60)
    print("TEST 6: Redis Connection")
    print("="*60)
    
    try:
        import redis.asyncio as aioredis
        from ares_core.config import settings
        
        redis_client = await aioredis.from_url(settings.redis_url)
        await redis_client.ping()
        await redis_client.close()
        
        print("✅ PASS: Redis connection successful")
        return True
    
    except Exception as e:
        print(f"⚠️  WARN: Redis connection failed")
        print(f"   Error: {e}")
        print("\n💡 Make sure Redis is running:")
        print("   redis-server")
        return False


async def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("🧪 ARES MCP Integration - Test Suite")
    print("="*60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Hexstrike Connection", test_connection),
        ("Tool Discovery", test_tool_discovery),
        ("Tool Search", test_tool_search),
        ("AI Integration", test_ai_integration),
        ("Redis Connection", test_redis),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            logger.exception(f"Test '{test_name}' crashed")
            results.append((test_name, False))
            print(f"\n💥 Test crashed: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "-"*60)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    print("="*60)
    
    if passed == total:
        print("\n🎉 All tests passed! MCP integration is ready to use.")
        print("\n📚 Next steps:")
        print("   1. Run examples: python3 /mnt/d_drive/ares/ares_mcp/examples.py")
        print("   2. Check README: cat /mnt/d_drive/ares/ares_mcp/README.md")
    elif passed >= total * 0.5:
        print("\n⚠️  Some tests failed, but core functionality works.")
        print("   Check failed tests and ensure all services are running.")
    else:
        print("\n❌ Multiple tests failed. Please check:")
        print("   1. Hexstrike server is running")
        print("   2. Ollama is installed and running")
        print("   3. Redis is running")
        print("   4. Database is initialized")
    
    return passed == total


if __name__ == "__main__":
    try:
        asyncio.run(run_all_tests())
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test suite failed: {e}")
        logger.exception("Test suite error")
