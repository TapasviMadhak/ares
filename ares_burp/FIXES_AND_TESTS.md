# ARES Burp Integration - Fixes and Testing

## Bugs Fixed (2026-03-29)

### 1. Critical: ProxyManager httpx API Fix
**File**: `proxy_manager.py:62`
- **Issue**: Used `proxies` parameter instead of `proxy` - caused TypeError
- **Fix**: Changed `httpx.AsyncClient(proxies=...)` → `httpx.AsyncClient(proxy=...)`
- **Impact**: Module would crash at runtime

### 2. Deprecation: datetime.utcnow()
**File**: `scanner_bridge.py:68`
- **Issue**: Used deprecated `datetime.utcnow()`
- **Fix**: Changed to `datetime.now(timezone.utc)`
- **Impact**: Future Python compatibility

## Testing
- Created `tests/test_burp_integration.py` with 25 tests
- All tests passing ✓
- Coverage: BurpClient, ProxyManager, ScannerBridge, BurpError

## Module Usage
```python
from ares_burp import BurpClient, ProxyManager, ScannerBridge

# Use BurpClient for API communication
async with BurpClient() as burp:
    task_id = await burp.start_scan("https://example.com")
    
# Use ProxyManager to route traffic through Burp
manager = ProxyManager()
response = await manager.request_through_proxy("GET", "https://example.com")

# Use ScannerBridge to coordinate ARES + Burp
bridge = ScannerBridge(burp, scan_id=123)
await bridge.start_coordinated_scan("https://example.com")
```

## Status
✅ All bugs fixed, tested, and verified
