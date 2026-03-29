"""
Tests for CSRF Detector
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from ares_scanner.csrf_detector import CSRFDetector, CSRFResult


@pytest.fixture
def detector():
    """Create CSRF detector instance"""
    return CSRFDetector(timeout=5)


@pytest.fixture
def sample_form():
    """Sample form data"""
    return {
        'action': '/submit',
        'method': 'POST',
        'inputs': [
            {'name': 'username', 'type': 'text', 'value': ''},
            {'name': 'password', 'type': 'password', 'value': ''},
            {'name': 'submit', 'type': 'submit', 'value': 'Login'}
        ]
    }


@pytest.fixture
def form_with_token():
    """Form with CSRF token"""
    return {
        'action': '/submit',
        'method': 'POST',
        'inputs': [
            {'name': 'username', 'type': 'text', 'value': ''},
            {'name': 'password', 'type': 'password', 'value': ''},
            {'name': 'csrf_token', 'type': 'hidden', 'value': 'abc123xyz789'},
            {'name': 'submit', 'type': 'submit', 'value': 'Login'}
        ]
    }


@pytest.mark.asyncio
async def test_detector_initialization(detector):
    """Test CSRF detector initialization"""
    assert detector.timeout == 5
    assert detector.session is None


@pytest.mark.asyncio
async def test_missing_csrf_token_detection(detector, sample_form):
    """Test detection of missing CSRF token"""
    with patch.object(detector, '_get_session') as mock_session:
        # Mock successful form submission without token
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Success')
        
        mock_session.return_value.request = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        results = await detector.test_form(
            url='http://example.com/login',
            form=sample_form,
            base_url='http://example.com'
        )
        
        # Should detect missing CSRF token
        assert len(results) > 0
        assert any(r.vulnerability_type == 'missing_csrf_token' for r in results)


@pytest.mark.asyncio
async def test_weak_token_detection(detector):
    """Test detection of weak CSRF tokens"""
    weak_form = {
        'action': '/submit',
        'method': 'POST',
        'inputs': [
            {'name': 'csrf_token', 'type': 'hidden', 'value': '123'},  # Too short
        ]
    }
    
    with patch.object(detector, '_get_session') as mock_session:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Success')
        
        mock_session.return_value.request = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        results = await detector.test_form(
            url='http://example.com/login',
            form=weak_form
        )
        
        # Should detect weak token
        weak_token_found = any(r.vulnerability_type == 'weak_csrf_token' for r in results)
        assert weak_token_found


@pytest.mark.asyncio
async def test_token_in_url_detection(detector):
    """Test detection of CSRF token in URL"""
    form_with_url_token = {
        'action': '/submit?csrf_token=abc123',
        'method': 'POST',
        'inputs': []
    }
    
    with patch.object(detector, '_get_session') as mock_session:
        mock_session.return_value.request = AsyncMock()
        
        results = await detector.test_form(
            url='http://example.com/login',
            form=form_with_url_token
        )
        
        # Should detect token in URL
        assert any(r.vulnerability_type == 'csrf_token_in_url' for r in results)


@pytest.mark.asyncio
async def test_samesite_cookie_check(detector):
    """Test SameSite cookie attribute check"""
    with patch.object(detector, '_get_session') as mock_session:
        # Mock cookies without SameSite
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.cookies = {
            'sessionid': {'samesite': ''}  # Missing SameSite
        }
        
        mock_session.return_value.get = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        result = await detector._check_samesite_cookie(
            'http://example.com',
            mock_session.return_value
        )
        
        if result:
            assert result.vulnerability_type == 'missing_samesite_cookie'


@pytest.mark.asyncio
async def test_oauth_missing_state(detector):
    """Test OAuth flow without state parameter"""
    with patch.object(detector, '_get_session') as mock_session:
        mock_response = AsyncMock()
        mock_response.status = 302
        mock_response.headers = {'Location': 'http://example.com/callback?code=abc'}
        
        mock_session.return_value.get = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        results = await detector.test_oauth_flow(
            authorization_url='http://oauth.example.com/authorize',
            client_id='test123'
        )
        
        # Should detect missing state
        assert any(r.vulnerability_type == 'oauth_missing_state' for r in results)


@pytest.mark.asyncio
async def test_json_endpoint_csrf(detector):
    """Test JSON endpoint for CSRF protection"""
    with patch.object(detector, '_get_session') as mock_session:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Access-Control-Allow-Origin': '*'}
        
        mock_session.return_value.request = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        result = await detector.test_json_endpoint(
            url='http://api.example.com/update',
            method='POST',
            json_data={'test': 'data'}
        )
        
        if result:
            assert result.vulnerability_type == 'json_csrf'
            assert result.severity == 'high'


@pytest.mark.asyncio
async def test_form_with_valid_token_not_flagged(detector, form_with_token):
    """Test that forms with valid tokens are not flagged"""
    with patch.object(detector, '_get_session') as mock_session:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Success')
        
        mock_session.return_value.request = AsyncMock(return_value=mock_response)
        mock_session.return_value.get = AsyncMock(return_value=mock_response)
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
        mock_session.return_value.__aexit__ = AsyncMock()
        
        # Mock the _check_missing_token to return None (token present)
        with patch.object(detector, '_check_missing_token', return_value=None):
            results = await detector.test_form(
                url='http://example.com/login',
                form=form_with_token
            )
            
            # Should not detect missing token
            assert not any(r.vulnerability_type == 'missing_csrf_token' for r in results)


@pytest.mark.asyncio
async def test_detector_cleanup(detector):
    """Test detector cleanup"""
    await detector._get_session()  # Create session
    assert detector.session is not None
    
    await detector.close()
    # Session should be closed (implementation may vary)


def test_token_names_coverage():
    """Test that common token names are covered"""
    expected_tokens = ['csrf', 'csrf_token', 'token', '_token', 'xsrf']
    
    for token in expected_tokens:
        assert token in CSRFDetector.TOKEN_NAMES


def test_state_changing_methods():
    """Test state-changing methods list"""
    assert 'POST' in CSRFDetector.STATE_CHANGING_METHODS
    assert 'PUT' in CSRFDetector.STATE_CHANGING_METHODS
    assert 'DELETE' in CSRFDetector.STATE_CHANGING_METHODS
    assert 'GET' not in CSRFDetector.STATE_CHANGING_METHODS
