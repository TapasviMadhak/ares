"""
Web Crawler for ARES
Discovers URLs, forms, API endpoints, and parameters
"""

from typing import List, Set, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass
import asyncio
from playwright.async_api import async_playwright, Page, Browser
from loguru import logger


@dataclass
class CrawledEndpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str = "GET"
    parameters: Dict[str, List[str]] = None
    forms: List[Dict] = None
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.forms is None:
            self.forms = []
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}


class WebCrawler:
    """
    Intelligent web crawler for security testing
    """
    
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        respect_robots: bool = False,
        user_agent: str = None
    ):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.user_agent = user_agent or "ARES-Scanner/0.1"
        
        # State
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[CrawledEndpoint] = []
        self.forms_found: List[Dict] = []
        self.api_endpoints: Set[str] = set()
        
        # Target domain for scope checking
        self.target_domain = urlparse(target_url).netloc
        
        logger.info(f"Initialized crawler for {target_url}")
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        parsed = urlparse(url)
        return parsed.netloc == self.target_domain
    
    async def crawl(self) -> List[CrawledEndpoint]:
        """
        Start crawling the target
        
        Returns:
            List of discovered endpoints
        """
        logger.info(f"Starting crawl of {self.target_url}")
        
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=True
            )
            
            await self._crawl_url(context, self.target_url, depth=0)
            
            await browser.close()
        
        logger.info(f"Crawl complete. Discovered {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints
    
    async def _crawl_url(self, context, url: str, depth: int):
        """Recursively crawl URLs"""
        
        # Check limits
        if depth > self.max_depth:
            return
        if len(self.visited_urls) >= self.max_pages:
            return
        if url in self.visited_urls:
            return
        if not self.is_in_scope(url):
            return
        
        self.visited_urls.add(url)
        logger.debug(f"Crawling: {url} (depth: {depth})")
        
        try:
            page = await context.new_page()
            
            # Navigate to URL
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            
            if not response:
                logger.warning(f"No response from {url}")
                return
            
            # Create endpoint entry
            endpoint = CrawledEndpoint(
                url=url,
                method="GET",
                headers=await response.all_headers(),
            )
            
            # Extract parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                endpoint.parameters = parse_qs(parsed.query)
            
            # Find forms
            forms = await self._extract_forms(page)
            endpoint.forms = forms
            self.forms_found.extend(forms)
            
            # Find links
            links = await self._extract_links(page, url)
            
            # Detect API endpoints from JavaScript
            api_endpoints = await self._detect_api_endpoints(page)
            self.api_endpoints.update(api_endpoints)
            
            # Add to discovered endpoints
            self.discovered_endpoints.append(endpoint)
            
            await page.close()
            
            # Recursively crawl discovered links
            tasks = []
            for link in list(links)[:10]:  # Limit concurrent crawls
                if link not in self.visited_urls:
                    tasks.append(self._crawl_url(context, link, depth + 1))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
    
    async def _extract_links(self, page: Page, base_url: str) -> Set[str]:
        """Extract all links from page"""
        links = set()
        
        try:
            # Get all <a> tags
            a_tags = await page.query_selector_all('a[href]')
            for tag in a_tags:
                href = await tag.get_attribute('href')
                if href:
                    absolute_url = urljoin(base_url, href)
                    if self.is_in_scope(absolute_url):
                        # Remove fragment
                        absolute_url = absolute_url.split('#')[0]
                        links.add(absolute_url)
        
        except Exception as e:
            logger.error(f"Error extracting links: {e}")
        
        return links
    
    async def _extract_forms(self, page: Page) -> List[Dict]:
        """Extract all forms from page"""
        forms = []
        
        try:
            form_elements = await page.query_selector_all('form')
            
            for form_elem in form_elements:
                form_data = {
                    'action': await form_elem.get_attribute('action'),
                    'method': (await form_elem.get_attribute('method') or 'GET').upper(),
                    'inputs': []
                }
                
                # Get all input fields
                inputs = await form_elem.query_selector_all('input, textarea, select')
                for input_elem in inputs:
                    input_data = {
                        'name': await input_elem.get_attribute('name'),
                        'type': await input_elem.get_attribute('type') or 'text',
                        'value': await input_elem.get_attribute('value'),
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
        
        except Exception as e:
            logger.error(f"Error extracting forms: {e}")
        
        return forms
    
    async def _detect_api_endpoints(self, page: Page) -> Set[str]:
        """Detect API endpoints from JavaScript"""
        endpoints = set()
        
        try:
            # Look for common API patterns in JavaScript
            script_content = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.querySelectorAll('script'));
                    return scripts.map(s => s.textContent || '').join('\\n');
                }
            """)
            
            # Simple regex patterns for API endpoints
            import re
            patterns = [
                r'["\']/(api|graphql|rest|v\d+)/[^"\']+["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, script_content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    endpoint = urljoin(page.url, match)
                    if self.is_in_scope(endpoint):
                        endpoints.add(endpoint)
        
        except Exception as e:
            logger.error(f"Error detecting API endpoints: {e}")
        
        return endpoints
    
    def get_summary(self) -> Dict:
        """Get crawl summary statistics"""
        return {
            'total_urls': len(self.visited_urls),
            'total_endpoints': len(self.discovered_endpoints),
            'forms_found': len(self.forms_found),
            'api_endpoints': len(self.api_endpoints),
            'discovered_urls': list(self.visited_urls),
        }
