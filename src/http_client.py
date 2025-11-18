"""HTTP client wrapper for Auth0 API requests"""

import asyncio
import time
from typing import Optional
from urllib.parse import urljoin

import httpx
from rich.console import Console

console = Console()


class Auth0HttpClient:
    """
    Wrapper around httpx for Auth0-specific requests.
    Handles rate limiting, retries, and request tracking.
    """
    
    def __init__(
        self,
        domain: str,
        rate_limit_delay: float = 1.0,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """
        Initialize HTTP client.
        
        Args:
            domain: Auth0 tenant domain (e.g., victim.auth0.com)
            rate_limit_delay: Delay between requests in seconds
            proxy: HTTP proxy URL
            user_agent: Custom User-Agent header
        """
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0
        
        # Request statistics
        self.total_requests = 0
        self.rate_limited_count = 0
        self.error_count = 0
        
        # HTTP client configuration
        headers = {
            "User-Agent": user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        
        client_kwargs = {
            "headers": headers,
            "timeout": 30.0,
            "follow_redirects": False,  # We want to detect redirects manually
        }
        
        if proxy:
            client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}
        
        self.client = httpx.AsyncClient(**client_kwargs)
    
    async def _rate_limit_wait(self):
        """Apply rate limiting delay between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    async def get(
        self,
        path: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Execute GET request.
        
        Args:
            path: API path (e.g., '/oauth/token')
            params: Query parameters
            headers: Additional headers
            **kwargs: Additional httpx request parameters
        
        Returns:
            httpx.Response object
        """
        await self._rate_limit_wait()
        self.total_requests += 1
        
        url = urljoin(self.base_url, path)
        
        try:
            response = await self.client.get(url, params=params, headers=headers, **kwargs)
            self._check_rate_limit(response)
            return response
        except Exception as e:
            self.error_count += 1
            console.print(f"[red]Request error:[/red] {e}")
            raise
    
    async def post(
        self,
        path: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Execute POST request.
        
        Args:
            path: API path
            data: Form data
            json: JSON body
            headers: Additional headers
            **kwargs: Additional httpx request parameters
        
        Returns:
            httpx.Response object
        """
        await self._rate_limit_wait()
        self.total_requests += 1
        
        url = urljoin(self.base_url, path)
        
        try:
            response = await self.client.post(url, data=data, json=json, headers=headers, **kwargs)
            self._check_rate_limit(response)
            return response
        except Exception as e:
            self.error_count += 1
            console.print(f"[red]Request error:[/red] {e}")
            raise
    
    async def options(
        self,
        path: str,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Execute OPTIONS request (for CORS testing).
        
        Args:
            path: API path
            headers: Additional headers
            **kwargs: Additional httpx request parameters
        
        Returns:
            httpx.Response object
        """
        await self._rate_limit_wait()
        self.total_requests += 1
        
        url = urljoin(self.base_url, path)
        
        try:
            response = await self.client.request("OPTIONS", url, headers=headers, **kwargs)
            return response
        except Exception as e:
            self.error_count += 1
            console.print(f"[red]Request error:[/red] {e}")
            raise
    
    async def patch(
        self,
        path: str,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Execute PATCH request.
        
        Args:
            path: API path
            json: JSON body
            headers: Additional headers
            **kwargs: Additional httpx request parameters
        
        Returns:
            httpx.Response object
        """
        await self._rate_limit_wait()
        self.total_requests += 1
        
        url = urljoin(self.base_url, path)
        
        try:
            response = await self.client.patch(url, json=json, headers=headers, **kwargs)
            self._check_rate_limit(response)
            return response
        except Exception as e:
            self.error_count += 1
            console.print(f"[red]Request error:[/red] {e}")
            raise
    
    def _check_rate_limit(self, response: httpx.Response):
        """Check if response indicates rate limiting"""
        if response.status_code == 429:
            self.rate_limited_count += 1
            console.print("[yellow]⚠️  Rate limited! Stopping scan.[/yellow]")
            raise RateLimitException("Rate limit exceeded")
        
        # Check for account blocking
        try:
            body = response.json()
            if "error" in body:
                if "blocked" in body.get("error", "").lower():
                    console.print("[red]🛑 Account blocked! Stopping scan.[/red]")
                    raise AccountBlockedException("Account has been blocked")
                
                if "too many" in body.get("error_description", "").lower():
                    self.rate_limited_count += 1
                    console.print("[yellow]⚠️  Too many attempts! Stopping scan.[/yellow]")
                    raise RateLimitException("Too many attempts")
        except (ValueError, KeyError):
            pass
    
    async def measure_timing(
        self,
        path: str,
        method: str = "POST",
        **kwargs
    ) -> tuple[httpx.Response, float]:
        """
        Execute request and measure response time (for timing attacks).
        
        Args:
            path: API path
            method: HTTP method
            **kwargs: Request parameters
        
        Returns:
            Tuple of (response, elapsed_time_ms)
        """
        await self._rate_limit_wait()
        self.total_requests += 1
        
        url = urljoin(self.base_url, path)
        
        start_time = time.perf_counter()
        
        try:
            if method.upper() == "POST":
                response = await self.client.post(url, **kwargs)
            elif method.upper() == "GET":
                response = await self.client.get(url, **kwargs)
            else:
                response = await self.client.request(method, url, **kwargs)
            
            elapsed = (time.perf_counter() - start_time) * 1000  # Convert to ms
            
            return response, elapsed
        except Exception as e:
            self.error_count += 1
            console.print(f"[red]Request error:[/red] {e}")
            raise
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
    
    def get_stats(self) -> dict:
        """Get request statistics"""
        return {
            "total_requests": self.total_requests,
            "rate_limited_count": self.rate_limited_count,
            "error_count": self.error_count,
        }


class RateLimitException(Exception):
    """Raised when rate limit is exceeded"""
    pass


class AccountBlockedException(Exception):
    """Raised when account is blocked"""
    pass

