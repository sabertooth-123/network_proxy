
"""
Cache Module for Proxy Server
Implements LRU (Least Recently Used) cache with configurable size and TTL
Supports HTTP response caching with proper cache-control header handling


"""

import time
import threading
import hashlib
import json
from typing import Optional, Dict, Tuple
from collections import OrderedDict
from datetime import datetime, timedelta
import logging


class CacheEntry:
    """
    Represents a single cached HTTP response
    
    Attributes:
        key (str): Unique cache key
        response_data (bytes): Cached response data
        headers (dict): Response headers
        status_code (int): HTTP status code
        timestamp (float): When the entry was cached
        ttl (int): Time to live in seconds
        size (int): Size of cached data in bytes
        hits (int): Number of cache hits
    """
    
    def __init__(self, key: str, response_data: bytes, headers: Dict[str, str],
                 status_code: int, ttl: int = 300):
        """
        Initialize a cache entry
        
        Args:
            key: Unique identifier for this cache entry
            response_data: The HTTP response body
            headers: Response headers
            status_code: HTTP status code
            ttl: Time to live in seconds (default: 5 minutes)
        """
        self.key = key
        self.response_data = response_data
        self.headers = headers
        self.status_code = status_code
        self.timestamp = time.time()
        self.ttl = ttl
        self.size = len(response_data)
        self.hits = 0
        self.last_accessed = self.timestamp
    
    def is_expired(self) -> bool:
        """Check if this cache entry has expired"""
        if self.ttl == 0:  # 0 means never expires
            return False
        return (time.time() - self.timestamp) > self.ttl
    
    def is_stale(self) -> bool:
        """
        Check if entry is stale based on Cache-Control headers
        
        Returns:
            True if entry should not be used
        """
        if self.is_expired():
            return True
        
        # Check Cache-Control headers
        cache_control = self.headers.get('cache-control', '').lower()
        
        if 'no-cache' in cache_control or 'no-store' in cache_control:
            return True
        
        # Check max-age if present
        if 'max-age=' in cache_control:
            try:
                max_age_str = cache_control.split('max-age=')[1].split(',')[0].strip()
                max_age = int(max_age_str)
                age = time.time() - self.timestamp
                if age > max_age:
                    return True
            except (ValueError, IndexError):
                pass
        
        return False
    
    def touch(self):
        """Update last accessed time and increment hit counter"""
        self.last_accessed = time.time()
        self.hits += 1
    
    def __repr__(self):
        return (f"CacheEntry(key={self.key[:20]}..., "
                f"size={self.size}, hits={self.hits}, "
                f"age={int(time.time() - self.timestamp)}s)")


class LRUCache():
    """
    LRU (Least Recently Used) Cache Implementation
    
    Thread-safe cache with automatic eviction of least recently used items
    when the cache reaches its maximum size.
    
    Features:
        - Thread-safe operations
        - Automatic LRU eviction
        - TTL (Time To Live) support
        - Cache statistics tracking
        - Configurable size limits
    
    Example:
        >>> cache = LRUCache(max_size=100, max_memory_mb=50)
        >>> cache.put("key1", b"data", {"content-type": "text/html"}, 200)
        >>> data, headers, status = cache.get("key1")
        >>> if data:
        >>>     print("Cache hit!")
    """
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100,
                 default_ttl: int = 300):
        """
        Initialize LRU cache
        
        Args:
            max_size: Maximum number of entries (default: 1000)
            max_memory_mb: Maximum memory usage in MB (default: 100)
            default_ttl: Default TTL in seconds (default: 300)
        """
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.default_ttl = default_ttl
        
        # OrderedDict maintains insertion order for LRU
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expired': 0,
            'total_size': 0,
            'entries': 0
        }
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Start cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def _generate_key(self, method: str, url: str, headers: Dict[str, str] = None) -> str:
        """
        Generate a unique cache key
        
        Args:
            method: HTTP method (GET, HEAD)
            url: Complete URL
            headers: Request headers (for Vary support)
        
        Returns:
            Unique cache key string
        """
        # Simple key: method + URL
        key_string = f"{method}:{url}"
        
        # TODO: Add Vary header support for more sophisticated caching
        # if headers and 'vary' in response_headers:
        #     vary_headers = response_headers['vary'].split(',')
        #     for header in vary_headers:
        #         key_string += f":{headers.get(header.strip(), '')}"
        
        # Use SHA256 for consistent key length
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def is_cacheable(self, method: str, status_code: int, 
                    headers: Dict[str, str]) -> bool:
        """
        Determine if a response is cacheable
        
        Args:
            method: HTTP method
            status_code: Response status code
            headers: Response headers
        
        Returns:
            True if response can be cached
        """
        # Only cache GET and HEAD requests
        if method not in ('GET', 'HEAD'):
            return False
        
        # Only cache successful responses
        if status_code not in (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501):
            return False
        
        # Check Cache-Control headers
        cache_control = headers.get('cache-control', '').lower()
        
        # Explicit no-cache or no-store
        if 'no-store' in cache_control or 'private' in cache_control:
            return False
        
        # Check for Pragma: no-cache (HTTP/1.0)
        if headers.get('pragma', '').lower() == 'no-cache':
            return False
        
        return True
    
    def get_ttl(self, headers: Dict[str, str]) -> int:
        """
        Determine TTL from response headers
        
        Args:
            headers: Response headers
        
        Returns:
            TTL in seconds
        """
        cache_control = headers.get('cache-control', '').lower()
        
        # Check for max-age
        if 'max-age=' in cache_control:
            try:
                max_age_str = cache_control.split('max-age=')[1].split(',')[0].strip()
                return int(max_age_str)
            except (ValueError, IndexError):
                pass
        
        # Check Expires header
        expires = headers.get('expires', '')
        if expires:
            try:
                # Parse expires date (simplified)
                # TODO: Implement proper HTTP date parsing
                return self.default_ttl
            except:
                pass
        
        return self.default_ttl
    
    def put(self, method: str, url: str, response_data: bytes,
            headers: Dict[str, str], status_code: int,
            request_headers: Dict[str, str] = None) -> bool:
        """
        Store a response in the cache
        
        Args:
            method: HTTP method
            url: Complete URL
            response_data: Response body
            headers: Response headers
            status_code: HTTP status code
            request_headers: Request headers (optional)
        
        Returns:
            True if cached successfully, False otherwise
        """
        # Check if cacheable
        if not self.is_cacheable(method, status_code, headers):
            self.logger.debug(f"Response not cacheable: {method} {url}")
            return False
        
        with self.lock:
            # Generate key
            key = self._generate_key(method, url, request_headers)
            
            # Get TTL
            ttl = self.get_ttl(headers)
            
            # Create cache entry
            entry = CacheEntry(key, response_data, headers, status_code, ttl)
            
            # Check if adding this would exceed memory limit
            if self.stats['total_size'] + entry.size > self.max_memory_bytes:
                # Evict entries until we have space
                self._evict_until_space(entry.size)
            
            # Check if we need to evict due to max size
            if len(self.cache) >= self.max_size:
                self._evict_lru()
            
            # Add to cache
            self.cache[key] = entry
            self.cache.move_to_end(key)  # Mark as most recently used
            
            # Update stats
            self.stats['total_size'] += entry.size
            self.stats['entries'] = len(self.cache)
            
            self.logger.info(f"Cached: {method} {url[:50]} (size: {entry.size}, ttl: {ttl})")
            return True
    
    def get(self, method: str, url: str,
            request_headers: Dict[str, str] = None) -> Tuple[Optional[bytes], Optional[Dict], Optional[int]]:
        """
        Retrieve a response from cache
        
        Args:
            method: HTTP method
            url: Complete URL
            request_headers: Request headers (optional)
        
        Returns:
            Tuple of (response_data, headers, status_code) or (None, None, None) if not found
        """
        with self.lock:
            key = self._generate_key(method, url, request_headers)
            
            # Check if in cache
            if key not in self.cache:
                self.stats['misses'] += 1
                return None, None, None
            
            entry = self.cache[key]
            
            # Check if stale
            if entry.is_stale():
                self.logger.debug(f"Cache entry expired: {url[:50]}")
                del self.cache[key]
                self.stats['total_size'] -= entry.size
                self.stats['expired'] += 1
                self.stats['misses'] += 1
                self.stats['entries'] = len(self.cache)
                return None, None, None
            
            # Update access time and move to end (most recently used)
            entry.touch()
            self.cache.move_to_end(key)
            
            # Update stats
            self.stats['hits'] += 1
            
            self.logger.info(f"Cache HIT: {method} {url[:50]} (hits: {entry.hits})")
            
            return entry.response_data, entry.headers.copy(), entry.status_code
    
    def _evict_lru(self):
        """Evict the least recently used entry"""
        if not self.cache:
            return
        
        # Remove first item (least recently used)
        key, entry = self.cache.popitem(last=False)
        self.stats['total_size'] -= entry.size
        self.stats['evictions'] += 1
        self.stats['entries'] = len(self.cache)
        
        self.logger.debug(f"Evicted LRU entry: {entry.key[:20]}... (age: {int(time.time() - entry.timestamp)}s)")
    
    def _evict_until_space(self, needed_space: int):
        """Evict entries until we have enough space"""
        while self.cache and (self.stats['total_size'] + needed_space > self.max_memory_bytes):
            self._evict_lru()
    
    def _cleanup_loop(self):
        """Background thread to clean up expired entries"""
        while self.running:
            time.sleep(60)  # Run every minute
            self._cleanup_expired()
    
    def _cleanup_expired(self):
        """Remove all expired entries"""
        with self.lock:
            expired_keys = []
            
            for key, entry in self.cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                entry = self.cache[key]
                del self.cache[key]
                self.stats['total_size'] -= entry.size
                self.stats['expired'] += 1
            
            if expired_keys:
                self.stats['entries'] = len(self.cache)
                self.logger.info(f"Cleaned up {len(expired_keys)} expired entries")
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.stats['total_size'] = 0
            self.stats['entries'] = 0
            self.logger.info("Cache cleared")
    
    def remove(self, method: str, url: str, request_headers: Dict[str, str] = None):
        """Remove a specific entry from cache"""
        with self.lock:
            key = self._generate_key(method, url, request_headers)
            if key in self.cache:
                entry = self.cache[key]
                del self.cache[key]
                self.stats['total_size'] -= entry.size
                self.stats['entries'] = len(self.cache)
                self.logger.info(f"Removed from cache: {url[:50]}")
    
    def get_stats(self) -> Dict:
        """
        Get cache statistics
        
        Returns:
            Dictionary with cache statistics
        """
        with self.lock:
            stats = self.stats.copy()
            
            # Calculate hit rate
            total_requests = stats['hits'] + stats['misses']
            if total_requests > 0:
                stats['hit_rate'] = (stats['hits'] / total_requests) * 100
            else:
                stats['hit_rate'] = 0.0
            
            # Memory usage
            stats['memory_usage_mb'] = stats['total_size'] / (1024 * 1024)
            stats['memory_limit_mb'] = self.max_memory_bytes / (1024 * 1024)
            stats['memory_usage_percent'] = (stats['total_size'] / self.max_memory_bytes) * 100
            
            # Size limits
            stats['max_entries'] = self.max_size
            stats['entries_usage_percent'] = (stats['entries'] / self.max_size) * 100
            
            return stats
    
    def get_entries_info(self, limit: int = 10) -> list:
        """
        Get information about cached entries
        
        Args:
            limit: Maximum number of entries to return
        
        Returns:
            List of entry information dictionaries
        """
        with self.lock:
            entries_info = []
            
            for key, entry in list(self.cache.items())[:limit]:
                info = {
                    'key': entry.key[:16] + '...',
                    'size_kb': entry.size / 1024,
                    'hits': entry.hits,
                    'age_seconds': int(time.time() - entry.timestamp),
                    'ttl': entry.ttl,
                    'status_code': entry.status_code,
                    'expired': entry.is_expired()
                }
                entries_info.append(info)
            
            return entries_info
    
    def shutdown(self):
        """Shutdown the cache and cleanup thread"""
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=2)
        self.clear()


# Convenience function
def create_cache(max_size: int = 1000, max_memory_mb: int = 100,
                default_ttl: int = 300) -> LRUCache:
    """
    Create and return an LRU cache instance
    
    Args:
        max_size: Maximum number of entries
        max_memory_mb: Maximum memory in megabytes
        default_ttl: Default time to live in seconds
    
    Returns:
        LRUCache instance
    """
    return LRUCache(max_size, max_memory_mb, default_ttl)