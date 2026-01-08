#!/usr/bin/env python3
"""
Cache Module Test Suite
Tests LRU caching functionality, TTL, eviction, and thread safety
"""

import sys
import time
import threading
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from cache import LRUCache, CacheEntry, create_cache


class CacheTester:
    """Test suite for cache module"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
    
    def print_header(self, title):
        """Print test section header"""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}\n")
    
    def assert_test(self, condition, test_name):
        """Assert a test condition"""
        if condition:
            print(f"✓ PASS: {test_name}")
            self.tests_passed += 1
            return True
        else:
            print(f"✗ FAIL: {test_name}")
            self.tests_failed += 1
            return False
    
    def test_cache_entry(self):
        """Test CacheEntry class"""
        self.print_header("Test 1: Cache Entry")
        
        entry = CacheEntry(
            key="test_key",
            response_data=b"Hello World",
            headers={'content-type': 'text/plain'},
            status_code=200,
            ttl=10
        )
        
        self.assert_test(
            entry.key == "test_key",
            "Entry key is correct"
        )
        self.assert_test(
            entry.size == 11,
            "Entry size calculated correctly (11 bytes)"
        )
        self.assert_test(
            not entry.is_expired(),
            "Fresh entry not expired"
        )
        self.assert_test(
            entry.hits == 0,
            "Initial hit count is 0"
        )
        
        # Touch entry
        entry.touch()
        self.assert_test(
            entry.hits == 1,
            "Hit count incremented after touch"
        )
    
    def test_cache_put_get(self):
        """Test basic cache put and get"""
        self.print_header("Test 2: Basic Put/Get")
        
        cache = LRUCache(max_size=100, max_memory_mb=10, default_ttl=300)
        
        # Put data
        success = cache.put(
            'GET', 'http://example.com',
            b'Test response data',
            {'content-type': 'text/html'},
            200
        )
        
        self.assert_test(
            success,
            "Data stored successfully"
        )
        
        # Get data
        data, headers, status = cache.get('GET', 'http://example.com')
        
        self.assert_test(
            data == b'Test response data',
            "Retrieved data matches stored data"
        )
        self.assert_test(
            headers['content-type'] == 'text/html',
            "Retrieved headers match"
        )
        self.assert_test(
            status == 200,
            "Retrieved status code matches"
        )
    
    def test_cache_miss(self):
        """Test cache miss"""
        self.print_header("Test 3: Cache Miss")
        
        cache = LRUCache(max_size=100)
        
        data, headers, status = cache.get('GET', 'http://nonexistent.com')
        
        self.assert_test(
            data is None,
            "Cache miss returns None for data"
        )
        self.assert_test(
            headers is None,
            "Cache miss returns None for headers"
        )
        self.assert_test(
            status is None,
            "Cache miss returns None for status"
        )
    
    def test_lru_eviction(self):
        """Test LRU eviction policy"""
        self.print_header("Test 4: LRU Eviction")
        
        cache = LRUCache(max_size=3, max_memory_mb=10)
        
        # Add 3 entries
        cache.put('GET', 'http://site1.com', b'data1', {}, 200)
        cache.put('GET', 'http://site2.com', b'data2', {}, 200)
        cache.put('GET', 'http://site3.com', b'data3', {}, 200)
        
        self.assert_test(
            len(cache.cache) == 3,
            "Cache has 3 entries"
        )
        
        # Access site1 to make it most recently used
        cache.get('GET', 'http://site1.com')
        
        # Add 4th entry, should evict site2 (LRU)
        cache.put('GET', 'http://site4.com', b'data4', {}, 200)
        
        self.assert_test(
            len(cache.cache) == 3,
            "Cache still has 3 entries after eviction"
        )
        
        # site2 should be evicted
        data, _, _ = cache.get('GET', 'http://site2.com')
        self.assert_test(
            data is None,
            "LRU entry (site2) was evicted"
        )
        
        # site1 should still be there
        data, _, _ = cache.get('GET', 'http://site1.com')
        self.assert_test(
            data is not None,
            "Recently accessed entry (site1) still in cache"
        )
    
    def test_ttl_expiration(self):
        """Test TTL expiration"""
        self.print_header("Test 5: TTL Expiration")
        
        cache = LRUCache(max_size=100, default_ttl=2)  # 2 second TTL
        
        # Store with short TTL
        cache.put('GET', 'http://example.com', b'data', 
                 {'cache-control': 'max-age=2'}, 200)
        
        # Should be available immediately
        data, _, _ = cache.get('GET', 'http://example.com')
        self.assert_test(
            data is not None,
            "Fresh cache entry retrieved"
        )
        
        # Wait for expiration
        print("  Waiting 3 seconds for TTL expiration...")
        time.sleep(3)
        
        # Should be expired now
        data, _, _ = cache.get('GET', 'http://example.com')
        self.assert_test(
            data is None,
            "Expired entry not returned"
        )
    
    def test_cache_control_headers(self):
        """Test Cache-Control header respect"""
        self.print_header("Test 6: Cache-Control Headers")
        
        cache = LRUCache(max_size=100)
        
        # Test no-store
        success = cache.put('GET', 'http://example.com', b'data',
                          {'cache-control': 'no-store'}, 200)
        self.assert_test(
            not success,
            "no-store prevents caching"
        )
        
        # Test private
        success = cache.put('GET', 'http://example2.com', b'data',
                          {'cache-control': 'private'}, 200)
        self.assert_test(
            not success,
            "private prevents caching"
        )
        
        # Test cacheable
        success = cache.put('GET', 'http://example3.com', b'data',
                          {'cache-control': 'public, max-age=3600'}, 200)
        self.assert_test(
            success,
            "public allows caching"
        )
    
    def test_method_cacheability(self):
        """Test HTTP method cacheability"""
        self.print_header("Test 7: Method Cacheability")
        
        cache = LRUCache(max_size=100)
        
        # GET should be cacheable
        success = cache.put('GET', 'http://example.com', b'data', {}, 200)
        self.assert_test(success, "GET requests cacheable")
        
        # HEAD should be cacheable
        success = cache.put('HEAD', 'http://example.com', b'', {}, 200)
        self.assert_test(success, "HEAD requests cacheable")
        
        # POST should not be cacheable
        success = cache.put('POST', 'http://example.com', b'data', {}, 200)
        self.assert_test(not success, "POST requests not cacheable")
        
        # PUT should not be cacheable
        success = cache.put('PUT', 'http://example.com', b'data', {}, 200)
        self.assert_test(not success, "PUT requests not cacheable")
    
    def test_memory_limit(self):
        """Test memory limit enforcement"""
        self.print_header("Test 8: Memory Limit")
        
        # Create cache with 1MB limit
        cache = LRUCache(max_size=1000, max_memory_mb=1)
        
        # Try to add 500KB entries
        large_data = b'x' * (500 * 1024)  # 500KB
        
        cache.put('GET', 'http://site1.com', large_data, {}, 200)
        cache.put('GET', 'http://site2.com', large_data, {}, 200)
        
        # Second entry should trigger eviction of first
        stats = cache.get_stats()
        
        self.assert_test(
            stats['evictions'] > 0,
            "Memory limit triggered eviction"
        )
        self.assert_test(
            stats['memory_usage_mb'] <= 1.1,  # Allow small overhead
            "Memory usage within limit"
        )
    
    def test_statistics(self):
        """Test statistics tracking"""
        self.print_header("Test 9: Statistics")
        
        cache = LRUCache(max_size=100)
        
        # Generate some activity
        cache.put('GET', 'http://site1.com', b'data1', {}, 200)
        cache.put('GET', 'http://site2.com', b'data2', {}, 200)
        
        # Hit
        cache.get('GET', 'http://site1.com')
        # Miss
        cache.get('GET', 'http://nonexistent.com')
        
        stats = cache.get_stats()
        
        self.assert_test(
            stats['hits'] == 1,
            "Hit count correct (1)"
        )
        self.assert_test(
            stats['misses'] == 1,
            "Miss count correct (1)"
        )
        self.assert_test(
            stats['entries'] == 2,
            "Entry count correct (2)"
        )
        self.assert_test(
            stats['hit_rate'] == 50.0,
            "Hit rate calculated correctly (50%)"
        )
        
        print(f"\n  Cache Statistics:")
        print(f"    Hits: {stats['hits']}")
        print(f"    Misses: {stats['misses']}")
        print(f"    Hit Rate: {stats['hit_rate']:.1f}%")
        print(f"    Entries: {stats['entries']}")
        print(f"    Memory Usage: {stats['memory_usage_mb']:.2f} MB")
    
    def test_thread_safety(self):
        """Test thread safety"""
        self.print_header("Test 10: Thread Safety")
        
        cache = LRUCache(max_size=1000)
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(100):
                    url = f'http://site{i % 50}.com'
                    # Put
                    cache.put('GET', url, f'data{i}'.encode(), {}, 200)
                    # Get
                    cache.get('GET', url)
            except Exception as e:
                errors.append(e)
        
        # Create 10 threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        self.assert_test(
            len(errors) == 0,
            "No errors in concurrent access"
        )
        
        stats = cache.get_stats()
        self.assert_test(
            stats['entries'] > 0,
            f"Cache has entries after concurrent operations ({stats['entries']})"
        )
    
    def test_clear_and_remove(self):
        """Test clear and remove operations"""
        self.print_header("Test 11: Clear and Remove")
        
        cache = LRUCache(max_size=100)
        
        # Add entries
        cache.put('GET', 'http://site1.com', b'data1', {}, 200)
        cache.put('GET', 'http://site2.com', b'data2', {}, 200)
        cache.put('GET', 'http://site3.com', b'data3', {}, 200)
        
        # Remove one
        cache.remove('GET', 'http://site2.com')
        
        data, _, _ = cache.get('GET', 'http://site2.com')
        self.assert_test(
            data is None,
            "Removed entry not found"
        )
        
        # Others should still exist
        data, _, _ = cache.get('GET', 'http://site1.com')
        self.assert_test(
            data is not None,
            "Other entries still exist after remove"
        )
        
        # Clear all
        cache.clear()
        
        stats = cache.get_stats()
        self.assert_test(
            stats['entries'] == 0,
            "Cache empty after clear"
        )
    
    def demo_cache_usage(self):
        """Demonstrate cache usage"""
        self.print_header("Demo: Cache Usage Example")
        
        print("Creating cache with 1000 entries, 100MB limit...")
        cache = create_cache(max_size=1000, max_memory_mb=100, default_ttl=300)
        
        print("\nStoring responses...")
        for i in range(5):
            url = f'http://example{i}.com'
            data = f'Response data for site {i}'.encode()
            cache.put('GET', url, data, 
                     {'content-type': 'text/html', 'cache-control': 'max-age=3600'},
                     200)
            print(f"  Cached: {url}")
        
        print("\nRetrieving from cache...")
        data, headers, status = cache.get('GET', 'http://example0.com')
        if data:
            print(f"  ✓ Cache HIT: {data.decode()}")
        
        print("\nCache Statistics:")
        stats = cache.get_stats()
        print(f"  Entries: {stats['entries']}")
        print(f"  Hits: {stats['hits']}")
        print(f"  Misses: {stats['misses']}")
        print(f"  Hit Rate: {stats['hit_rate']:.1f}%")
        print(f"  Memory: {stats['memory_usage_mb']:.2f} MB / {stats['memory_limit_mb']:.0f} MB")
        
        cache.shutdown()
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("  CACHE MODULE TEST SUITE")
        print("="*70)
        
        self.test_cache_entry()
        self.test_cache_put_get()
        self.test_cache_miss()
        self.test_lru_eviction()
        self.test_ttl_expiration()
        self.test_cache_control_headers()
        self.test_method_cacheability()
        self.test_memory_limit()
        self.test_statistics()
        self.test_thread_safety()
        self.test_clear_and_remove()
        self.demo_cache_usage()
        
        # Summary
        print("\n" + "="*70)
        print("  TEST SUMMARY")
        print("="*70)
        print(f"  Total Tests: {self.tests_passed + self.tests_failed}")
        print(f"  Passed: {self.tests_passed}")
        print(f"  Failed: {self.tests_failed}")
        
        if self.tests_failed == 0:
            print("\n  ✓✓✓ ALL TESTS PASSED! ✓✓✓")
        else:
            print(f"\n  ✗ {self.tests_failed} TEST(S) FAILED")
        
        print("="*70 + "\n")
        
        return self.tests_failed == 0


def main():
    """Main test runner"""
    tester = CacheTester()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()