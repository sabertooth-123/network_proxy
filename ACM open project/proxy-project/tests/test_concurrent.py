#!/usr/bin/env python3
"""
Concurrent Proxy Server Test Suite
Tests the proxy server's ability to handle multiple concurrent clients
"""

import socket
import threading
import time
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


class ConcurrentProxyTester:
    """Test suite for concurrent proxy operations"""
    
    def __init__(self, proxy_host='localhost', proxy_port=8888):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_url = f'http://{proxy_host}:{proxy_port}'
        self.results = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'total_time': 0
        }
        self.lock = threading.Lock()
    
    def test_connection(self):
        """Test if proxy is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def make_request(self, url, request_id):
        """Make a single request through the proxy"""
        start_time = time.time()
        try:
            proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            
            response = requests.get(url, proxies=proxies, timeout=10)
            elapsed = time.time() - start_time
            
            with self.lock:
                self.results['successful'] += 1
                self.results['total_time'] += elapsed
            
            return {
                'id': request_id,
                'success': True,
                'status': response.status_code,
                'time': elapsed,
                'size': len(response.content)
            }
        
        except Exception as e:
            elapsed = time.time() - start_time
            
            with self.lock:
                self.results['failed'] += 1
                self.results['total_time'] += elapsed
            
            return {
                'id': request_id,
                'success': False,
                'error': str(e),
                'time': elapsed
            }
    
    def test_concurrent_requests(self, num_requests=10, url='http://www.google.com/'):
        """Test multiple concurrent requests"""
        print(f"\n{'='*70}")
        print(f"Testing {num_requests} concurrent requests to {url}")
        print(f"{'='*70}")
        
        self.results = {
            'total_requests': num_requests,
            'successful': 0,
            'failed': 0,
            'total_time': 0
        }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [
                executor.submit(self.make_request, url, i)
                for i in range(num_requests)
            ]
            
            for future in as_completed(futures):
                result = future.result()
                if result['success']:
                    print(f"✓ Request {result['id']:3d}: SUCCESS - "
                          f"Status {result['status']} - "
                          f"Time {result['time']:.2f}s - "
                          f"Size {result['size']:,} bytes")
                else:
                    print(f"✗ Request {result['id']:3d}: FAILED - {result['error']}")
        
        total_elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print("Test Results:")
        print(f"  Total Requests: {self.results['total_requests']}")
        print(f"  Successful: {self.results['successful']}")
        print(f"  Failed: {self.results['failed']}")
        print(f"  Total Time: {total_elapsed:.2f} seconds")
        print(f"  Avg Response Time: {self.results['total_time']/num_requests:.2f} seconds")
        print(f"  Requests/Second: {num_requests/total_elapsed:.2f}")
        print(f"{'='*70}\n")
        
        return self.results
    
    def test_sustained_load(self, duration=30, requests_per_second=5):
        """Test sustained concurrent load"""
        print(f"\n{'='*70}")
        print(f"Sustained Load Test - {duration} seconds @ {requests_per_second} req/s")
        print(f"{'='*70}")
        
        self.results = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'total_time': 0
        }
        
        end_time = time.time() + duration
        request_id = 0
        
        with ThreadPoolExecutor(max_workers=requests_per_second * 2) as executor:
            while time.time() < end_time:
                batch_start = time.time()
                
                # Submit batch of requests
                futures = []
                for _ in range(requests_per_second):
                    future = executor.submit(
                        self.make_request,
                        'http://www.google.com/',
                        request_id
                    )
                    futures.append(future)
                    request_id += 1
                    self.results['total_requests'] += 1
                
                # Wait for batch to complete or move to next second
                for future in as_completed(futures, timeout=1):
                    try:
                        result = future.result(timeout=0.1)
                        status = "✓" if result['success'] else "✗"
                        print(f"{status} Request {result['id']}", end="\r")
                    except:
                        pass
                
                # Sleep remaining time in this second
                elapsed = time.time() - batch_start
                if elapsed < 1.0:
                    time.sleep(1.0 - elapsed)
        
        print(f"\n{'='*70}")
        print("Sustained Load Test Results:")
        print(f"  Total Requests: {self.results['total_requests']}")
        print(f"  Successful: {self.results['successful']}")
        print(f"  Failed: {self.results['failed']}")
        print(f"  Success Rate: {self.results['successful']/self.results['total_requests']*100:.1f}%")
        print(f"{'='*70}\n")
        
        return self.results
    
    def test_different_endpoints(self, num_requests=20):
        """Test concurrent requests to different endpoints"""
        print(f"\n{'='*70}")
        print(f"Testing {num_requests} concurrent requests to various endpoints")
        print(f"{'='*70}")
        
        endpoints = [
            'http://httpbin.org/get',
            'http://httpbin.org/headers',
            'http://httpbin.org/user-agent',
            'http://httpbin.org/ip',
            'http://example.com'
        ]
        
        self.results = {
            'total_requests': num_requests,
            'successful': 0,
            'failed': 0,
            'total_time': 0
        }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [
                executor.submit(
                    self.make_request,
                    endpoints[i % len(endpoints)],
                    i
                )
                for i in range(num_requests)
            ]
            
            for future in as_completed(futures):
                result = future.result()
                status = "✓" if result['success'] else "✗"
                print(f"{status} Request {result['id']:3d} completed in {result['time']:.2f}s")
        
        total_elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print("Multi-Endpoint Test Results:")
        print(f"  Total Requests: {self.results['total_requests']}")
        print(f"  Successful: {self.results['successful']}")
        print(f"  Failed: {self.results['failed']}")
        print(f"  Total Time: {total_elapsed:.2f} seconds")
        print(f"{'='*70}\n")
        
        return self.results


def main():
    """Main test runner"""
    print("="*70)
    print("Concurrent Proxy Server Test Suite")
    print("="*70)
    
    tester = ConcurrentProxyTester()
    
    # Test 1: Check proxy is running
    print("\n[Test 0] Checking if proxy server is running...")
    if not tester.test_connection():
        print("✗ FAILED: Proxy server is not reachable at localhost:8888")
        print("Please start the proxy server first:")
        print("  python src/proxy_server.py")
        sys.exit(1)
    print("✓ PASSED: Proxy server is running\n")
    
    # Test 1: Small concurrent load (10 requests)
    print("\n[Test 1] Small Concurrent Load")
    tester.test_concurrent_requests(num_requests=10)
    
    # Test 2: Medium concurrent load (50 requests)
    print("\n[Test 2] Medium Concurrent Load")
    tester.test_concurrent_requests(num_requests=50)
    
    # Test 3: Different endpoints
    print("\n[Test 3] Various Endpoints")
    tester.test_different_endpoints(num_requests=20)
    '''
    # Test 4: Sustained load (optional - comment out if too long)
    print("\n[Test 4] Sustained Load (15 seconds)")
    response = input("Run sustained load test? (y/n): ")
    if response.lower() == 'y':
        tester.test_sustained_load(duration=15, requests_per_second=5)
    
    print("\n" + "="*70)
    print("All tests completed!")
    print("Check logs/proxy.log for detailed proxy server logs")
    print("="*70)
'''

if __name__ == '__main__':
    main()