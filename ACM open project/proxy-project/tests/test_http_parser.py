
"""
HTTP Parser Test Suite
Tests the HTTP request and response parsing implementation
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

# Now import from http_parser
from http_parser import (
    HTTPParser, HTTPRequest, HTTPResponse,
    HTTPRequestBuilder, HTTPParseError,
    parse_http_request, build_origin_request, build_error_response
)


class HTTPParserTester:
    """Test suite for HTTP parser"""
    
    def __init__(self):
        self.parser = HTTPParser()
        self.tests_passed = 0
        self.tests_failed = 0
    
    def assert_equal(self, actual, expected, test_name):
        """Assert two values are equal"""
        if actual == expected:
            print(f"✓ PASS: {test_name}")
            self.tests_passed += 1
            return True
        else:
            print(f"✗ FAIL: {test_name}")
            print(f"  Expected: {expected}")
            print(f"  Got: {actual}")
            self.tests_failed += 1
            return False
    
    def test_simple_get_request(self):
        """Test parsing a simple GET request"""
        print("\n[Test 1] Simple GET Request")
        
        request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            
            self.assert_equal(request.method, "GET", "Method is GET")
            self.assert_equal(request.path, "/", "Path is /")
            self.assert_equal(request.version, "HTTP/1.1", "Version is HTTP/1.1")
            self.assert_equal(request.host, "example.com", "Host is example.com")
            self.assert_equal(request.port, 80, "Port is 80")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_absolute_uri_request(self):
        """Test parsing request with absolute URI"""
        print("\n[Test 2] Absolute URI Request")
        
        request_data = b"GET http://example.com/path?query=value HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            
            self.assert_equal(request.method, "GET", "Method is GET")
            self.assert_equal(request.host, "example.com", "Host is example.com")
            self.assert_equal(request.path, "/path", "Path is /path")
            self.assert_equal(request.query, "query=value", "Query is correct")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_post_request_with_body(self):
        """Test parsing POST request with body"""
        print("\n[Test 3] POST Request with Body")
        
        body = b"key1=value1&key2=value2"
        request_data = (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"\r\n" +
            body
        )
        
        try:
            request = self.parser.parse_request(request_data)
            
            self.assert_equal(request.method, "POST", "Method is POST")
            self.assert_equal(request.path, "/submit", "Path is /submit")
            self.assert_equal(request.content_length, len(body), "Content-Length is correct")
            self.assert_equal(request.body, body, "Body is correct")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_connect_request(self):
        """Test parsing CONNECT request"""
        print("\n[Test 4] CONNECT Request")
        
        request_data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            
            self.assert_equal(request.method, "CONNECT", "Method is CONNECT")
            self.assert_equal(request.host, "example.com", "Host is example.com")
            self.assert_equal(request.port, 443, "Port is 443")
            self.assert_equal(request.is_connect, True, "is_connect is True")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_multiple_headers(self):
        """Test parsing request with multiple headers"""
        print("\n[Test 5] Multiple Headers")
        
        request_data = (
            b"GET /page HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: TestBot/1.0\r\n"
            b"Accept: text/html\r\n"
            b"Accept-Language: en-US\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        
        try:
            request = self.parser.parse_request(request_data)
            
            self.assert_equal(request.method, "GET", "Method is GET")
            self.assert_equal('user-agent' in request.headers, True, "User-Agent header exists")
            self.assert_equal(request.headers['user-agent'], "TestBot/1.0", "User-Agent is correct")
            self.assert_equal('accept' in request.headers, True, "Accept header exists")
            self.assert_equal(len(request.headers) >= 4, True, "At least 4 headers parsed")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_malformed_request(self):
        """Test error handling for malformed request"""
        print("\n[Test 6] Malformed Request")
        
        request_data = b"INVALID REQUEST\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            print(f"✗ FAIL: Should have raised HTTPParseError")
            self.tests_failed += 1
        
        except HTTPParseError as e:
            print(f"✓ PASS: Correctly raised HTTPParseError: {e}")
            self.tests_passed += 1
        
        except Exception as e:
            print(f"✗ FAIL: Wrong exception type - {e}")
            self.tests_failed += 1
    
    def test_build_origin_request(self):
        """Test building origin-format request"""
        print("\n[Test 7] Build Origin Request")
        
        # Parse proxy-style request
        request_data = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            origin_bytes = build_origin_request(request)
            
            # Should convert to origin form (path only)
            origin_text = origin_bytes.decode('utf-8')
            
            self.assert_equal("GET /path HTTP/1.1" in origin_text, True, "Request line converted to origin form")
            self.assert_equal("Host: example.com" in origin_text, True, "Host header preserved")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_build_error_response(self):
        """Test building error response"""
        print("\n[Test 8] Build Error Response")
        
        try:
            error_bytes = build_error_response(404, "Not Found", "The page was not found")
            error_text = error_bytes.decode('utf-8')
            
            self.assert_equal("HTTP/1.1 404 Not Found" in error_text, True, "Status line is correct")
            self.assert_equal("Content-Type: text/html" in error_text, True, "Content-Type header present")
            self.assert_equal("404 Not Found" in error_text, True, "HTML body contains error")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_request_to_bytes(self):
        """Test converting request back to bytes"""
        print("\n[Test 9] Request to Bytes")
        
        request_data = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n"
        
        try:
            request = self.parser.parse_request(request_data)
            reconstructed = request.to_bytes()
            
            # Parse reconstructed request
            request2 = self.parser.parse_request(reconstructed)
            
            self.assert_equal(request.method, request2.method, "Method preserved")
            self.assert_equal(request.path, request2.path, "Path preserved")
            self.assert_equal(request.host, request2.host, "Host preserved")
        
        except Exception as e:
            print(f"✗ FAIL: Exception - {e}")
            self.tests_failed += 1
    
    def test_various_http_methods(self):
        """Test parsing various HTTP methods"""
        print("\n[Test 10] Various HTTP Methods")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        
        for method in methods:
            request_data = f"{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
            
            try:
                request = self.parser.parse_request(request_data)
                self.assert_equal(request.method, method, f"Method {method} parsed correctly")
            except Exception as e:
                print(f"✗ FAIL: {method} - {e}")
                self.tests_failed += 1
    
    def run_all_tests(self):
        """Run all tests"""
        print("="*70)
        print("HTTP Parser Test Suite")
        print("="*70)
        
        self.test_simple_get_request()
        self.test_absolute_uri_request()
        self.test_post_request_with_body()
        self.test_connect_request()
        self.test_multiple_headers()
        self.test_malformed_request()
        self.test_build_origin_request()
        self.test_build_error_response()
        self.test_request_to_bytes()
        self.test_various_http_methods()
        
        print("\n" + "="*70)
        print("Test Summary:")
        print(f"  Total Tests: {self.tests_passed + self.tests_failed}")
        print(f"  Passed: {self.tests_passed}")
        print(f"  Failed: {self.tests_failed}")
        
        if self.tests_failed == 0:
            print("\n✓ ALL TESTS PASSED!")
        else:
            print(f"\n✗ {self.tests_failed} TEST(S) FAILED")
        
        print("="*70)
        
        return self.tests_failed == 0


def main():
    """Main test runner"""
    tester = HTTPParserTester()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()