
"""
HTTP Request and Response Parser Module
Implements correct parsing and forwarding of HTTP requests and responses
"""

import re
from typing import Dict, Tuple, Optional, List
from urllib.parse import urlparse, urlunparse
import logging


class HTTPParseError(Exception):
    """Custom exception for HTTP parsing errors"""
    pass


class HTTPRequest:
    """
    Represents a parsed HTTP request
    Implements RFC 7230 compliant HTTP/1.1 request parsing
    """
    
    def __init__(self):
        self.method: str = ""
        self.uri: str = ""
        self.path: str = ""
        self.query: str = ""
        self.version: str = "HTTP/1.1"
        self.headers: Dict[str, str] = {}
        self.body: bytes = b''
        self.host: str = ""
        self.port: int = 80
        self.is_connect: bool = False
        
        # Additional metadata
        self.content_length: int = 0
        self.transfer_encoding: Optional[str] = None
        self.connection: str = "close"
        self.raw_request_line: str = ""
    
    def __str__(self):
        return f"HTTPRequest({self.method} {self.uri} {self.version})"
    
    def __repr__(self):
        return (f"HTTPRequest(method={self.method}, uri={self.uri}, "
                f"host={self.host}:{self.port}, headers={len(self.headers)})")
    
    def to_bytes(self) -> bytes:
        """
        Convert the request back to bytes for forwarding
        Returns the complete HTTP request as bytes
        """
        # Request line
        if self.is_connect:
            request_line = f"{self.method} {self.host}:{self.port} {self.version}\r\n"
        else:
            # For proxy, use absolute URI or path only for origin server
            request_line = f"{self.method} {self.path}"
            if self.query:
                request_line += f"?{self.query}"
            request_line += f" {self.version}\r\n"
        
        # Headers
        headers_bytes = request_line.encode('utf-8')
        for key, value in self.headers.items():
            headers_bytes += f"{key}: {value}\r\n".encode('utf-8')
        headers_bytes += b"\r\n"
        
        # Body
        return headers_bytes + self.body
    
    def get_absolute_uri(self) -> str:
        """Get the absolute URI for the request"""
        if self.uri.startswith('http://') or self.uri.startswith('https://'):
            return self.uri
        
        scheme = 'https' if self.port == 443 else 'http'
        if (scheme == 'http' and self.port == 80) or (scheme == 'https' and self.port == 443):
            return f"{scheme}://{self.host}{self.path}"
        else:
            return f"{scheme}://{self.host}:{self.port}{self.path}"


class HTTPResponse:
    """
    Represents a parsed HTTP response
    Implements RFC 7230 compliant HTTP/1.1 response parsing
    """
    
    def __init__(self):
        self.version: str = "HTTP/1.1"
        self.status_code: int = 0
        self.reason_phrase: str = ""
        self.headers: Dict[str, str] = {}
        self.body: bytes = b''
        
        # Additional metadata
        self.content_length: int = 0
        self.transfer_encoding: Optional[str] = None
        self.connection: str = "close"
        self.raw_status_line: str = ""
    
    def __str__(self):
        return f"HTTPResponse({self.version} {self.status_code} {self.reason_phrase})"
    
    def __repr__(self):
        return (f"HTTPResponse(status={self.status_code}, "
                f"reason={self.reason_phrase}, headers={len(self.headers)})")
    
    def to_bytes(self) -> bytes:
        """
        Convert the response back to bytes for forwarding
        Returns the complete HTTP response as bytes
        """
        # Status line
        status_line = f"{self.version} {self.status_code} {self.reason_phrase}\r\n"
        
        # Headers
        response_bytes = status_line.encode('utf-8')
        for key, value in self.headers.items():
            response_bytes += f"{key}: {value}\r\n".encode('utf-8')
        response_bytes += b"\r\n"
        
        # Body
        return response_bytes + self.body


class HTTPParser():
    """
    Advanced HTTP Request and Response Parser
    Implements correct parsing according to RFC 7230
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # HTTP methods from RFC 7231
        self.valid_methods = {
            'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT',
            'OPTIONS', 'TRACE', 'PATCH'
        }
        
        # Header field name regex (RFC 7230)
        self.header_field_regex = re.compile(r'^[!#$%&\'*+\-.0-9A-Z^_`a-z|~]+$')
    
    def parse_request(self, data: bytes) -> HTTPRequest:
        """
        Parse HTTP request from raw bytes
        
        Args:
            data: Raw HTTP request bytes
            
        Returns:
            HTTPRequest object
            
        Raises:
            HTTPParseError: If request is malformed
        """
        request = HTTPRequest()
        
        if not data:
            raise HTTPParseError("Empty request data")
        
        try:
            # Find header/body boundary
            if b'\r\n\r\n' in data:
                headers_data, body_data = data.split(b'\r\n\r\n', 1)
                request.body = body_data
            else:
                headers_data = data
                request.body = b''
            
            # Decode headers
            try:
                headers_text = headers_data.decode('utf-8')
            except UnicodeDecodeError:
                headers_text = headers_data.decode('latin-1')
            
            # Split into lines
            lines = headers_text.split('\r\n')
            
            if not lines:
                raise HTTPParseError("No request line found")
            
            # Parse request line
            request_line = lines[0]
            request.raw_request_line = request_line
            self._parse_request_line(request, request_line)
            
            # Parse headers
            self._parse_headers(request, lines[1:])
            
            # Extract host and port from headers if not in URI
            if not request.host:
                self._extract_host_port(request)
            
            # Parse body based on Content-Length or Transfer-Encoding
            self._parse_request_body(request)
            
            # Validate request
            self._validate_request(request)
            
            return request
        
        except Exception as e:
            self.logger.error(f"Error parsing request: {e}")
            raise HTTPParseError(f"Failed to parse HTTP request: {e}")
    
    def _parse_request_line(self, request: HTTPRequest, line: str):
        """Parse the HTTP request line"""
        parts = line.split(' ')
        
        if len(parts) != 3:
            raise HTTPParseError(f"Invalid request line: {line}")
        
        method, uri, version = parts
        
        # Validate method
        if method.upper() not in self.valid_methods:
            raise HTTPParseError(f"Invalid HTTP method: {method}")
        
        request.method = method.upper()
        request.uri = uri
        request.version = version
        
        # Check if CONNECT method
        if request.method == 'CONNECT':
            request.is_connect = True
            # CONNECT uses authority form: host:port
            if ':' in uri:
                request.host, port_str = uri.split(':', 1)
                try:
                    request.port = int(port_str)
                except ValueError:
                    raise HTTPParseError(f"Invalid port in CONNECT: {port_str}")
            else:
                raise HTTPParseError("CONNECT requires host:port format")
        else:
            # Parse URI (absolute or relative)
            self._parse_uri(request, uri)
    
    def _parse_uri(self, request: HTTPRequest, uri: str):
        """Parse the request URI"""
        if uri.startswith('http://') or uri.startswith('https://'):
            # Absolute URI form (proxy request)
            parsed = urlparse(uri)
            request.host = parsed.hostname or ""
            request.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            request.path = parsed.path or '/'
            request.query = parsed.query or ""
        else:
            # Origin form (path only)
            if '?' in uri:
                request.path, request.query = uri.split('?', 1)
            else:
                request.path = uri
                request.query = ""
    
    def _parse_headers(self, request: HTTPRequest, header_lines: List[str]):
        """Parse HTTP headers"""
        current_header = None
        
        for line in header_lines:
            if not line:
                continue
            
            # Handle multi-line headers (obs-fold from RFC 7230)
            if line.startswith((' ', '\t')):
                if current_header:
                    # Continue previous header
                    key, value = current_header
                    request.headers[key] = request.headers[key] + ' ' + line.strip()
                continue
            
            # Parse header field
            if ':' not in line:
                continue
            
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # Validate header field name
            if not self.header_field_regex.match(key):
                self.logger.warning(f"Invalid header field name: {key}")
                continue
            
            # Normalize header name (case-insensitive)
            key_lower = key.lower()
            
            # Store header
            request.headers[key_lower] = value
            current_header = (key_lower, value)
            
            # Extract important headers
            if key_lower == 'content-length':
                try:
                    request.content_length = int(value)
                except ValueError:
                    self.logger.warning(f"Invalid Content-Length: {value}")
            elif key_lower == 'transfer-encoding':
                request.transfer_encoding = value.lower()
            elif key_lower == 'connection':
                request.connection = value.lower()
    
    def _extract_host_port(self, request: HTTPRequest):
        """Extract host and port from Host header"""
        host_header = request.headers.get('host', '')
        
        if not host_header:
            if not request.is_connect:
                raise HTTPParseError("Missing Host header")
            return
        
        if ':' in host_header:
            request.host, port_str = host_header.rsplit(':', 1)
            try:
                request.port = int(port_str)
            except ValueError:
                request.host = host_header
                request.port = 80
        else:
            request.host = host_header
            request.port = 80
    
    def _parse_request_body(self, request: HTTPRequest):
        """Parse request body based on Content-Length or Transfer-Encoding"""
        # For requests with body (POST, PUT, PATCH)
        if request.method in ('POST', 'PUT', 'PATCH'):
            if request.content_length > 0:
                # Body length specified by Content-Length
                expected_length = request.content_length
                actual_length = len(request.body)
                
                if actual_length < expected_length:
                    self.logger.warning(
                        f"Body length mismatch: expected {expected_length}, "
                        f"got {actual_length}"
                    )
            elif request.transfer_encoding == 'chunked':
                # Chunked transfer encoding
                self.logger.info("Chunked transfer encoding detected")
                # Note: Full chunked decoding would go here
                # For proxy, we can forward chunks as-is
    
    def _validate_request(self, request: HTTPRequest):
        """Validate the parsed request"""
        # Check HTTP version
        if not request.version.startswith('HTTP/'):
            raise HTTPParseError(f"Invalid HTTP version: {request.version}")
        
        # Validate that we have a host
        if not request.host and not request.is_connect:
            raise HTTPParseError("Cannot determine target host")
        
        # Validate port
        if request.port < 1 or request.port > 65535:
            raise HTTPParseError(f"Invalid port: {request.port}")
    
    def parse_response(self, data: bytes) -> HTTPResponse:
        """
        Parse HTTP response from raw bytes
        
        Args:
            data: Raw HTTP response bytes
            
        Returns:
            HTTPResponse object
            
        Raises:
            HTTPParseError: If response is malformed
        """
        response = HTTPResponse()
        
        if not data:
            raise HTTPParseError("Empty response data")
        
        try:
            # Find header/body boundary
            if b'\r\n\r\n' in data:
                headers_data, body_data = data.split(b'\r\n\r\n', 1)
                response.body = body_data
            else:
                headers_data = data
                response.body = b''
            
            # Decode headers
            try:
                headers_text = headers_data.decode('utf-8')
            except UnicodeDecodeError:
                headers_text = headers_data.decode('latin-1')
            
            # Split into lines
            lines = headers_text.split('\r\n')
            
            if not lines:
                raise HTTPParseError("No status line found")
            
            # Parse status line
            status_line = lines[0]
            response.raw_status_line = status_line
            self._parse_status_line(response, status_line)
            
            # Parse headers
            self._parse_response_headers(response, lines[1:])
            
            # Parse body based on Content-Length or Transfer-Encoding
            self._parse_response_body(response)
            
            return response
        
        except Exception as e:
            self.logger.error(f"Error parsing response: {e}")
            raise HTTPParseError(f"Failed to parse HTTP response: {e}")
    
    def _parse_status_line(self, response: HTTPResponse, line: str):
        """Parse the HTTP status line"""
        parts = line.split(' ', 2)
        
        if len(parts) < 2:
            raise HTTPParseError(f"Invalid status line: {line}")
        
        response.version = parts[0]
        
        try:
            response.status_code = int(parts[1])
        except ValueError:
            raise HTTPParseError(f"Invalid status code: {parts[1]}")
        
        response.reason_phrase = parts[2] if len(parts) > 2 else ""
    
    def _parse_response_headers(self, response: HTTPResponse, header_lines: List[str]):
        """Parse HTTP response headers"""
        current_header = None
        
        for line in header_lines:
            if not line:
                continue
            
            # Handle multi-line headers
            if line.startswith((' ', '\t')):
                if current_header:
                    key, value = current_header
                    response.headers[key] = response.headers[key] + ' ' + line.strip()
                continue
            
            # Parse header field
            if ':' not in line:
                continue
            
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # Normalize header name
            key_lower = key.lower()
            
            # Store header
            response.headers[key_lower] = value
            current_header = (key_lower, value)
            
            # Extract important headers
            if key_lower == 'content-length':
                try:
                    response.content_length = int(value)
                except ValueError:
                    self.logger.warning(f"Invalid Content-Length: {value}")
            elif key_lower == 'transfer-encoding':
                response.transfer_encoding = value.lower()
            elif key_lower == 'connection':
                response.connection = value.lower()
    
    def _parse_response_body(self, response: HTTPResponse):
        """Parse response body based on headers"""
        if response.content_length > 0:
            expected_length = response.content_length
            actual_length = len(response.body)
            
            if actual_length < expected_length:
                self.logger.warning(
                    f"Response body length mismatch: expected {expected_length}, "
                    f"got {actual_length}"
                )
        elif response.transfer_encoding == 'chunked':
            self.logger.info("Chunked transfer encoding in response")


class HTTPRequestBuilder:
    """Helper class to build HTTP requests for forwarding"""
    
    @staticmethod
    def build_origin_request(request: HTTPRequest) -> bytes:
        """
        Build request for forwarding to origin server
        Converts proxy request to origin form
        """
        # Create new request with path only (not absolute URI)
        origin_request = HTTPRequest()
        origin_request.method = request.method
        origin_request.path = request.path
        origin_request.query = request.query
        origin_request.version = request.version
        origin_request.body = request.body
        
        # Copy and modify headers
        origin_request.headers = request.headers.copy()
        
        # Ensure Host header is present
        if 'host' not in origin_request.headers:
            if request.port in (80, 443):
                origin_request.headers['host'] = request.host
            else:
                origin_request.headers['host'] = f"{request.host}:{request.port}"
        
        # Remove proxy-specific headers
        headers_to_remove = ['proxy-connection', 'proxy-authorization']
        for header in headers_to_remove:
            origin_request.headers.pop(header, None)
        
        # Modify Connection header
        origin_request.headers['connection'] = 'close'
        
        return origin_request.to_bytes()
    
    @staticmethod
    def build_error_response(status_code: int, reason: str, message: str = "") -> bytes:
        """Build an error response"""
        response = HTTPResponse()
        response.status_code = status_code
        response.reason_phrase = reason
        response.version = "HTTP/1.1"
        
        # Build HTML body
        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <title>{status_code} {reason}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 50px; }}
        h1 {{ color: #d32f2f; }}
        p {{ color: #666; }}
    </style>
</head>
<body>
    <h1>{status_code} {reason}</h1>
    <p>{message if message else reason}</p>
    <hr>
    <p><small>Proxy Server</small></p>
</body>
</html>"""
        
        response.body = html_body.encode('utf-8')
        
        # Set headers
        response.headers['content-type'] = 'text/html; charset=utf-8'
        response.headers['content-length'] = str(len(response.body))
        response.headers['connection'] = 'close'
        
        return response.to_bytes()


# Convenience functions
def parse_http_request(data: bytes) -> HTTPRequest:
    """Parse HTTP request from bytes"""
    parser = HTTPParser()
    return parser.parse_request(data)


def parse_http_response(data: bytes) -> HTTPResponse:
    """Parse HTTP response from bytes"""
    parser = HTTPParser()
    return parser.parse_response(data)


def build_origin_request(request: HTTPRequest) -> bytes:
    """Build request for origin server"""
    return HTTPRequestBuilder.build_origin_request(request)


def build_error_response(status_code: int, reason: str, message: str = "") -> bytes:
    """Build HTTP error response"""
    return HTTPRequestBuilder.build_error_response(status_code, reason, message)