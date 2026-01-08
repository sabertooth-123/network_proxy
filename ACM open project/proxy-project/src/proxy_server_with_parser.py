"""
Custom Network Proxy Server
A forward proxy server supporting HTTP/HTTPS with filtering and logging.


"""

import socket
import threading
import logging
import argparse
import json
from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlparse
import select


class ProxyConfig:
    """Configuration management for the proxy server"""
    
    def __init__(self, config_file='config/proxy_config.json'):
        # Default configuration
        self.host = '127.0.0.1'
        self.port = 8888
        self.max_threads = 50
        self.timeout = 10
        self.buffer_size = 8192
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.log_file = 'logs/proxy.log'
        
        # Load from file if exists
        if Path(config_file).exists():
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.host = config.get('host', self.host)
                self.port = config.get('port', self.port)
                self.max_threads = config.get('max_threads', self.max_threads)
                self.timeout = config.get('timeout', self.timeout)
                self.buffer_size = config.get('buffer_size', self.buffer_size)
                self.log_file = config.get('log_file', self.log_file)
                
                # Load blocked domains/IPs
                blocked_file = config.get('blocked_file', 'config/blocked_domains.txt')
                self.load_blocked_list(blocked_file)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def load_blocked_list(self, blocked_file):
        """Load blocked domains and IPs from file"""
        if not Path(blocked_file).exists():
            print(f"Warning: Blocked domains file not found: {blocked_file}")
            return
        
        try:
            with open(blocked_file, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        # Check if it's an IP address
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                            self.blocked_ips.add(line)
                        else:
                            self.blocked_domains.add(line)
            
            print(f"Loaded {len(self.blocked_domains)} blocked domains and {len(self.blocked_ips)} blocked IPs")
        except Exception as e:
            print(f"Error loading blocked list: {e}")
    
    def is_blocked(self, host):
        """Check if a host is blocked"""
        host = host.lower().strip()
        
        # Check if it's a blocked IP
        if host in self.blocked_ips:
            return True
        
        # Check if domain or any parent domain is blocked
        # This allows blocking *.example.com by adding example.com
        parts = host.split('.')
        for i in range(len(parts)):
            domain = '.'.join(parts[i:])
            if domain in self.blocked_domains:
                return True
        
        return False


class ProxyServer:
    """Main proxy server class"""
    
    def __init__(self, config):
        self.config = config
        self.server_socket = None
        self.running = False
        self.active_connections = 0
        self.total_requests = 0
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        # Create logs directory if it doesn't exist
        Path(self.config.log_file).parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the proxy server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(100)
            self.running = True
            
            self.logger.info("=" * 60)
            self.logger.info(f"Proxy server started on {self.config.host}:{self.config.port}")
            self.logger.info(f"Logging to: {self.config.log_file}")
            self.logger.info(f"Press Ctrl+C to stop")
            self.logger.info("=" * 60)
            
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self.active_connections += 1
                    self.total_requests += 1
                    
                    self.logger.info(f"[Connection #{self.total_requests}] New connection from {client_addr}")
                    
                    # Handle client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("=" * 60)
        self.logger.info(f"Proxy server stopped. Total requests: {self.total_requests}")
        self.logger.info("=" * 60)
    
    def handle_client(self, client_socket, client_addr):
        """Handle a client connection"""
        client_socket.settimeout(self.config.timeout)
        
        try:
            # Read client request
            request_data = self.recv_all(client_socket)
            if not request_data:
                self.logger.warning(f"Empty request from {client_addr}")
                return
            
            # Parse the request
            request_line, headers, body = self.parse_http_request(request_data)
            
            if not request_line:
                self.logger.warning(f"Malformed request from {client_addr}")
                self.send_error(client_socket, 400, "Bad Request")
                return
            
            # Extract method, URL, version
            parts = request_line.split(' ')
            if len(parts) != 3:
                self.send_error(client_socket, 400, "Bad Request")
                return
            
            method, url, version = parts
            
            # Log the request line
            self.logger.info(f"[{client_addr[0]}:{client_addr[1]}] {method} {url}")
            
            # Handle CONNECT method (for HTTPS)
            if method == 'CONNECT':
                self.handle_connect(client_socket, url, client_addr)
                return
            
            # Extract host and port
            host, port, path = self.parse_url(url, headers)
            
            if not host:
                self.logger.error(f"Cannot determine host from request: {url}")
                self.send_error(client_socket, 400, "Bad Request - No Host")
                return
            
            # Check if host is blocked
            if self.config.is_blocked(host):
                self.logger.warning(f"[BLOCKED] {host} requested by {client_addr}")
                self.send_error(client_socket, 403, "Forbidden - Domain Blocked")
                return
            
            # Forward the request
            self.forward_request(client_socket, method, host, port, path, 
                               headers, body, client_addr)
        
        except socket.timeout:
            self.logger.warning(f"Timeout handling client {client_addr}")
        except Exception as e:
            self.logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            client_socket.close()
            self.active_connections -= 1
    
    def recv_all(self, sock, max_size=65536):
        """Receive data until headers are complete"""
        data = b''
        
        while len(data) < max_size:
            try:
                chunk = sock.recv(self.config.buffer_size)
                if not chunk:
                    break
                data += chunk
                
                # Check if we have complete headers
                if b'\r\n\r\n' in data:
                    return data
            except socket.timeout:
                break
            except Exception as e:
                self.logger.error(f"Error receiving data: {e}")
                break
        
        return data
    
    def parse_http_request(self, request_data):
        """Parse HTTP request into components"""
        try:
            # Split headers and body
            if b'\r\n\r\n' in request_data:
                headers_part, body = request_data.split(b'\r\n\r\n', 1)
            else:
                headers_part = request_data
                body = b''
            
            headers_text = headers_part.decode('utf-8', errors='ignore')
            lines = headers_text.split('\r\n')
            
            if not lines:
                return None, {}, body
            
            request_line = lines[0]
            headers = {}
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return request_line, headers, body
        
        except Exception as e:
            self.logger.error(f"Error parsing request: {e}")
            return None, {}, b''
    
    def parse_url(self, url, headers):
        """Extract host, port, and path from URL"""
        try:
            # Handle absolute URLs (http://example.com/path)
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
            else:
                # Relative URL - get host from headers
                host_header = headers.get('host', '')
                if ':' in host_header:
                    host, port_str = host_header.split(':', 1)
                    port = int(port_str)
                else:
                    host = host_header
                    port = 80
                path = url if url else '/'
            
            return host, port, path
        
        except Exception as e:
            self.logger.error(f"Error parsing URL {url}: {e}")
            return None, None, None
    
    def forward_request(self, client_socket, method, host, port, path,
                       headers, body, client_addr):
        """Forward request to destination server"""
        try:
            # Connect to destination server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.config.timeout)
            server_socket.connect((host, port))
            
            # Reconstruct HTTP request
            request = f"{method} {path} HTTP/1.1\r\n"
            
            # Add/modify headers
            headers['host'] = host
            headers['connection'] = 'close'
            
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            
            request += "\r\n"
            
            # Send request
            server_socket.sendall(request.encode() + body)
            
            self.logger.info(f"[FORWARD] {method} {host}:{port}{path}")
            
            # Relay response back to client
            total_bytes = 0
            while True:
                data = server_socket.recv(self.config.buffer_size)
                if not data:
                    break
                client_socket.sendall(data)
                total_bytes += len(data)
            
            self.logger.info(f"[SUCCESS] Transferred {total_bytes} bytes from {host}")
            
            server_socket.close()
        
        except socket.timeout:
            self.logger.error(f"Timeout connecting to {host}:{port}")
            self.send_error(client_socket, 504, "Gateway Timeout")
        except Exception as e:
            self.logger.error(f"Error forwarding request to {host}:{port} - {e}")
            self.send_error(client_socket, 502, "Bad Gateway")
    
    def handle_connect(self, client_socket, url, client_addr):
        """Handle HTTPS CONNECT tunneling"""
        try:
            # Parse host:port
            if ':' not in url:
                self.send_error(client_socket, 400, "Bad Request - Invalid CONNECT")
                return
            
            host, port_str = url.split(':', 1)
            port = int(port_str)
            
            # Check if host is blocked
            if self.config.is_blocked(host):
                self.logger.warning(f"[BLOCKED] CONNECT to {host}:{port} from {client_addr}")
                self.send_error(client_socket, 403, "Forbidden - Domain Blocked")
                return
            
            # Connect to destination
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.config.timeout)
            server_socket.connect((host, port))
            
            # Send success response
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            
            self.logger.info(f"[CONNECT] Tunnel established to {host}:{port}")
            
            # Bidirectional relay
            self.relay_data(client_socket, server_socket)
            
            server_socket.close()
        
        except ValueError:
            self.send_error(client_socket, 400, "Bad Request - Invalid Port")
        except socket.timeout:
            self.logger.error(f"Timeout connecting to {url}")
            self.send_error(client_socket, 504, "Gateway Timeout")
        except Exception as e:
            self.logger.error(f"Error handling CONNECT to {url}: {e}")
            self.send_error(client_socket, 502, "Bad Gateway")
    
    def relay_data(self, client_socket, server_socket):
        """Relay data bidirectionally between two sockets"""
        client_socket.setblocking(False)
        server_socket.setblocking(False)
        
        sockets = [client_socket, server_socket]
        
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
                
                if exceptional:
                    break
                
                for sock in readable:
                    try:
                        data = sock.recv(self.config.buffer_size)
                        if not data:
                            return
                        
                        if sock is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    
                    except Exception:
                        return
        except Exception:
            pass
    
    def send_error(self, client_socket, code, message):
        """Send HTTP error response"""
        response = f"HTTP/1.1 {code} {message}\r\n"
        response += "Content-Type: text/html\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += f"<html><body><h1>{code} {message}</h1></body></html>\r\n"
        
        try:
            client_socket.sendall(response.encode())
        except:
            pass


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Custom Network Proxy Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default config
  %(prog)s --config config/custom.json  # Use custom config
  %(prog)s --host 0.0.0.0 --port 9999   # Override host/port
        """
    )
    
    parser.add_argument('--config', 
                       default='config/proxy_config.json',
                       help='Configuration file path (default: config/proxy_config.json)')
    parser.add_argument('--host', 
                       help='Proxy host address (overrides config)')
    parser.add_argument('--port', 
                       type=int,
                       help='Proxy port (overrides config)')
    
    args = parser.parse_args()
    
    # Load configuration
    config = ProxyConfig(args.config)
    
    # Override with command-line arguments
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    
    # Start proxy server
    proxy = ProxyServer(config)
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n\nShutting down proxy server...")


if __name__ == '__main__':
    main()