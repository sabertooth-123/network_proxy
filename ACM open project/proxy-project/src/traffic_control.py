
"""
Traffic Control Module
Implements configurable traffic control mechanisms including:
- Advanced logging with multiple levels and formats
- Domain/IP filtering with rules
- Bandwidth monitoring
- Rate limiting
- Access control lists (ACLs)
"""

import re
import json
import time
import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import threading


class FilterRule:
    """Represents a single filtering rule"""
    
    def __init__(self, rule_type: str, pattern: str, action: str, priority: int = 0):
        """
        Initialize a filter rule
        
        Args:
            rule_type: 'domain', 'ip', 'path', 'method', 'user-agent'
            pattern: Pattern to match (supports wildcards)
            action: 'block', 'allow', 'log', 'rate-limit'
            priority: Higher priority rules are checked first
        """
        self.rule_type = rule_type
        self.pattern = pattern
        self.action = action
        self.priority = priority
        self.compiled_regex = None
        
        # Convert wildcard pattern to regex
        if '*' in pattern or '?' in pattern:
            regex_pattern = pattern.replace('.', r'\.')
            regex_pattern = regex_pattern.replace('*', '.*')
            regex_pattern = regex_pattern.replace('?', '.')
            regex_pattern = f'^{regex_pattern}$'
            self.compiled_regex = re.compile(regex_pattern, re.IGNORECASE)
    
    def matches(self, value: str) -> bool:
        """Check if value matches this rule"""
        if self.compiled_regex:
            return bool(self.compiled_regex.match(value))
        return value.lower() == self.pattern.lower()
    
    def __repr__(self):
        return f"FilterRule({self.rule_type}={self.pattern}, action={self.action})"


class AccessLog:
    """Represents a single access log entry"""
    
    def __init__(self, timestamp: datetime, client_ip: str, client_port: int,
                 method: str, host: str, path: str, status: int,
                 bytes_sent: int, bytes_received: int, duration: float,
                 action: str = "allow", user_agent: str = ""):
        self.timestamp = timestamp
        self.client_ip = client_ip
        self.client_port = client_port
        self.method = method
        self.host = host
        self.path = path
        self.status = status
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received
        self.duration = duration
        self.action = action
        self.user_agent = user_agent
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'method': self.method,
            'host': self.host,
            'path': self.path,
            'status': self.status,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'duration_ms': round(self.duration * 1000, 2),
            'action': self.action,
            'user_agent': self.user_agent
        }
    
    def to_clf_format(self) -> str:
        """Convert to Common Log Format (CLF)"""
        # Format: client - - [timestamp] "method path HTTP/1.1" status bytes
        timestamp_str = self.timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')
        return (f'{self.client_ip} - - [{timestamp_str}] '
                f'"{self.method} {self.host}{self.path} HTTP/1.1" '
                f'{self.status} {self.bytes_sent}')
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())


class RateLimiter:
    """Rate limiter for IP addresses"""
    
    def __init__(self, requests_per_minute: int = 60, window_seconds: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self.request_times: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """
        Check if request from IP is allowed
        
        Returns:
            Tuple of (allowed, remaining_quota)
        """
        with self.lock:
            current_time = time.time()
            cutoff_time = current_time - self.window_seconds
            
            # Get request times for this IP
            times = self.request_times[client_ip]
            
            # Remove old requests outside the window
            times = [t for t in times if t > cutoff_time]
            self.request_times[client_ip] = times
            
            # Check if under limit
            if len(times) < self.requests_per_minute:
                times.append(current_time)
                remaining = self.requests_per_minute - len(times)
                return True, remaining
            else:
                return False, 0
    
    def reset(self, client_ip: str):
        """Reset rate limit for an IP"""
        with self.lock:
            if client_ip in self.request_times:
                del self.request_times[client_ip]


class BandwidthMonitor:
    """Monitor bandwidth usage per IP"""
    
    def __init__(self):
        self.usage: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {'bytes_sent': 0, 'bytes_received': 0, 'requests': 0}
        )
        self.lock = threading.Lock()
    
    def record(self, client_ip: str, bytes_sent: int, bytes_received: int):
        """Record bandwidth usage"""
        with self.lock:
            self.usage[client_ip]['bytes_sent'] += bytes_sent
            self.usage[client_ip]['bytes_received'] += bytes_received
            self.usage[client_ip]['requests'] += 1
    
    def get_usage(self, client_ip: str) -> Dict[str, int]:
        """Get usage for an IP"""
        with self.lock:
            return self.usage[client_ip].copy()
    
    def get_all_usage(self) -> Dict[str, Dict[str, int]]:
        """Get all usage statistics"""
        with self.lock:
            return {ip: stats.copy() for ip, stats in self.usage.items()}
    
    def reset(self, client_ip: Optional[str] = None):
        """Reset statistics"""
        with self.lock:
            if client_ip:
                if client_ip in self.usage:
                    del self.usage[client_ip]
            else:
                self.usage.clear()


class TrafficLogger:
    """Advanced traffic logger with multiple formats"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Main access log
        self.access_log_file = self.log_dir / "access.log"
        self.access_logger = self._setup_logger(
            'access',
            self.access_log_file,
            logging.INFO
        )
        
        # Blocked requests log
        self.blocked_log_file = self.log_dir / "blocked.log"
        self.blocked_logger = self._setup_logger(
            'blocked',
            self.blocked_log_file,
            logging.WARNING
        )
        
        # JSON structured log
        self.json_log_file = self.log_dir / "access.json"
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'rate_limited': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0
        }
        self.stats_lock = threading.Lock()
    
    def _setup_logger(self, name: str, log_file: Path, level: int) -> logging.Logger:
        """Setup a logger instance"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers.clear()
        
        handler = logging.FileHandler(log_file)
        handler.setLevel(level)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def log_access(self, access_log: AccessLog):
        """Log an access entry"""
        # Log to access log (CLF format)
        self.access_logger.info(access_log.to_clf_format())
        
        # Log to JSON file
        with open(self.json_log_file, 'a') as f:
            f.write(access_log.to_json() + '\n')
        
        # Update statistics
        with self.stats_lock:
            self.stats['total_requests'] += 1
            if access_log.action == 'block':
                self.stats['blocked_requests'] += 1
            else:
                self.stats['allowed_requests'] += 1
            self.stats['total_bytes_sent'] += access_log.bytes_sent
            self.stats['total_bytes_received'] += access_log.bytes_received
    
    def log_blocked(self, client_ip: str, host: str, reason: str):
        """Log a blocked request"""
        self.blocked_logger.warning(
            f"BLOCKED: {client_ip} -> {host} - Reason: {reason}"
        )
    
    def log_rate_limited(self, client_ip: str, host: str):
        """Log a rate-limited request"""
        self.blocked_logger.warning(
            f"RATE_LIMITED: {client_ip} -> {host}"
        )
        with self.stats_lock:
            self.stats['rate_limited'] += 1
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self.stats_lock:
            return self.stats.copy()


class TrafficController():
    """
    Main traffic control system
    Manages filtering, logging, rate limiting, and bandwidth monitoring
    """
    
    def __init__(self, config_file: str = "config/traffic_control.json"):
        self.config_file = Path(config_file)
        self.rules: List[FilterRule] = []
        self.rate_limiter = RateLimiter()
        self.bandwidth_monitor = BandwidthMonitor()
        self.logger = TrafficLogger()
        
        # Default settings
        self.enable_rate_limiting = True
        self.enable_bandwidth_monitoring = True
        self.enable_logging = True
        self.default_action = "allow"  # allow or block
        
        # Load configuration
        if self.config_file.exists():
            self.load_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            "rate_limiting": {
                "enabled": True,
                "requests_per_minute": 60,
                "window_seconds": 60
            },
            "bandwidth_monitoring": {
                "enabled": True
            },
            "logging": {
                "enabled": True,
                "log_directory": "logs"
            },
            "default_action": "allow",
            "rules": [
                {
                    "rule_type": "domain",
                    "pattern": "*.malware.com",
                    "action": "block",
                    "priority": 10
                },
                {
                    "rule_type": "domain",
                    "pattern": "*.ads.example.com",
                    "action": "block",
                    "priority": 5
                },
                {
                    "rule_type": "ip",
                    "pattern": "192.168.1.100",
                    "action": "block",
                    "priority": 8
                },
                {
                    "rule_type": "method",
                    "pattern": "TRACE",
                    "action": "block",
                    "priority": 7
                }
            ]
        }
        
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        print(f"Created default traffic control config: {self.config_file}")
    
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            # Load rate limiting settings
            rate_config = config.get('rate_limiting', {})
            self.enable_rate_limiting = rate_config.get('enabled', True)
            if self.enable_rate_limiting:
                self.rate_limiter = RateLimiter(
                    requests_per_minute=rate_config.get('requests_per_minute', 60),
                    window_seconds=rate_config.get('window_seconds', 60)
                )
            
            # Load bandwidth monitoring settings
            bw_config = config.get('bandwidth_monitoring', {})
            self.enable_bandwidth_monitoring = bw_config.get('enabled', True)
            
            # Load logging settings
            log_config = config.get('logging', {})
            self.enable_logging = log_config.get('enabled', True)
            if self.enable_logging:
                log_dir = log_config.get('log_directory', 'logs')
                self.logger = TrafficLogger(log_dir)
            
            # Load default action
            self.default_action = config.get('default_action', 'allow')
            
            # Load rules
            self.rules.clear()
            for rule_data in config.get('rules', []):
                rule = FilterRule(
                    rule_type=rule_data['rule_type'],
                    pattern=rule_data['pattern'],
                    action=rule_data['action'],
                    priority=rule_data.get('priority', 0)
                )
                self.rules.append(rule)
            
            # Sort rules by priority (highest first)
            self.rules.sort(key=lambda r: r.priority, reverse=True)
            
            print(f"Loaded {len(self.rules)} traffic control rules")
        
        except Exception as e:
            print(f"Error loading traffic control config: {e}")
            self._create_default_config()
    
    def reload_config(self):
        """Reload configuration from file"""
        print("Reloading traffic control configuration...")
        self.load_config()
    
    def check_request(self, client_ip: str, method: str, host: str, 
                     path: str, user_agent: str = "") -> Tuple[bool, str]:
        """
        Check if request should be allowed
        
        Returns:
            Tuple of (allowed, reason)
        """
        # Check rate limiting
        if self.enable_rate_limiting:
            allowed, remaining = self.rate_limiter.is_allowed(client_ip)
            if not allowed:
                if self.enable_logging:
                    self.logger.log_rate_limited(client_ip, host)
                return False, f"rate_limited (quota: 0)"
        
        # Check filtering rules
        for rule in self.rules:
            if rule.rule_type == 'domain' and rule.matches(host):
                if rule.action == 'block':
                    reason = f"blocked by domain rule: {rule.pattern}"
                    if self.enable_logging:
                        self.logger.log_blocked(client_ip, host, reason)
                    return False, reason
                elif rule.action == 'allow':
                    return True, "allowed by rule"
            
            elif rule.rule_type == 'ip' and rule.matches(client_ip):
                if rule.action == 'block':
                    reason = f"blocked by IP rule: {rule.pattern}"
                    if self.enable_logging:
                        self.logger.log_blocked(client_ip, host, reason)
                    return False, reason
                elif rule.action == 'allow':
                    return True, "allowed by rule"
            
            elif rule.rule_type == 'method' and rule.matches(method):
                if rule.action == 'block':
                    reason = f"blocked by method rule: {rule.pattern}"
                    if self.enable_logging:
                        self.logger.log_blocked(client_ip, host, reason)
                    return False, reason
                elif rule.action == 'allow':
                    return True, "allowed by rule"
            
            elif rule.rule_type == 'path' and rule.matches(path):
                if rule.action == 'block':
                    reason = f"blocked by path rule: {rule.pattern}"
                    if self.enable_logging:
                        self.logger.log_blocked(client_ip, host, reason)
                    return False, reason
                elif rule.action == 'allow':
                    return True, "allowed by rule"
            
            elif rule.rule_type == 'user-agent' and rule.matches(user_agent):
                if rule.action == 'block':
                    reason = f"blocked by user-agent rule: {rule.pattern}"
                    if self.enable_logging:
                        self.logger.log_blocked(client_ip, host, reason)
                    return False, reason
                elif rule.action == 'allow':
                    return True, "allowed by rule"
        
        # No matching rule, use default action
        if self.default_action == 'block':
            return False, "blocked by default policy"
        return True, "allowed by default policy"
    
    def log_request(self, access_log: AccessLog):
        """Log a request"""
        if self.enable_logging:
            self.logger.log_access(access_log)
        
        if self.enable_bandwidth_monitoring:
            self.bandwidth_monitor.record(
                access_log.client_ip,
                access_log.bytes_sent,
                access_log.bytes_received
            )
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        stats = {}
        
        if self.enable_logging:
            stats['logging'] = self.logger.get_stats()
        
        if self.enable_bandwidth_monitoring:
            stats['bandwidth'] = self.bandwidth_monitor.get_all_usage()
        
        stats['rules_count'] = len(self.rules)
        stats['rate_limiting_enabled'] = self.enable_rate_limiting
        
        return stats
    
    def get_top_clients(self, limit: int = 10) -> List[Tuple[str, Dict]]:
        """Get top clients by request count"""
        if not self.enable_bandwidth_monitoring:
            return []
        
        usage = self.bandwidth_monitor.get_all_usage()
        sorted_clients = sorted(
            usage.items(),
            key=lambda x: x[1]['requests'],
            reverse=True
        )
        return sorted_clients[:limit]
    
    def add_rule(self, rule_type: str, pattern: str, action: str, priority: int = 0):
        """Add a new filtering rule"""
        rule = FilterRule(rule_type, pattern, action, priority)
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        print(f"Added rule: {rule}")
    
    def remove_rule(self, rule_type: str, pattern: str):
        """Remove a filtering rule"""
        self.rules = [r for r in self.rules 
                     if not (r.rule_type == rule_type and r.pattern == pattern)]
        print(f"Removed rule: {rule_type}={pattern}")
    
    def list_rules(self) -> List[FilterRule]:
        """Get all current rules"""
        return self.rules.copy()


# Convenience functions
def create_traffic_controller(config_file: str = "config/traffic_control.json") -> TrafficController:
    """Create and return a traffic controller instance"""
    return TrafficController(config_file)