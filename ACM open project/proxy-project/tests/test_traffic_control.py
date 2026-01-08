
"""
Traffic Control Test and Demonstration
Tests filtering, logging, and rate limiting functionality
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from traffic_control import (
    TrafficController, FilterRule, AccessLog,
    RateLimiter, BandwidthMonitor
)


class TrafficControlTester():
    """Test suite for traffic control"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.controller = None
    
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
    
    def test_filter_rules(self):
        """Test filter rule matching"""
        self.print_header("Test 1: Filter Rule Matching")
        
        # Test exact match
        rule1 = FilterRule('domain', 'example.com', 'block')
        self.assert_test(
            rule1.matches('example.com'),
            "Exact domain match"
        )
        self.assert_test(
            not rule1.matches('test.com'),
            "Domain non-match"
        )
        
        # Test wildcard match
        rule2 = FilterRule('domain', '*.ads.com', 'block')
        self.assert_test(
            rule2.matches('tracker.ads.com'),
            "Wildcard domain match"
        )
        self.assert_test(
            rule2.matches('any.subdomain.ads.com'),
            "Multi-level wildcard match"
        )
        
        # Test IP match
        rule3 = FilterRule('ip', '192.168.1.*', 'block')
        self.assert_test(
            rule3.matches('192.168.1.100'),
            "IP wildcard match"
        )
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        self.print_header("Test 2: Rate Limiting")
        
        limiter = RateLimiter(requests_per_minute=5, window_seconds=10)
        
        # Should allow first 5 requests
        for i in range(5):
            allowed, remaining = limiter.is_allowed('192.168.1.1')
            self.assert_test(
                allowed,
                f"Request {i+1}/5 allowed"
            )
        
        # 6th request should be blocked
        allowed, remaining = limiter.is_allowed('192.168.1.1')
        self.assert_test(
            not allowed,
            "6th request blocked (rate limit exceeded)"
        )
        
        # Different IP should be allowed
        allowed, _ = limiter.is_allowed('192.168.1.2')
        self.assert_test(
            allowed,
            "Different IP not affected by rate limit"
        )
    
    def test_bandwidth_monitoring(self):
        """Test bandwidth monitoring"""
        self.print_header("Test 3: Bandwidth Monitoring")
        
        monitor = BandwidthMonitor()
        
        # Record some traffic
        monitor.record('192.168.1.1', bytes_sent=1000, bytes_received=500)
        monitor.record('192.168.1.1', bytes_sent=2000, bytes_received=1000)
        monitor.record('192.168.1.2', bytes_sent=500, bytes_received=250)
        
        # Check totals
        usage1 = monitor.get_usage('192.168.1.1')
        self.assert_test(
            usage1['bytes_sent'] == 3000,
            "Bytes sent tracked correctly (3000)"
        )
        self.assert_test(
            usage1['bytes_received'] == 1500,
            "Bytes received tracked correctly (1500)"
        )
        self.assert_test(
            usage1['requests'] == 2,
            "Request count correct (2)"
        )
    
    def test_access_logging(self):
        """Test access log formatting"""
        self.print_header("Test 4: Access Logging")
        
        log = AccessLog(
            timestamp=datetime.now(),
            client_ip='192.168.1.1',
            client_port=54321,
            method='GET',
            host='example.com',
            path='/test',
            status=200,
            bytes_sent=1234,
            bytes_received=567,
            duration=0.5,
            action='allow',
            user_agent='TestBot/1.0'
        )
        
        # Test CLF format
        clf = log.to_clf_format()
        self.assert_test(
            '192.168.1.1' in clf,
            "CLF contains client IP"
        )
        self.assert_test(
            'GET' in clf,
            "CLF contains method"
        )
        self.assert_test(
            '200' in clf,
            "CLF contains status code"
        )
        
        # Test JSON format
        json_str = log.to_json()
        self.assert_test(
            'client_ip' in json_str,
            "JSON contains client_ip field"
        )
        self.assert_test(
            'duration_ms' in json_str,
            "JSON contains duration_ms field"
        )
    
    def test_traffic_controller(self):
        """Test the main traffic controller"""
        self.print_header("Test 5: Traffic Controller Integration")
        
        # Create controller with test config
        self.controller = TrafficController('config/traffic_control.json')
        
        # Test allowed request
        allowed, reason = self.controller.check_request(
            client_ip='192.168.1.1',
            method='GET',
            host='google.com',
            path='/',
            user_agent='curl/7.68.0'
        )
        self.assert_test(
            allowed,
            "Normal request allowed"
        )
        
        # Test blocked domain (if example.com is in blocklist)
        allowed, reason = self.controller.check_request(
            client_ip='192.168.1.1',
            method='GET',
            host='example.com',
            path='/',
            user_agent='curl/7.68.0'
        )
        self.assert_test(
            not allowed,
            "Blocked domain rejected"
        )
        print(f"  Reason: {reason}")
        
        # Test blocked method
        allowed, reason = self.controller.check_request(
            client_ip='192.168.1.1',
            method='TRACE',
            host='google.com',
            path='/',
            user_agent='curl/7.68.0'
        )
        self.assert_test(
            not allowed,
            "TRACE method blocked"
        )
    
    def test_rule_management(self):
        """Test adding and removing rules"""
        self.print_header("Test 6: Rule Management")
        
        if not self.controller:
            self.controller = TrafficController('config/traffic_control.json')
        
        initial_count = len(self.controller.rules)
        
        # Add a rule
        self.controller.add_rule('domain', 'test.block.com', 'block', priority=15)
        new_count = len(self.controller.rules)
        self.assert_test(
            new_count == initial_count + 1,
            "Rule added successfully"
        )
        
        # Test the new rule
        allowed, _ = self.controller.check_request(
            '192.168.1.1', 'GET', 'test.block.com', '/', ''
        )
        self.assert_test(
            not allowed,
            "New rule blocks correctly"
        )
        
        # Remove the rule
        self.controller.remove_rule('domain', 'test.block.com')
        final_count = len(self.controller.rules)
        self.assert_test(
            final_count == initial_count,
            "Rule removed successfully"
        )
    
    def test_statistics(self):
        """Test statistics gathering"""
        self.print_header("Test 7: Statistics")
        
        if not self.controller:
            self.controller = TrafficController('config/traffic_control.json')
        
        # Generate some traffic
        for i in range(5):
            log = AccessLog(
                timestamp=datetime.now(),
                client_ip=f'192.168.1.{i}',
                client_port=50000 + i,
                method='GET',
                host='example.com',
                path='/',
                status=200 if i < 3 else 403,
                bytes_sent=1000,
                bytes_received=500,
                duration=0.1,
                action='allow' if i < 3 else 'block'
            )
            self.controller.log_request(log)
        
        stats = self.controller.get_statistics()
        
        self.assert_test(
            'logging' in stats,
            "Statistics contain logging data"
        )
        self.assert_test(
            'bandwidth' in stats,
            "Statistics contain bandwidth data"
        )
        
        print(f"\n  Current Statistics:")
        if 'logging' in stats:
            log_stats = stats['logging']
            print(f"    Total Requests: {log_stats.get('total_requests', 0)}")
            print(f"    Allowed: {log_stats.get('allowed_requests', 0)}")
            print(f"    Blocked: {log_stats.get('blocked_requests', 0)}")
    
    def test_rate_limit_integration(self):
        """Test rate limiting in traffic controller"""
        self.print_header("Test 8: Rate Limiting Integration")
        
        if not self.controller:
            self.controller = TrafficController('config/traffic_control.json')
        
        # Make many requests from same IP
        test_ip = '10.0.0.100'
        allowed_count = 0
        blocked_count = 0
        
        for i in range(70):  # More than the limit
            allowed, reason = self.controller.check_request(
                test_ip, 'GET', 'google.com', '/', ''
            )
            if allowed:
                allowed_count += 1
            else:
                blocked_count += 1
        
        self.assert_test(
            blocked_count > 0,
            f"Rate limit triggered ({blocked_count} requests blocked)"
        )
        print(f"  Allowed: {allowed_count}, Blocked: {blocked_count}")
    
    def demo_log_files(self):
        """Demonstrate log file creation"""
        self.print_header("Demo: Log Files")
        
        print("Log files created:")
        log_dir = Path('logs')
        if log_dir.exists():
            for log_file in log_dir.glob('*.log'):
                size = log_file.stat().st_size
                print(f"  ✓ {log_file.name} ({size} bytes)")
            for log_file in log_dir.glob('*.json'):
                size = log_file.stat().st_size
                print(f"  ✓ {log_file.name} ({size} bytes)")
        else:
            print("  (No log files created yet)")
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("  TRAFFIC CONTROL TEST SUITE")
        print("="*70)
        
        self.test_filter_rules()
        self.test_rate_limiting()
        self.test_bandwidth_monitoring()
        self.test_access_logging()
        self.test_traffic_controller()
        self.test_rule_management()
        self.test_statistics()
        self.test_rate_limit_integration()
        self.demo_log_files()
        
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
    tester = TrafficControlTester()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()