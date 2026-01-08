# ==============================================================================
# Proxy Server Test Suite (PowerShell)
# ==============================================================================

$PROXY = "localhost:8888"
$TEST_COUNT = 0
$PASS_COUNT = 0
$FAIL_COUNT = 0

function Print-Header() {
    param($Message)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Print-Result() {
    param($Success, $Message)
    $script:TEST_COUNT++
    if ($Success) {
        Write-Host "✓ PASS: $Message" -ForegroundColor Green
        $script:PASS_COUNT++
    } else {
        Write-Host "✗ FAIL: $Message" -ForegroundColor Red
        $script:FAIL_COUNT++
    }
}

function Test-ProxyRunning {
    try {
        $connection = Test-NetConnection -ComputerName localhost -Port 8888 -InformationLevel Quiet
        return $connection
    } catch {
        return $false
    }
}

# Main test suite
Print-Header "Proxy Server Test Suite"
Write-Host "Proxy: $PROXY"
Write-Host "Current time: $(Get-Date)"
Write-Host ""

# Check if proxy is running
Write-Host "Checking if proxy server is running..."
if (Test-ProxyRunning) {
    Write-Host "✓ Proxy server is running on port 8888" -ForegroundColor Green
} else {
    Write-Host "✗ Proxy server is NOT running on port 8888" -ForegroundColor Red
    Write-Host "Please start the proxy server first: python src\proxy_server.py"
    exit 1
}

# Test 1: Basic HTTP GET request
Print-Header "Test 1: Basic HTTP GET Request"
Write-Host "Testing: curl -x $PROXY http://example.com"
try {
    $response = curl.exe -x $PROXY http://example.com -s -o $null -w "%{http_code}"
    Print-Result ($response -eq "200") "HTTP GET request to example.com (Status: $response)"
} catch {
    Print-Result $false "HTTP GET request to example.com (Error: $_)"
}

# Test 2: HTTP request to different site
Print-Header "Test 2: HTTP Request to httpbin.org"
Write-Host "Testing: curl -x $PROXY http://httpbin.org/get"
try {
    $response = curl.exe -x $PROXY http://httpbin.org/get -s -o $null -w "%{http_code}"
    Print-Result ($response -eq "200") "HTTP GET request to httpbin.org (Status: $response)"
} catch {
    Print-Result $false "HTTP GET request to httpbin.org (Error: $_)"
}

# Test 3: HTTPS request
Print-Header "Test 3: HTTPS Request (CONNECT Tunnel)"
Write-Host "Testing: curl -x $PROXY https://example.com"
try {
    $response = curl.exe -x $PROXY https://example.com -s -o $null -w "%{http_code}"
    Print-Result ($response -eq "200") "HTTPS request to example.com (Status: $response)"
} catch {
    Print-Result $false "HTTPS request to example.com (Error: $_)"
}

# Test 4: POST request
Print-Header "Test 4: POST Request"
Write-Host "Testing: curl -x $PROXY -X POST http://httpbin.org/post"
try {
    $response = curl.exe -x $PROXY -X POST http://httpbin.org/post -d "test=data" -s -o $null -w "%{http_code}"
    Print-Result ($response -eq "200") "HTTP POST request (Status: $response)"
} catch {
    Print-Result $false "HTTP POST request (Error: $_)"
}

# Test 5: HEAD request
Print-Header "Test 5: HEAD Request"
Write-Host "Testing: curl -x $PROXY --head http://example.com"
try {
    $response = curl.exe -x $PROXY --head http://example.com -s -o $null -w "%{http_code}"
    Print-Result ($response -eq "200") "HTTP HEAD request (Status: $response)"
} catch {
    Print-Result $false "HTTP HEAD request (Error: $_)"
}

# Test 6: Concurrent requests
Print-Header "Test 6: Concurrent Requests"
Write-Host "Testing: 5 simultaneous requests"
try {
    1..5 | ForEach-Object -Parallel {
        curl.exe -x localhost:8888 http://example.com -s -o $null
    }
    Print-Result $true "Concurrent requests (5 simultaneous)"
} catch {
    Print-Result $false "Concurrent requests (Error: $_)"
}

# Summary
Print-Header "Test Summary"
Write-Host "Total tests: $TEST_COUNT"
Write-Host "Passed: $PASS_COUNT" -ForegroundColor Green
Write-Host "Failed: $FAIL_COUNT" -ForegroundColor Red

if ($FAIL_COUNT -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "ALL TESTS PASSED! ✓" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "SOME TESTS FAILED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Check logs\proxy.log for detailed proxy server logs"