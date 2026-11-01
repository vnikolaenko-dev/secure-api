param([string]$BaseUrl = 'http://localhost:18081')
$ErrorActionPreference = 'Stop'
if (-not $env:APP_ADMIN_PASSWORD) { throw 'Set APP_ADMIN_PASSWORD first' }
$report = [System.Collections.Generic.List[string]]::new()
function Check([string]$Method, [string]$Path, [string]$Body, [string]$Token, [int]$Expected) {
    $params = @{ Uri = "$BaseUrl$Path"; Method = $Method; UseBasicParsing = $true; ContentType = 'application/json' }
    if ($Body) { $params.Body = $Body }
    if ($Token) { $params.Headers = @{ Authorization = "Bearer $Token" } }
    $responseBody = ''
    try { $response = Invoke-WebRequest @params; $status = [int]$response.StatusCode; $responseBody = $response.Content }
    catch { if (-not $_.Exception.Response) { throw }; $status = [int]$_.Exception.Response.StatusCode }
    if ($status -ne $Expected) { throw "$Method $Path expected $Expected, got $status" }
    $line = "$Method $Path -> $status PASS"
    Write-Output $line | Out-Host
    $report.Add($line)
    return $responseBody
}
$null = Check GET /api/data '' '' 401
$body = @{username='admin'; password=$env:APP_ADMIN_PASSWORD} | ConvertTo-Json -Compress
$login = (Check POST /auth/login $body '' 200) | ConvertFrom-Json
$null = Check GET /api/data '' $login.accessToken 200
$post = Check POST /api/data '{"content":"<script>alert(1)</script>"}' $login.accessToken 201
if ($post -notlike '*&lt;script&gt;*') { throw 'XSS escaping failed' }
$null = Check GET /api/data '' 'fake.jwt.token' 401
$null = Check POST /auth/login '{"username":"admin","password":"incorrect"}' '' 401
New-Item -ItemType Directory -Force reports | Out-Null
$report | Set-Content -Encoding UTF8 reports/smoke.txt
