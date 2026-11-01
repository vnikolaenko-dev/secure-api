param([ValidateSet('All', 'Update', 'Scan')][string]$Mode = 'All')
$ErrorActionPreference = 'Stop'
# PowerShell 7 must let us capture Maven's output and preserve its exit code.
$PSNativeCommandUseErrorActionPreference = $false
$projectRoot = Split-Path -Parent $PSScriptRoot
$logPath = Join-Path $projectRoot 'sca.log'

if ($Mode -ne 'Scan' -and [string]::IsNullOrWhiteSpace($env:NVD_API_KEY)) {
    $message = 'SCA cannot run: NVD_API_KEY is missing. Request and activate a key at https://nvd.nist.gov/developers/request-an-api-key. For GitHub Actions, add the repository Actions secret NVD_API_KEY. Fork pull requests do not receive this secret.'
    Set-Content -LiteralPath $logPath -Value $message -Encoding UTF8
    Write-Error $message -ErrorAction Continue
    exit 1
}

Push-Location $projectRoot
try {
    $wrapper = if ($env:OS -eq 'Windows_NT') { '.\mvnw.cmd' } else { './mvnw' }
    $scanExitCode = 0
    if ($Mode -ne 'Scan') {
        Write-Output 'SCA: updating the NVD database (the first download can take tens of minutes).'
        & $wrapper -B -ntp dependency-check:update-only 2>&1 |
            Tee-Object -FilePath $logPath
        $scanExitCode = $LASTEXITCODE
    }
    if ($scanExitCode -eq 0 -and $Mode -ne 'Update') {
        Write-Output 'SCA: scanning dependencies using the database updated in the preceding stage.'
        & $wrapper -B -ntp -DskipTests package dependency-check:check '-DautoUpdate=false' 2>&1 |
            Tee-Object -FilePath $logPath -Append
        $scanExitCode = $LASTEXITCODE
    }
} finally {
    Pop-Location
}
exit $scanExitCode
