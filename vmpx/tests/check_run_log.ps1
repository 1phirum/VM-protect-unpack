param(
    [Parameter(Mandatory = $true)]
    [string]$Log,
    [string]$Expect = ""
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Log)) {
    Write-Error "log not found: $Log"
    exit 2
}

$text = Get-Content -LiteralPath $Log -Raw

if ($text -match "stopping on terminal exception") {
    if ($text -match "(?m)^STATUS run ok\b") {
        Write-Error "terminal exception followed by STATUS run ok in $Log"
        exit 1
    }
    if ($text -notmatch "STATUS run failed status=terminal-exception") {
        Write-Error "terminal exception not reported as terminal-exception in $Log"
        exit 1
    }
}

if ($Expect -and $text -notmatch [regex]::Escape("status=$Expect")) {
    Write-Error "expected status=$Expect in $Log"
    exit 1
}

Write-Output "run log ok: $Log"
