[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/](?:\.git)[\\/]'
}

$patterns = @(
    '(?i)C:\\Users\\',
    '(?i)gh[opsu]_[A-Za-z0-9_]{20,}',
    '(?i)(?:api[_-]?key|token|password)\s*[:=]\s*["''][^"'']{8,}["'']'
)

foreach ($file in $files) {
    $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) {
            throw "Sanitization check failed for a tracked workspace file."
        }
    }
}

Write-Host 'Sanitization check passed.'
