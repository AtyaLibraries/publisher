[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Repository,
    [Parameter(Mandatory)][string] $Ref,
    [AllowEmptyString()][string] $Solution = '',
    [AllowEmptyString()][string] $PackageProject = '',
    [AllowEmptyString()][string] $GlobalJson = 'global.json'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PublisherSecurity.psm1') -Force

$canonicalRepository = ConvertTo-CanonicalRepository -Repository $Repository
$release = ConvertTo-CanonicalReleaseRef -Ref $Ref
$safeSolution = ConvertTo-SafeRelativePath -Path $Solution -Name 'solution' -AllowEmpty
$safePackageProject = ConvertTo-SafeRelativePath -Path $PackageProject -Name 'package project' -AllowEmpty
$safeGlobalJson = ConvertTo-SafeRelativePath -Path $GlobalJson -Name 'global.json path'

$values = [ordered]@{
    repository = $canonicalRepository
    ref = $release.Ref
    version = $release.Version
    solution = $safeSolution
    package_project = $safePackageProject
    global_json = $safeGlobalJson
}

if ($env:GITHUB_OUTPUT) {
    foreach ($item in $values.GetEnumerator()) {
        Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$($item.Key)=$($item.Value)"
    }
}

[pscustomobject] $values
