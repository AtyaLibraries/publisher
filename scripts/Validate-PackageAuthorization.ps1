[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackagePath,
    [Parameter(Mandatory)][string] $RequestedRepository,
    [Parameter(Mandatory)][string] $AllowlistPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PublisherSecurity.psm1') -Force

$identity = Read-PackageIdentity -PackagePath $PackagePath
$policy = Read-PublisherAllowlist -AllowlistPath $AllowlistPath
$result = Test-PackageAuthorization -Identity $identity -RequestedRepository $RequestedRepository -Policy $policy

if ($env:GITHUB_OUTPUT) {
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "package_id=$($result.PackageId)"
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "policy_version=$($result.PolicyVersion)"
}

Write-Output "Package authorization verified for the requested repository under policy $($result.PolicyVersion)."
