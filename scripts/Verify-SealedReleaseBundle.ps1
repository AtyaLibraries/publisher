[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BundlePath,
    [Parameter(Mandatory)][string] $ExpectedPackageId,
    [Parameter(Mandatory)][string] $ExpectedVersion,
    [Parameter(Mandatory)][string] $ExpectedRepository,
    [Parameter(Mandatory)][string] $ExpectedRef,
    [Parameter(Mandatory)][string] $ExpectedCommit,
    [Parameter(Mandatory)][string] $ExpectedPolicyVersion
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PublisherSecurity.psm1') -Force

$null = Test-SealedReleaseBundle -BundlePath $BundlePath -ExpectedPackageId $ExpectedPackageId `
    -ExpectedVersion $ExpectedVersion -ExpectedRepository $ExpectedRepository `
    -ExpectedRef $ExpectedRef -ExpectedCommit $ExpectedCommit -ExpectedPolicyVersion $ExpectedPolicyVersion

Write-Output 'Sealed release bundle hashes and manifest remain unchanged.'
