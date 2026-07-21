[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'scripts/PublisherSecurity.psm1') -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

$script:Passed = 0
$script:Failed = 0

function Test-Case([string] $Name, [scriptblock] $Body) {
    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name"
        Write-Host $_.Exception.Message
    }
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) { throw "Expected '$Expected'; got '$Actual'." }
}

function Assert-True([bool] $Value, [string] $Message) {
    if (-not $Value) { throw $Message }
}

function Assert-Throws([string] $ExpectedMessage, [scriptblock] $Body) {
    try { & $Body }
    catch {
        Assert-Equal $ExpectedMessage $_.Exception.Message
        return
    }
    throw 'Expected the operation to fail closed.'
}

function New-TestPortablePdbBytes([string] $SourceLinkMarker) {
    $streams = [ordered]@{
        '#Pdb' = [byte[]] (1, 0, 0, 0)
        '#~' = [byte[]] (0, 0, 0, 0)
        '#Strings' = [byte[]] (0)
        '#GUID' = ([Guid] 'CC110556-A091-4D38-9FEC-25AB9A351A6A').ToByteArray()
        '#Blob' = [Text.Encoding]::UTF8.GetBytes("{`"documents`":{`"*`":`"$SourceLinkMarker*`"}}")
    }
    $version = [Text.Encoding]::ASCII.GetBytes("PDB v1.0`0`0`0`0")
    $headerLength = 16 + $version.Length + 4
    foreach ($name in $streams.Keys) {
        $nameLength = [Text.Encoding]::ASCII.GetByteCount($name) + 1
        $headerLength += 8 + (($nameLength + 3) -band -4)
    }
    $total = $headerLength + (($streams.Values | ForEach-Object Length | Measure-Object -Sum).Sum)
    $bytes = [byte[]]::new($total)
    [BitConverter]::GetBytes([uint32] 0x424A5342).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($bytes, 4)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($bytes, 6)
    [BitConverter]::GetBytes([uint32] $version.Length).CopyTo($bytes, 12)
    $version.CopyTo($bytes, 16)
    $directory = 16 + $version.Length
    [BitConverter]::GetBytes([uint16] $streams.Count).CopyTo($bytes, $directory + 2)
    $cursor = $directory + 4
    $dataOffset = $headerLength
    foreach ($name in $streams.Keys) {
        $data = $streams[$name]
        [BitConverter]::GetBytes([uint32] $dataOffset).CopyTo($bytes, $cursor)
        [BitConverter]::GetBytes([uint32] $data.Length).CopyTo($bytes, $cursor + 4)
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($name)
        $nameBytes.CopyTo($bytes, $cursor + 8)
        $cursor += 8 + (($nameBytes.Length + 1 + 3) -band -4)
        $data.CopyTo($bytes, $dataOffset)
        $dataOffset += $data.Length
    }
    return $bytes
}

function New-TestPackage {
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $PackageId = 'Atya.Foundation.Guards',
        [string] $Version = '1.2.3',
        [string] $RepositoryUrl = 'https://github.com/AtyaLibraries/Guards',
        [int] $NuspecCount = 1,
        [switch] $MalformedXml,
        [switch] $MissingId,
        [switch] $DuplicateId,
        [switch] $MissingRepository,
        [switch] $DuplicateMetadata,
        [switch] $ForeignIdentityNamespace,
        [string] $DefaultNamespace = '',
        [switch] $SymbolsPackage,
        [switch] $MalformedPortablePdb,
        [switch] $MissingSourceLink,
        [switch] $UnsafeArchivePath
    )

    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($index in 1..$NuspecCount) {
            $entry = $archive.CreateEntry("package$index.nuspec")
            $stream = $entry.Open()
            try {
                $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
                try {
                    if ($MalformedXml) {
                        $writer.Write('<package><metadata>')
                    }
                    else {
                        $escapedId = [Security.SecurityElement]::Escape($PackageId)
                        $escapedUrl = [Security.SecurityElement]::Escape($RepositoryUrl)
                        $prefix = if ($ForeignIdentityNamespace) { 'foreign:' } else { '' }
                        $foreignNamespace = if ($ForeignIdentityNamespace) { ' xmlns:foreign="urn:foreign"' } else { '' }
                        $defaultNamespaceAttribute = if ($DefaultNamespace) { " xmlns=`"$DefaultNamespace`"" } else { '' }
                        $id = if ($MissingId) { '' } elseif ($DuplicateId) { "<id>$escapedId</id><id>$escapedId</id>" } else { "<$($prefix)id>$escapedId</$($prefix)id>" }
                        $repository = if ($MissingRepository) { '' } else { "<$($prefix)repository type=`"git`" url=`"$escapedUrl`" />" }
                        $packageType = if ($SymbolsPackage) { '<packageTypes><packageType name="SymbolsPackage" /></packageTypes>' } else { '' }
                        $metadata = "<metadata>$id<version>$Version</version>$packageType$repository</metadata>"
                        if ($DuplicateMetadata) { $metadata += $metadata }
                        $writer.Write("<?xml version=`"1.0`"?><package$defaultNamespaceAttribute$foreignNamespace>$metadata</package>")
                    }
                }
                finally { $writer.Dispose() }
            }
            finally { $stream.Dispose() }
        }

        $contentPath = if ($SymbolsPackage) { 'lib/net10.0/Atya.Foundation.Guards.pdb' } else { 'lib/net10.0/Atya.Foundation.Guards.dll' }
        $contentEntry = $archive.CreateEntry($contentPath)
        $contentStream = $contentEntry.Open()
        try {
            $content = if ($SymbolsPackage) {
                $sourceLink = if ($MissingSourceLink) { '' } else { 'https://raw.githubusercontent.com/AtyaLibraries/Guards/0123456789012345678901234567890123456789/*' }
                if ($MalformedPortablePdb) {
                    [Text.Encoding]::UTF8.GetBytes("BSJB synthetic portable pdb $sourceLink")
                }
                else { New-TestPortablePdbBytes $sourceLink }
            }
            else { [byte[]] (1, 2, 3, 4) }
            $contentStream.Write($content, 0, $content.Length)
        }
        finally { $contentStream.Dispose() }

        if ($SymbolsPackage) {
            $relationships = $archive.CreateEntry('_rels/.rels')
            $relationshipsStream = $relationships.Open()
            try {
                $relationshipsBytes = [Text.Encoding]::UTF8.GetBytes('<Relationships />')
                $relationshipsStream.Write($relationshipsBytes, 0, $relationshipsBytes.Length)
            }
            finally { $relationshipsStream.Dispose() }
        }

        if ($UnsafeArchivePath) {
            $unsafe = $archive.CreateEntry('../unexpected.txt')
            $unsafe.Open().Dispose()
        }
    }
    finally { $archive.Dispose() }
}

function New-PolicyFile([string] $Path, [object[]] $Packages, [string] $Schema = '1.0.0', [string] $Version = '1.5.1') {
    $json = [ordered]@{ schemaVersion = $Schema; policyVersion = $Version; packages = $Packages } |
        ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function New-TestSbom([string] $Path, [string] $PackageId, [string] $Version, [string] $PackagePath) {
    $hash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $value = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        version = 1
        serialNumber = 'urn:uuid:00000000-0000-0000-0000-000000000000'
        metadata = [ordered]@{
            component = [ordered]@{ name = "$PackageId.$Version.nupkg"; version = "sha256:$hash" }
        }
        components = @()
    }
    [IO.File]::WriteAllText($Path, (($value | ConvertTo-Json -Depth 10) + "`n"), [Text.UTF8Encoding]::new($false))
}

function New-TestBundle([string] $Path) {
    New-Item -ItemType Directory -Path $Path | Out-Null
    $primary = Join-Path $Path 'package.nupkg'
    New-TestPackage -Path $primary
    New-TestPackage -Path (Join-Path $Path 'package.snupkg') -SymbolsPackage
    New-TestSbom (Join-Path $Path 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' $primary
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ("publisher-security-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $allowlistPath = Join-Path $root 'policy/publisher-allowlist.json'
    $invalidRepository = 'The source repository identity is not an approved AtyaLibraries owner/name value.'
    $invalidRef = 'The source ref is not an immutable release tag.'
    $invalidVersion = 'The release tag does not contain a supported semantic version.'
    $invalidPath = 'path is not a safe repository-relative path.'
    $invalidUrl = 'Package repository metadata is not a supported canonical GitHub URL.'

    Test-Case 'canonical request passes' {
        Assert-Equal 'AtyaLibraries/Guards' (ConvertTo-CanonicalRepository 'AtyaLibraries/Guards')
        $release = ConvertTo-CanonicalReleaseRef 'v1.2.3-preview.1'
        Assert-Equal 'refs/tags/v1.2.3-preview.1' $release.Ref
        Assert-Equal '1.2.3-preview.1' $release.Version
        Assert-Equal 'src/Guards.csproj' (ConvertTo-SafeRelativePath 'src/Guards.csproj' 'project')
    }

    foreach ($repository in @('Other/Guards', 'atyalibraries/Guards', 'AtyaLibraries/Guards.git', 'AtyaLibraries/../Guards', 'AtyaLibraries/Guards/extra')) {
        Test-Case "unsafe repository fails: $repository" { Assert-Throws $invalidRepository { ConvertTo-CanonicalRepository $repository } }
    }
    foreach ($ref in @('main', 'refs/heads/v1.2.3', 'V1.2.3')) {
        Test-Case "unsafe ref fails: $ref" { Assert-Throws $invalidRef { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($ref in @('v1.2', 'v1.2.3+metadata', 'v1.2.3/other', 'v01.2.3', 'v1.02.3', 'v1.2.03', 'v1.2.3-01')) {
        Test-Case "invalid semantic version fails: $ref" { Assert-Throws $invalidVersion { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($path in @('../secret', '/tmp/file', 'src\file.csproj', './src/file.csproj', 'src/$file.csproj', 'src//file.csproj', 'src/file.csproj/')) {
        Test-Case "unsafe path fails: $path" { Assert-Throws $invalidPath { ConvertTo-SafeRelativePath $path 'path' } }
    }

    $validPackage = Join-Path $temp 'valid.nupkg'
    New-TestPackage -Path $validPackage
    Test-Case 'authorized derived PackageId and repository pass' {
        $identity = Read-PackageIdentity $validPackage
        $policy = Read-PublisherAllowlist $allowlistPath
        $result = Test-PackageAuthorization $identity 'AtyaLibraries/Guards' $policy
        Assert-Equal 'Atya.Foundation.Guards' $result.PackageId
        Assert-Equal '1.5.1' $result.PolicyVersion
    }
    Test-Case 'optional canonical dot-git repository URL passes' {
        Assert-Equal 'AtyaLibraries/Guards' (ConvertFrom-PackageRepositoryUrl 'https://github.com/AtyaLibraries/Guards.git/')
    }

    $namespacedPackage = Join-Path $temp 'namespaced.nupkg'
    New-TestPackage -Path $namespacedPackage -DefaultNamespace 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'
    Test-Case 'standard namespaced nuspec passes' {
        Assert-Equal 'Atya.Foundation.Guards' (Read-PackageIdentity $namespacedPackage).PackageId
    }

    $unknownPackage = Join-Path $temp 'unknown.nupkg'
    New-TestPackage -Path $unknownPackage -PackageId 'Atya.Unknown.Package' -RepositoryUrl 'https://github.com/AtyaLibraries/Guards'
    Test-Case 'unknown PackageId fails' {
        Assert-Throws 'The derived package id is not uniquely authorized by publisher policy.' { Test-PackageAuthorization (Read-PackageIdentity $unknownPackage) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    $wrongProvenance = Join-Path $temp 'wrong-provenance.nupkg'
    New-TestPackage -Path $wrongProvenance -RepositoryUrl 'https://github.com/AtyaLibraries/Results'
    Test-Case 'PackageId-to-repository policy mismatch fails' {
        Assert-Throws 'The derived package id is not authorized for the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $wrongProvenance) 'AtyaLibraries/Results' (Read-PublisherAllowlist $allowlistPath) }
    }
    Test-Case 'nuspec provenance mismatch fails' {
        Assert-Throws 'Package repository provenance does not match the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $wrongProvenance) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    foreach ($case in @(
        @{ Name = 'repository owner case'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/atyalibraries/Guards' },
        @{ Name = 'PackageId case'; Id = 'atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository query'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards?ref=main' },
        @{ Name = 'repository fragment'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards#readme' },
        @{ Name = 'repository userinfo'; Id = 'Atya.Foundation.Guards'; Url = 'https://user@github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository port'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com:444/AtyaLibraries/Guards' },
        @{ Name = 'alternate host'; Id = 'Atya.Foundation.Guards'; Url = 'https://www.github.com/AtyaLibraries/Guards' },
        @{ Name = 'encoded repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/%47uards' },
        @{ Name = 'encoded slash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries%2FGuards' },
        @{ Name = 'encoded backslash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries%5CGuards' },
        @{ Name = 'dot segment repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Other/../Guards' },
        @{ Name = 'double slash repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries//Guards' },
        @{ Name = 'repository prefix'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/prefix/AtyaLibraries/Guards' },
        @{ Name = 'repository suffix'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards/extra' },
        @{ Name = 'repository backslash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries\Guards' }
    )) {
        $path = Join-Path $temp (($case.Name -replace ' ', '-') + '.nupkg')
        New-TestPackage -Path $path -PackageId $case.Id -RepositoryUrl $case.Url
        $expected = if ($case.Name -eq 'PackageId case') { 'The package id is missing or malformed.' } else { $invalidUrl }
        Test-Case "$($case.Name) normalization fails closed" { Assert-Throws $expected { Read-PackageIdentity $path } }
    }

    $repositoryCase = Join-Path $temp 'repository-slug-case.nupkg'
    New-TestPackage -Path $repositoryCase -RepositoryUrl 'https://github.com/AtyaLibraries/guards'
    Test-Case 'repository slug case normalization fails closed' {
        Assert-Throws 'Package repository provenance does not match the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $repositoryCase) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    $missingNuspec = Join-Path $temp 'missing-nuspec.nupkg'
    $emptyArchive = [IO.Compression.ZipFile]::Open($missingNuspec, [IO.Compression.ZipArchiveMode]::Create)
    $emptyArchive.Dispose()
    Test-Case 'missing nuspec fails' { Assert-Throws 'The package must contain exactly one nuspec.' { Read-PackageIdentity $missingNuspec } }

    $duplicateNuspec = Join-Path $temp 'duplicate-nuspec.nupkg'
    New-TestPackage -Path $duplicateNuspec -NuspecCount 2
    Test-Case 'duplicate nuspec fails' { Assert-Throws 'The package must contain exactly one nuspec.' { Read-PackageIdentity $duplicateNuspec } }

    $malformedArchive = Join-Path $temp 'malformed-archive.nupkg'
    [IO.File]::WriteAllBytes($malformedArchive, [byte[]] (1, 2, 3, 4))
    Test-Case 'malformed ZIP fails with sanitized reason' { Assert-Throws 'The package artifact is not a valid ZIP archive.' { Read-PackageIdentity $malformedArchive } }

    $malformed = Join-Path $temp 'malformed.nupkg'
    New-TestPackage -Path $malformed -MalformedXml
    Test-Case 'malformed nuspec fails' { Assert-Throws 'The package nuspec is not valid safe XML.' { Read-PackageIdentity $malformed } }

    $foreignNamespace = Join-Path $temp 'foreign-namespace.nupkg'
    New-TestPackage -Path $foreignNamespace -ForeignIdentityNamespace
    Test-Case 'foreign-namespace identity elements fail' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $foreignNamespace } }

    $duplicateMetadata = Join-Path $temp 'duplicate-metadata.nupkg'
    New-TestPackage -Path $duplicateMetadata -DuplicateMetadata
    Test-Case 'duplicate metadata elements fail' { Assert-Throws 'The package nuspec must contain exactly one metadata element.' { Read-PackageIdentity $duplicateMetadata } }

    $duplicateId = Join-Path $temp 'duplicate-id.nupkg'
    New-TestPackage -Path $duplicateId -DuplicateId
    Test-Case 'duplicate package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $duplicateId } }

    $missingId = Join-Path $temp 'missing-id.nupkg'
    New-TestPackage -Path $missingId -MissingId
    Test-Case 'missing package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $missingId } }

    $missingRepository = Join-Path $temp 'missing-repository.nupkg'
    New-TestPackage -Path $missingRepository -MissingRepository
    Test-Case 'missing repository metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $missingRepository } }
    Test-Case 'package size boundary fails closed' { Assert-Throws 'The package artifact is missing, empty, oversized, or has an invalid extension.' { Read-PackageIdentity $validPackage -MaximumPackageBytes 1 } }
    Test-Case 'package entry boundary fails closed' { Assert-Throws 'The package contains too many entries.' { Read-PackageIdentity $validPackage -MaximumEntries 0 } }
    Test-Case 'nuspec size boundary fails closed' { Assert-Throws 'The package nuspec is empty or oversized.' { Read-PackageIdentity $validPackage -MaximumNuspecBytes 1 } }

    $badSchema = Join-Path $temp 'bad-schema.json'
    New-PolicyFile $badSchema @([ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }) '2.0.0'
    Test-Case 'unsupported schema fails' { Assert-Throws 'The publisher allowlist uses an unsupported policy schema or version.' { Read-PublisherAllowlist $badSchema } }

    $badVersion = Join-Path $temp 'bad-version.json'
    New-PolicyFile $badVersion @([ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }) '1.0.0' '2.0.0'
    Test-Case 'unsupported policy major fails' { Assert-Throws 'The publisher allowlist uses an unsupported policy schema or version.' { Read-PublisherAllowlist $badVersion } }

    $duplicates = Join-Path $temp 'duplicates.json'
    New-PolicyFile $duplicates @(
        [ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' },
        [ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }
    )
    Test-Case 'duplicate policy ids fail' { Assert-Throws 'The publisher allowlist contains duplicate or ambiguous package metadata.' { Read-PublisherAllowlist $duplicates } }

    Test-Case 'generated policy snapshot is byte-identical to recorded platform blob' {
        $actual = (& git -c "safe.directory=$($root.Replace('\', '/'))" hash-object $allowlistPath).Trim()
        Assert-Equal 'bc4d0fbfe4e752f7db5da17ddf047a1bbb3eb4b8' $actual
    }

    $validBundle = Join-Path $temp 'valid-bundle'
    New-TestBundle $validBundle
    Test-Case 'complete authorized release bundle validates and seals' {
        $sealed = New-SealedReleaseBundle $validBundle 'AtyaLibraries/Guards' '1.2.3' 'refs/tags/v1.2.3' $allowlistPath
        Assert-Equal 'Atya.Foundation.Guards' $sealed.PackageId
        Assert-Equal '1.2.3' $sealed.Version
        Assert-True (Test-Path -LiteralPath (Join-Path $validBundle 'release-manifest.json') -PathType Leaf) 'Release manifest was not generated.'
        Assert-True (Test-SealedReleaseBundle $validBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.PolicyVersion) 'Sealed bundle verification failed.'
    }

    $missingSymbolBundle = Join-Path $temp 'missing-symbol-bundle'
    New-TestBundle $missingSymbolBundle
    Remove-Item -LiteralPath (Join-Path $missingSymbolBundle 'package.snupkg')
    Test-Case 'missing required symbol package fails' {
        Assert-Throws 'The release bundle must contain exactly one symbol package.' { New-SealedReleaseBundle $missingSymbolBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $duplicatePrimaryBundle = Join-Path $temp 'duplicate-primary-bundle'
    New-TestBundle $duplicatePrimaryBundle
    Copy-Item -LiteralPath (Join-Path $duplicatePrimaryBundle 'package.nupkg') -Destination (Join-Path $duplicatePrimaryBundle 'duplicate.nupkg')
    Test-Case 'duplicate primary package fails' {
        Assert-Throws 'The release bundle must contain exactly one primary package.' { New-SealedReleaseBundle $duplicatePrimaryBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $duplicateSymbolBundle = Join-Path $temp 'duplicate-symbol-bundle'
    New-TestBundle $duplicateSymbolBundle
    Copy-Item -LiteralPath (Join-Path $duplicateSymbolBundle 'package.snupkg') -Destination (Join-Path $duplicateSymbolBundle 'duplicate.snupkg')
    Test-Case 'duplicate symbol package fails' {
        Assert-Throws 'The release bundle must contain exactly one symbol package.' { New-SealedReleaseBundle $duplicateSymbolBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    foreach ($mismatch in @(
        @{ Name = 'PackageId'; PackageId = 'Atya.Foundation.Results'; Version = '1.2.3'; Repository = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'version'; PackageId = 'Atya.Foundation.Guards'; Version = '1.2.4'; Repository = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository provenance'; PackageId = 'Atya.Foundation.Guards'; Version = '1.2.3'; Repository = 'https://github.com/AtyaLibraries/Results' }
    )) {
        $bundle = Join-Path $temp ("mismatched-" + ($mismatch.Name -replace ' ', '-') + '-bundle')
        New-TestBundle $bundle
        Remove-Item -LiteralPath (Join-Path $bundle 'package.snupkg')
        New-TestPackage -Path (Join-Path $bundle 'package.snupkg') -SymbolsPackage -PackageId $mismatch.PackageId -Version $mismatch.Version -RepositoryUrl $mismatch.Repository
        Test-Case "mismatched $($mismatch.Name) across package pair fails" {
            Assert-Throws 'The primary and symbol package identities do not agree.' { New-SealedReleaseBundle $bundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
        }
    }

    $requestedVersionBundle = Join-Path $temp 'requested-version-bundle'
    New-TestBundle $requestedVersionBundle
    Test-Case 'package and requested tag version mismatch fails' {
        Assert-Throws 'The requested tag and version do not agree.' { New-SealedReleaseBundle $requestedVersionBundle 'AtyaLibraries/Guards' '1.2.4' 'v1.2.3' $allowlistPath }
    }

    $badSbomBundle = Join-Path $temp 'bad-sbom-bundle'
    New-TestBundle $badSbomBundle
    New-TestSbom (Join-Path $badSbomBundle 'package.sbom.cdx.json') 'Atya.Foundation.Results' '1.2.3' (Join-Path $badSbomBundle 'package.nupkg')
    Test-Case 'SBOM package identity mismatch fails' {
        Assert-Throws 'The package SBOM does not identify the validated primary package.' { New-SealedReleaseBundle $badSbomBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $badSbomVersionBundle = Join-Path $temp 'bad-sbom-version-bundle'
    New-TestBundle $badSbomVersionBundle
    $sbomPath = Join-Path $badSbomVersionBundle 'package.sbom.cdx.json'
    [IO.File]::WriteAllText($sbomPath, ([regex]::Replace([IO.File]::ReadAllText($sbomPath), '"specVersion"\s*:\s*"1\.6"', '"specVersion": "2.0"')), [Text.UTF8Encoding]::new($false))
    Test-Case 'unsupported SBOM version fails' {
        Assert-Throws 'The package SBOM uses an unsupported or ambiguous format version.' { New-SealedReleaseBundle $badSbomVersionBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $malformedSbomBundle = Join-Path $temp 'malformed-sbom-bundle'
    New-TestBundle $malformedSbomBundle
    [IO.File]::WriteAllText((Join-Path $malformedSbomBundle 'package.sbom.cdx.json'), '{not-json', [Text.UTF8Encoding]::new($false))
    Test-Case 'malformed SBOM JSON fails with sanitized reason' {
        Assert-Throws 'The package SBOM is not valid JSON.' { New-SealedReleaseBundle $malformedSbomBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $missingSbomMetadataBundle = Join-Path $temp 'missing-sbom-metadata-bundle'
    New-TestBundle $missingSbomMetadataBundle
    [IO.File]::WriteAllText((Join-Path $missingSbomMetadataBundle 'package.sbom.cdx.json'), '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}', [Text.UTF8Encoding]::new($false))
    Test-Case 'missing SBOM identity metadata fails with sanitized reason' {
        Assert-Throws 'The package SBOM is missing required identity metadata.' { New-SealedReleaseBundle $missingSbomMetadataBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $unexpectedBundle = Join-Path $temp 'unexpected-bundle'
    New-TestBundle $unexpectedBundle
    [IO.File]::WriteAllText((Join-Path $unexpectedBundle 'unexpected.txt'), 'unexpected')
    Test-Case 'unexpected bundle file fails' {
        Assert-Throws 'The release bundle contains an unexpected artifact.' { New-SealedReleaseBundle $unexpectedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $unsafePathBundle = Join-Path $temp 'unsafe-path-bundle'
    New-TestBundle $unsafePathBundle
    New-Item -ItemType Directory -Path (Join-Path $unsafePathBundle 'nested') | Out-Null
    Test-Case 'nested bundle path fails' {
        Assert-Throws 'The release bundle contains an unsafe path or nested directory.' { New-SealedReleaseBundle $unsafePathBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $zeroLengthBundle = Join-Path $temp 'zero-length-bundle'
    New-TestBundle $zeroLengthBundle
    [IO.File]::WriteAllBytes((Join-Path $zeroLengthBundle 'package.sbom.cdx.json'), [byte[]] @())
    Test-Case 'zero-length required artifact fails' {
        Assert-Throws 'A required release artifact is empty or oversized.' { New-SealedReleaseBundle $zeroLengthBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $boundedBundle = Join-Path $temp 'bounded-bundle'
    New-TestBundle $boundedBundle
    Test-Case 'per-file bundle size boundary fails' {
        Assert-Throws 'A required release artifact is empty or oversized.' { New-SealedReleaseBundle $boundedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath -MaximumSbomBytes 1 }
    }
    Test-Case 'aggregate bundle size boundary fails' {
        Assert-Throws 'The release bundle exceeds the aggregate size boundary.' { New-SealedReleaseBundle $boundedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath -MaximumAggregateBytes 1 }
    }

    $unsafeArchiveBundle = Join-Path $temp 'unsafe-archive-bundle'
    New-TestBundle $unsafeArchiveBundle
    Remove-Item -LiteralPath (Join-Path $unsafeArchiveBundle 'package.nupkg')
    New-TestPackage -Path (Join-Path $unsafeArchiveBundle 'package.nupkg') -UnsafeArchivePath
    New-TestSbom (Join-Path $unsafeArchiveBundle 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' (Join-Path $unsafeArchiveBundle 'package.nupkg')
    Test-Case 'unsafe package archive path fails' {
        Assert-Throws 'The package contains an unsafe or ambiguous archive entry.' { New-SealedReleaseBundle $unsafeArchiveBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    foreach ($pdbCase in @(
        @{ Name = 'malformed Portable PDB'; Malformed = $true; MissingSourceLink = $false },
        @{ Name = 'missing SourceLink'; Malformed = $false; MissingSourceLink = $true }
    )) {
        $bundle = Join-Path $temp (($pdbCase.Name -replace ' ', '-') + '-bundle')
        New-TestBundle $bundle
        Remove-Item -LiteralPath (Join-Path $bundle 'package.snupkg')
        New-TestPackage -Path (Join-Path $bundle 'package.snupkg') -SymbolsPackage -MalformedPortablePdb:$pdbCase.Malformed -MissingSourceLink:$pdbCase.MissingSourceLink
        Test-Case "$($pdbCase.Name) fails" {
            Assert-Throws 'The symbol package does not contain portable SourceLink-bound PDBs.' { New-SealedReleaseBundle $bundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
        }
    }

    $missingSymbolTypeBundle = Join-Path $temp 'missing-symbol-type-bundle'
    New-TestBundle $missingSymbolTypeBundle
    Remove-Item -LiteralPath (Join-Path $missingSymbolTypeBundle 'package.snupkg')
    New-TestPackage -Path (Join-Path $missingSymbolTypeBundle 'package.snupkg')
    Test-Case 'missing SymbolsPackage type fails' {
        Assert-Throws 'The symbol package does not declare exactly one SymbolsPackage type.' { New-SealedReleaseBundle $missingSymbolTypeBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath }
    }

    $hashTamperBundle = Join-Path $temp 'hash-tamper-bundle'
    New-TestBundle $hashTamperBundle
    $sealed = New-SealedReleaseBundle $hashTamperBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath
    [IO.File]::AppendAllText((Join-Path $hashTamperBundle 'package.nupkg'), 'tamper')
    Test-Case 'artifact hash mismatch after sealing fails' {
        Assert-Throws 'A sealed artifact hash or length does not match the release manifest.' { Test-SealedReleaseBundle $hashTamperBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.PolicyVersion }
    }

    $manifestTamperBundle = Join-Path $temp 'manifest-tamper-bundle'
    New-TestBundle $manifestTamperBundle
    $sealed = New-SealedReleaseBundle $manifestTamperBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath
    $manifestPath = Join-Path $manifestTamperBundle 'release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace('Atya.Foundation.Guards', 'Atya.Foundation.Results')), [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest identity tampering fails' {
        Assert-Throws 'The release manifest identity does not match the authorized release.' { Test-SealedReleaseBundle $manifestTamperBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.PolicyVersion }
    }

    $manifestVersionBundle = Join-Path $temp 'manifest-version-bundle'
    New-TestBundle $manifestVersionBundle
    $sealed = New-SealedReleaseBundle $manifestVersionBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath
    $manifestPath = Join-Path $manifestVersionBundle 'release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace('"schemaVersion": "1.0.0"', '"schemaVersion": "2.0.0"')), [Text.UTF8Encoding]::new($false))
    Test-Case 'unsupported release manifest schema fails' {
        Assert-Throws 'The release manifest uses an unsupported schema version.' { Test-SealedReleaseBundle $manifestVersionBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.PolicyVersion }
    }

    $malformedManifestBundle = Join-Path $temp 'malformed-manifest-bundle'
    New-TestBundle $malformedManifestBundle
    $sealed = New-SealedReleaseBundle $malformedManifestBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $allowlistPath
    [IO.File]::WriteAllText((Join-Path $malformedManifestBundle 'release-manifest.json'), '{not-json', [Text.UTF8Encoding]::new($false))
    Test-Case 'malformed release manifest fails with sanitized reason' {
        Assert-Throws 'The release manifest is not valid JSON.' { Test-SealedReleaseBundle $malformedManifestBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.PolicyVersion }
    }

    $workflow = (Get-Content -LiteralPath (Join-Path $root '.github/workflows/publish.yml') -Raw) -replace "`r`n", "`n"
    $buildStart = $workflow.IndexOf("  build:`n", [StringComparison]::Ordinal)
    $publishStart = $workflow.IndexOf("  publish:`n", [StringComparison]::Ordinal)
    Assert-True ($buildStart -ge 0 -and $publishStart -gt $buildStart) 'Workflow jobs could not be located.'
    $buildJob = $workflow.Substring($buildStart, $publishStart - $buildStart)
    $publishJob = $workflow.Substring($publishStart)

    Test-Case 'untrusted build job has no publication authority' {
        Assert-True ($buildJob -notmatch 'id-token:\s*write|attestations:\s*write|environment:\s*production|NuGet/login|nuget push|NUGET_API_KEY') 'Build job contains publication authority.'
        Assert-True ($buildJob -match 'permissions:\s*\r?\n\s+contents:\s+read') 'Build job does not declare minimal contents permission.'
    }
    Test-Case 'auto-discovered source paths are canonicalized before job outputs' {
        Assert-True ($buildJob.Contains("ConvertTo-SafeRelativePath -Path `$solution -Name 'solution'")) 'The discovered solution path is not canonicalized.'
        Assert-True ($buildJob.Contains("ConvertTo-SafeRelativePath -Path `$packageProject -Name 'package project'")) 'The discovered package project path is not canonicalized.'
    }
    Test-Case 'privileged job never checks out or builds requested source' {
        Assert-True ($publishJob -notmatch 'build-pack-nuget|working-directory:\s*source|(?m)^\s*repository:\s*\$\{\{\s*needs\.build\.outputs\.repository') 'Publish job can check out or build requested source.'
        Assert-True ($publishJob -match 'repository:\s*AtyaLibraries/publisher') 'Publish job does not use trusted publisher controls.'
    }
    Test-Case 'complete sealed bundle is retained and attested before credentials and push' {
        $authorize = $publishJob.IndexOf('Validate, complete, and seal release bundle', [StringComparison]::Ordinal)
        $retain = $publishJob.IndexOf('Retain complete sealed release bundle', [StringComparison]::Ordinal)
        $attest = $publishJob.IndexOf('Attest complete sealed release bundle', [StringComparison]::Ordinal)
        $verify = $publishJob.IndexOf('Verify attested bytes before credential acquisition', [StringComparison]::Ordinal)
        $login = $publishJob.IndexOf('Log in to NuGet.org', [StringComparison]::Ordinal)
        $push = $publishJob.IndexOf('Push package', [StringComparison]::Ordinal)
        Assert-True ($authorize -ge 0 -and $authorize -lt $retain -and $retain -lt $attest -and $attest -lt $verify -and $verify -lt $login -and $login -lt $push) 'The release bundle is not sealed, retained, attested, and verified before credential acquisition.'
    }
    Test-Case 'push step re-verifies the sealed bundle immediately before publication' {
        $pushStep = $publishJob.Substring($publishJob.IndexOf('Push package', [StringComparison]::Ordinal))
        $verify = $pushStep.IndexOf('Verify-SealedReleaseBundle.ps1', [StringComparison]::Ordinal)
        $publish = $pushStep.IndexOf('dotnet nuget push ./inbound/package.nupkg', [StringComparison]::Ordinal)
        Assert-True ($verify -ge 0 -and $verify -lt $publish) 'The attested release bundle is not re-verified immediately before publication.'
    }
    Test-Case 'workflow actions use immutable SHA references' {
        $uses = [regex]::Matches($workflow, '(?m)^\s*uses:\s*[^\s]+@([^\s]+)')
        Assert-True ($uses.Count -gt 0) 'No workflow actions were found.'
        foreach ($use in $uses) {
            Assert-True ($use.Groups[1].Value -cmatch '^[0-9a-f]{40}$') "Mutable action reference found: $($use.Value)"
        }
    }
    Test-Case 'workflow carries one bounded and complete release bundle' {
        Assert-True ($workflow -match 'release-bundle/package\.nupkg' -and $workflow -match 'release-bundle/package\.snupkg' -and $workflow -match 'release-bundle/package\.sbom\.cdx\.json') 'The inbound artifact does not contain the exact required release files.'
        Assert-True ($workflow -match '\$packages\.Count -ne 1') 'Ambiguous package output check is missing.'
        Assert-True ($workflow -match '\$symbolPackages\.Count -ne 1' -and $workflow -match '\$sboms\.Count -ne 1') 'Complete bundle cardinality checks are missing.'
        Assert-True ($workflow -match '268435456' -and $workflow -match '8388608' -and $workflow -match '545259520') 'Release bundle size boundaries are missing.'
        Assert-True ($workflow -match 'retention-days:\s*1' -and $workflow -match 'retention-days:\s*90') 'Inbound or sealed artifact retention is not bounded.'
        Assert-True ($publishJob -match 'inbound/release-manifest\.json') 'The deterministic release manifest is not retained and attested.'
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Host "Publisher security tests: $script:Passed passed; $script:Failed failed."
if ($script:Failed -ne 0) { exit 1 }
