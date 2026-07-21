Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-CanonicalRepository {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Repository)

    if ($Repository.Length -gt 128 -or $Repository.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase) -or
        $Repository -cnotmatch '^AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
        throw 'The source repository identity is not an approved AtyaLibraries owner/name value.'
    }

    return $Repository
}

function ConvertTo-CanonicalReleaseRef {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Ref)

    if ($Ref.Length -gt 128) {
        throw 'The source ref is too long.'
    }

    $version = if ($Ref -cmatch '^refs/tags/v(.+)$') {
        $Matches[1]
    }
    elseif ($Ref -cmatch '^v(.+)$') {
        $Matches[1]
    }
    else {
        throw 'The source ref is not an immutable release tag.'
    }

    $numericIdentifier = '(?:0|[1-9][0-9]*)'
    $preReleaseIdentifier = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
    if ($version -cnotmatch "^$numericIdentifier\.$numericIdentifier\.$numericIdentifier(?:-$preReleaseIdentifier(?:\.$preReleaseIdentifier)*)?$") {
        throw 'The release tag does not contain a supported semantic version.'
    }

    return [pscustomobject]@{
        Ref = "refs/tags/v$version"
        Version = $version
    }
}

function ConvertTo-SafeRelativePath {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string] $Path,
        [Parameter(Mandatory)][string] $Name,
        [switch] $AllowEmpty
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($AllowEmpty) { return '' }
        throw "$Name is required."
    }

    if ($Path.Length -gt 240 -or $Path.Contains('\') -or $Path.StartsWith('/') -or
        $Path.EndsWith('/') -or $Path.Contains('//') -or
        $Path -cnotmatch '^[A-Za-z0-9._/-]+$') {
        throw "$Name is not a safe repository-relative path."
    }

    $segments = @($Path.Split('/', [StringSplitOptions]::RemoveEmptyEntries))
    if ($segments.Count -eq 0 -or $segments -contains '..' -or $segments -contains '.') {
        throw "$Name is not a safe repository-relative path."
    }

    return ($segments -join '/')
}

function ConvertFrom-PackageRepositoryUrl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Url)

    if ($Url.Length -gt 512) {
        throw 'Package repository metadata is too long.'
    }

    if ($Url -cnotmatch '^https://github\.com/AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:\.git)?/?$') {
        throw 'Package repository metadata is not a supported canonical GitHub URL.'
    }

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $uri) -or
        $uri.Scheme -cne 'https' -or $uri.Host -cne 'github.com' -or
        -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Package repository metadata is not a supported canonical GitHub URL.'
    }

    $path = $uri.AbsolutePath.TrimEnd('/')
    if ($path.EndsWith('.git', [StringComparison]::Ordinal)) {
        $path = $path.Substring(0, $path.Length - 4)
    }

    if ($path -cnotmatch '^/AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
        throw 'Package repository metadata does not identify an approved AtyaLibraries repository.'
    }

    return $path.TrimStart('/')
}

function Read-PackageIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $PackagePath,
        [long] $MaximumPackageBytes = 268435456,
        [int] $MaximumEntries = 4096,
        [long] $MaximumNuspecBytes = 1048576
    )

    try {
        $file = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    }
    catch {
        throw 'The package artifact is missing, empty, oversized, or has an invalid extension.'
    }
    if (-not $file.PSIsContainer -and $file.Extension -ceq '.nupkg' -and
        $file.Length -gt 0 -and $file.Length -le $MaximumPackageBytes) {
        # Continue.
    }
    else {
        throw 'The package artifact is missing, empty, oversized, or has an invalid extension.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        $archive = [IO.Compression.ZipFile]::OpenRead($file.FullName)
    }
    catch {
        throw 'The package artifact is not a valid ZIP archive.'
    }
    try {
        if ($archive.Entries.Count -gt $MaximumEntries) {
            throw 'The package contains too many entries.'
        }

        $nuspecs = @($archive.Entries | Where-Object {
            -not [string]::IsNullOrEmpty($_.Name) -and
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($nuspecs.Count -ne 1) {
            throw 'The package must contain exactly one nuspec.'
        }

        $nuspec = $nuspecs[0]
        if ($nuspec.Length -le 0 -or $nuspec.Length -gt $MaximumNuspecBytes) {
            throw 'The package nuspec is empty or oversized.'
        }

        $stream = $nuspec.Open()
        try {
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $settings.MaxCharactersInDocument = $MaximumNuspecBytes
            $reader = $null
            try {
                $reader = [Xml.XmlReader]::Create($stream, $settings)
                try {
                    $document = [Xml.XmlDocument]::new()
                    $document.XmlResolver = $null
                    $document.Load($reader)
                }
                finally {
                    if ($null -ne $reader) { $reader.Dispose() }
                }
            }
            catch {
                throw 'The package nuspec is not valid safe XML.'
            }
        }
        finally {
            $stream.Dispose()
        }

        if ($null -eq $document.DocumentElement -or $document.DocumentElement.LocalName -cne 'package') {
            throw 'The package nuspec does not contain a package root element.'
        }

        $manager = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespace = $document.DocumentElement.NamespaceURI
        if ($namespace) {
            $manager.AddNamespace('n', $namespace)
            $metadataNodes = @($document.SelectNodes('/n:package/n:metadata', $manager))
        }
        else {
            $metadataNodes = @($document.SelectNodes('/package/metadata'))
        }

        if ($metadataNodes.Count -ne 1) { throw 'The package nuspec must contain exactly one metadata element.' }
        $metadata = $metadataNodes[0]
        $idNodes = @($metadata.ChildNodes | Where-Object {
            $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'id' -and $_.NamespaceURI -ceq $namespace
        })
        $repositoryNodes = @($metadata.ChildNodes | Where-Object {
            $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'repository' -and $_.NamespaceURI -ceq $namespace
        })
        if ($idNodes.Count -ne 1 -or $repositoryNodes.Count -ne 1) {
            throw 'The package nuspec must contain exactly one id and repository element.'
        }

        $packageId = $idNodes[0].InnerText
        if ($packageId -cnotmatch '^Atya\.[A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)+$' -or $packageId.Length -gt 128) {
            throw 'The package id is missing or malformed.'
        }

        $repositoryUrl = $repositoryNodes[0].GetAttribute('url')
        if ([string]::IsNullOrWhiteSpace($repositoryUrl)) {
            throw 'The package repository URL is missing.'
        }

        return [pscustomobject]@{
            PackageId = $packageId
            Repository = ConvertFrom-PackageRepositoryUrl -Url $repositoryUrl
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Read-PublisherAllowlist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $AllowlistPath)

    $file = Get-Item -LiteralPath $AllowlistPath -ErrorAction Stop
    if ($file.Length -le 0 -or $file.Length -gt 1048576) {
        throw 'The publisher allowlist is empty or oversized.'
    }

    try {
        $policy = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    }
    catch {
        throw 'The publisher allowlist is not valid JSON.'
    }

    if ($policy.schemaVersion -cne '1.0.0' -or
        $policy.policyVersion -cnotmatch '^1\.[0-9]+\.[0-9]+$' -or
        $null -eq $policy.packages) {
        throw 'The publisher allowlist uses an unsupported policy schema or version.'
    }

    $entries = @($policy.packages)
    if ($entries.Count -eq 0 -or $entries.Count -gt 512) {
        throw 'The publisher allowlist contains an invalid number of entries.'
    }

    $seenIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenPairs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $id = [string] $entry.packageId
        $repository = [string] $entry.repository
        $defaultBranch = [string] $entry.defaultBranch
        if ($id -cnotmatch '^Atya\.[A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)+$' -or
            $repository -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or
            $defaultBranch -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$') {
            throw 'The publisher allowlist contains malformed metadata.'
        }
        if (-not $seenIds.Add($id) -or -not $seenPairs.Add("$id`n$repository")) {
            throw 'The publisher allowlist contains duplicate or ambiguous package metadata.'
        }
    }

    return $policy
}

function Test-PackageAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Identity,
        [Parameter(Mandatory)][string] $RequestedRepository,
        [Parameter(Mandatory)] $Policy
    )

    $canonicalRequest = ConvertTo-CanonicalRepository -Repository $RequestedRepository
    $requestedSlug = $canonicalRequest.Substring('AtyaLibraries/'.Length)
    if ($Identity.Repository -cne $canonicalRequest) {
        throw 'Package repository provenance does not match the requested repository.'
    }

    $matches = @($Policy.packages | Where-Object { [string] $_.packageId -ceq $Identity.PackageId })
    if ($matches.Count -ne 1) {
        throw 'The derived package id is not uniquely authorized by publisher policy.'
    }
    if ([string] $matches[0].repository -cne $requestedSlug) {
        throw 'The derived package id is not authorized for the requested repository.'
    }

    return [pscustomobject]@{
        PackageId = $Identity.PackageId
        Repository = $canonicalRequest
        PolicyVersion = [string] $Policy.policyVersion
    }
}

Export-ModuleMember -Function ConvertTo-CanonicalRepository, ConvertTo-CanonicalReleaseRef,
    ConvertTo-SafeRelativePath, ConvertFrom-PackageRepositoryUrl, Read-PackageIdentity,
    Read-PublisherAllowlist, Test-PackageAuthorization
