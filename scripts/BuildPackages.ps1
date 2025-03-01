<#
.SYNOPSIS
    Build packages from compiled dlls.
.PARAMETER Configuration
    The build configuration: Release or Debug. Default=Release
#>

[CmdletBinding()]
param(
    [string]
    [ValidateSet("Debug", "Release")]
    $Configuration="Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))
$RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path

function Exit-WithFailureMessage($scriptName, $message) {
    Write-Information "${scriptName}: $message"
    Write-Information "$scriptName FAILED."
    exit 1
}

dotnet tool update --global nbgv --version 3.3.37
$env:Path = "$env:Path;$env:USERPROFILE/.dotnet/tools"
$tag = nbgv get-version --variable NugetPackageVersion

if ($env:MsuiNugetPackageVersion) {
    Write-Information "Overriding Nerdbank.GitVersioning assigned PackageVersion: $tag -> $env:MsuiNugetPackageVersion."
    $tag = $env:MsuiNugetPackageVersion
}

dotnet pack src\Microsoft.Security.Utilities.Packages.sln -c $Configuration -p:IncludeSymbols=true -p:SymbolPackageFormat=snupkg /p:Version=$tag -o "$RepoRoot\bld\nupkg\AnyCPU_$Configuration"
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of Microsoft.Security.Utilities.Packages.sln failed."
}

Write-Information "$ScriptName SUCCEEDED."
