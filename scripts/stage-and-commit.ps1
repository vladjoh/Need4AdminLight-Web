# Run from PowerShell AFTER installing Git: https://git-scm.com/download/win
#
# From repo root (the folder that contains README.md, SECURITY.md, and src\):
#   .\scripts\stage-and-commit.ps1 [-Message "your message"] [-Push]
#
# .gitignore already excludes bin/, obj/, publish/, etc.

param(
    [string] $Message = "Update Need4Admin Light source",
    [switch] $Push
)

$ErrorActionPreference = "Stop"
# This file lives in <repo>\scripts\ — repo root is one level up
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

if (-not (Test-Path (Join-Path $repoRoot "README.md"))) {
    Write-Error "README.md not found. Run this script from the Need4AdminLight-Website repo (folder with README.md)."
}

$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Write-Error "Git is not installed or not on PATH. Install from https://git-scm.com/download/win then reopen the terminal."
}

if (-not (Test-Path ".git")) {
    Write-Host "Initializing git repository..."
    git init
    Write-Host "Add your remote, e.g.: git remote add origin https://github.com/vladjoh/Need4AdminLight-Web.git"
}

git add -A
git status

# Exit 0 = index matches HEAD (nothing new staged); 1 = there are staged changes
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Nothing to commit (no staged changes)."
} else {
    git commit -m $Message
    Write-Host "Committed: $Message"
}

if ($Push) {
    $branch = git rev-parse --abbrev-ref HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or $branch -eq "HEAD") {
        git branch -M main
        $branch = "main"
    }
    git push -u origin $branch
}
