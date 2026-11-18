# ScamShield server launcher - OpenRouter Free
# Keys are entered as secure prompts and kept only in this PowerShell process.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Convert-SecureStringToPlainText([System.Security.SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Restore-EnvValue([string]$Name, [string]$PreviousValue) {
    if ($null -eq $PreviousValue) {
        Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -Path "Env:$Name" -Value $PreviousValue
    }
}

$oldProvider = $env:AI_PROVIDER
$oldOpenRouterKey = $env:OPENROUTER_API_KEY
$oldAdminKey = $env:ADMIN_KEY

try {
    Write-Host ""
    Write-Host "=== ScamShield - OpenRouter Free ===" -ForegroundColor Cyan
    Write-Host "Model router: openrouter/free (chi chon model mien phi)"
    Write-Host ""

    $openRouterSecure = Read-Host "Nhap OpenRouter API Key" -AsSecureString
    $openRouterKey = Convert-SecureStringToPlainText $openRouterSecure
    if ([string]::IsNullOrWhiteSpace($openRouterKey)) {
        throw "OpenRouter API Key khong duoc de trong."
    }

    $adminSecure = Read-Host "Nhap Admin Key" -AsSecureString
    $adminKey = Convert-SecureStringToPlainText $adminSecure
    if ([string]::IsNullOrWhiteSpace($adminKey)) {
        throw "Admin Key khong duoc de trong."
    }

    $env:AI_PROVIDER = "openrouter"
    $env:OPENROUTER_API_KEY = $openRouterKey
    $env:ADMIN_KEY = $adminKey

    $python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $python)) {
        Write-Host "Chua co .venv, dang tao moi truong Python..." -ForegroundColor Yellow
        python -m venv (Join-Path $PSScriptRoot ".venv")
        if ($LASTEXITCODE -ne 0) { throw "Khong tao duoc .venv." }
    }

    if (-not (Test-Path -LiteralPath $python)) {
        throw "Khong tim thay Python trong .venv. Hay cai Python 3 truoc."
    }

    Write-Host "Dang kiem tra thu vien..." -ForegroundColor Yellow
    & $python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "Khong cai duoc thu vien server." }

    Write-Host ""
    Write-Host "OpenRouter da duoc chon lam AI provider." -ForegroundColor Green
    Write-Host "Trang quan tri: http://127.0.0.1:8000/admin"
    Write-Host "Nhan Ctrl+C de dung server."
    Write-Host ""

    & $python (Join-Path $PSScriptRoot "server.py")
    if ($LASTEXITCODE -ne 0) {
        throw "Server da dung voi ma loi $LASTEXITCODE."
    }
}
catch {
    Write-Host ""
    Write-Host ("Loi: " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
finally {
    $openRouterKey = $null
    $adminKey = $null
    $openRouterSecure = $null
    $adminSecure = $null
    Restore-EnvValue "AI_PROVIDER" $oldProvider
    Restore-EnvValue "OPENROUTER_API_KEY" $oldOpenRouterKey
    Restore-EnvValue "ADMIN_KEY" $oldAdminKey
}
