<#
.SYNOPSIS
    Abre o Console Virtual (KVM Java) de iDRAC6, iDRAC7 e iDRAC8 sem usar o arquivo .jnlp / Java Web Start.

.DESCRIPTION
    - Baixa os componentes do console (avctKVM.jar e bibliotecas nativas) do proprio iDRAC e guarda em cache\<IP>.
    - iDRAC6: autentica direto com usuario/senha.
    - iDRAC7/8: faz login na interface web e usa o token temporario do viewer.jnlp (como o navegador faz).
    - Libera, apenas para este processo Java, os algoritmos antigos que esses iDRACs exigem (idrac.security).

.PARAMETER Ip
    IP do iDRAC. Se omitido, mostra o menu com os servidores de servidores.txt.

.PARAMETER Usuario
    Usuario do iDRAC (padrao: root).

.PARAMETER Java
    Caminho do java.exe (Java 8). Se omitido, procura automaticamente.
#>
param(
    [string]$Ip,
    [string]$Usuario,
    [string]$Java
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'IdracComum.ps1')

function Show-Banner {
    Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│            DELL iDRAC LEGACY TOOLKIT - KVM VIRTUAL          │" -ForegroundColor Cyan
    Write-Host "│      Console KVM & Diagnostico TLS para iDRAC 6 / 7 / 8     │" -ForegroundColor DarkGray
    Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host "│  Autor:   Gustavo Martins (@GustavoMS0)                     │" -ForegroundColor White
    Write-Host "│  Projeto: https://github.com/GustavoMS0/idrac-legacy-toolkit│" -ForegroundColor DarkGray
    Write-Host "└─────────────────────────────────────────────────────────────┘`n" -ForegroundColor Cyan
}

Show-Banner

function Sair([string]$Mensagem) { Write-Host $Mensagem -ForegroundColor Red; Read-Host 'Enter para sair'; exit 1 }

# --- Java 8 (32 ou 64 bits) ---
if (-not $Java) {
    $Java = @(
        Get-ChildItem "${env:ProgramFiles(x86)}\Java\*\bin\java.exe", "$env:ProgramFiles\Java\*\bin\java.exe",
                      "$env:ProgramFiles\Eclipse Adoptium\*\bin\java.exe", "$env:ProgramFiles\Zulu\*\bin\java.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(jre|jdk)-?1\.8|8\.0|zulu-?8' } | Sort-Object LastWriteTime -Descending | ForEach-Object FullName
        (Get-Command java.exe -ErrorAction SilentlyContinue).Source
    ) | Where-Object { $_ } | Select-Object -First 1
}
if (-not $Java -or -not (Test-Path $Java)) { Sair 'Java 8 nao encontrado. Instale o Java 8 (Oracle JRE 8 ou Temurin/Zulu 8) ou informe -Java <caminho>.' }
$versaoJava = cmd /c "`"$Java`" -version 2>&1"
$arq = if ($versaoJava -match '64-Bit') { 'Win64' } else { 'Win32' }

# --- Escolha do servidor ---
if (-not $Ip) {
    $servidores = Get-ListaServidores
    Write-Host "--- Servidores Disponiveis ---`n" -ForegroundColor DarkCyan
    for ($k = 0; $k -lt $servidores.Count; $k++) { Write-Host ("  {0}) {1,-20} {2}" -f ($k + 1), $servidores[$k].Nome, $servidores[$k].IP) }
    $escolha = Read-Host "`nNumero da lista ou IP"
    if ($escolha -match '^\d+$' -and [int]$escolha -ge 1 -and [int]$escolha -le $servidores.Count) { $Ip = $servidores[[int]$escolha - 1].IP }
    else { $Ip = $escolha.Trim() }
}
if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { Sair "IP invalido: $Ip" }

# --- Componentes do console (cache por IP e arquitetura do Java) ---
$pasta = Join-Path $PSScriptRoot "cache\$Ip-$arq"
$lib   = Join-Path $pasta 'lib'
if (-not (Test-Path (Join-Path $pasta 'avctKVM.jar'))) {
    Write-Host "Baixando componentes do console de $Ip ..."
    New-Item -ItemType Directory -Force $lib | Out-Null

    function Baixar([string]$Nome, [switch]$Opcional) {
        $destino = Join-Path $pasta $Nome
        & curl.exe -sSkf --max-time 60 -o $destino "https://$Ip/software/$Nome" 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
        # iDRAC so com TLS 1.0 (ex.: iDRAC6 com firmware antigo): curl do Windows nao conecta, usa openssl
        try {
            $r = Invoke-OpenSslGet -Ip $Ip -Caminho "/software/$Nome"
            if ($r.Status -eq 200) { [IO.File]::WriteAllBytes($destino, $r.Corpo); return $true }
        } catch { if (-not $Opcional) { Write-Host $_.Exception.Message -ForegroundColor Yellow } }
        Remove-Item $destino -ErrorAction SilentlyContinue
        $false
    }

    foreach ($j in 'avctKVM.jar', "avctKVMIO$arq.jar", "avctVM$arq.jar") {
        if (-not (Baixar $j)) { Remove-Item $pasta -Recurse -Force; Sair "Nao consegui baixar $j de $Ip." }
    }
    # iDRAC7/8: validacao de certificado fica no VMAPI_DLL (nao existe no iDRAC6)
    $null = Baixar "avctVMAPI_DLL$arq.jar" -Opcional

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Get-ChildItem $pasta -Filter "*$arq.jar" | ForEach-Object {
        $zip = [IO.Compression.ZipFile]::OpenRead($_.FullName)
        try {
            $zip.Entries | Where-Object Name -like '*.dll' | ForEach-Object {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path $lib $_.Name), $true)
            }
        } finally { $zip.Dispose() }
    }
}

# --- Credenciais ---
if (-not $Usuario) { $Usuario = Read-Host 'Usuario do iDRAC [root]' }
if (-not $Usuario) { $Usuario = 'root' }
$sec   = Read-Host 'Senha do iDRAC' -AsSecureString
$senha = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))

$argsKvm = @("ip=$Ip", 'kmport=5900', 'vport=5900', "user=$Usuario", "`"passwd=$senha`"",
    'apcp=1', 'version=2', 'vmprivilege=true', "`"helpurl=https://${Ip}:443/help/contents.html`"")

# iDRAC7/8 nao aceita usuario/senha direto no console: login web + token temporario do viewer.jnlp
if (Test-Path (Join-Path $pasta "avctVMAPI_DLL$arq.jar")) {
    Set-AceitaCertificadoIdrac
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "https://$Ip/data/login" -SessionVariable sessao `
                -Body @{ user = $Usuario; password = $senha } -TimeoutSec 30
        $xml = [xml](ConvertTo-TextoResposta $r)
        if ($xml.root.authResult -ne '0') {
            $msg = "Login recusado pelo iDRAC (authResult=$($xml.root.authResult))."
            if ($xml.root.blockingTime -and $xml.root.blockingTime -ne '0') { $msg += " Bloqueado por $($xml.root.blockingTime)s apos tentativas erradas." }
            Sair $msg
        }
        $st1 = [regex]::Match($xml.root.forwardUrl, 'ST1=([0-9a-fA-F]+)').Groups[1].Value
        $jnlp = Invoke-WebRequest -UseBasicParsing -WebSession $sessao -TimeoutSec 30 `
                -Uri "https://$Ip/viewer.jnlp($Ip@0@iDRAC@$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())@ST1=$st1)"
        $argsKvm = @(([xml](ConvertTo-TextoResposta $jnlp)).jnlp.'application-desc'.argument | ForEach-Object { "`"$_`"" })
    } catch {
        Sair "Falha no login web do iDRAC: $($_.Exception.Message)"
    }
}

# --- Abre o console ---
$argsJava = @(
    "-Djava.security.properties=`"$(Join-Path $PSScriptRoot 'idrac.security')`""
    "-Djava.library.path=`"$lib`""
    '-cp', "`"$(Join-Path $pasta 'avctKVM.jar')`""
    'com.avocent.idrac.kvm.Main'
) + $argsKvm
Write-Host "Abrindo console de $Ip ..."
Start-Process -FilePath $Java -ArgumentList $argsJava -WorkingDirectory $pasta -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $pasta 'console_out.log') -RedirectStandardError (Join-Path $pasta 'console_err.log')
$senha = $null
