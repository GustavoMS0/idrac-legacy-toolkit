#Requires -Version 5.1
<#
.SYNOPSIS
    Abre o Console Virtual (KVM Java) de iDRAC6, iDRAC7 e iDRAC8 sem usar o arquivo .jnlp / Java Web Start.

.DESCRIPTION
    - Fixa o certificado TLS do iDRAC na primeira conexao (cache\<IP>\cert.sha256) e recusa certificados diferentes depois.
    - Baixa os componentes do console (avctKVM.jar e bibliotecas nativas) do proprio iDRAC e guarda em cache\<IP>-<arq>,
      com o SHA-256 de cada arquivo (componentes.sha256) para detectar alteracao do cache.
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
$ProgressPreference = 'SilentlyContinue'   # a barra de progresso deixa o Invoke-WebRequest do PS 5.1 muito lento
Set-StrictMode -Version Latest
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

# A pausa fica a cargo do Abrir-ConsoleIdrac.bat (pausa quando o codigo de saida e diferente de zero).
function Sair([string]$Mensagem) { Write-Host $Mensagem -ForegroundColor Red; exit 1 }

# --- Java 8 (32 ou 64 bits) ---
function Get-VersaoJava([string]$Caminho) {
    try { $r = Invoke-Externo -Programa $Caminho -Argumentos @('-version') -TimeoutSeg 30; "$($r.Erro)`n$($r.Saida)" } catch { '' }
}

if ($Java) {
    if (-not (Test-Path $Java -PathType Leaf)) { Sair "Java nao encontrado em: $Java" }
    $versaoJava = Get-VersaoJava $Java
    if ($versaoJava -notmatch 'version "1\.8\.0') { Write-Host "Aviso: $Java nao parece ser Java 8. O console pode nao funcionar." -ForegroundColor Yellow }
} else {
    # Nomes de pasta de Java 8: jre1.8.0_401, jdk1.8.0_202, jdk8u392-b08, jdk-8.0.392.8-hotspot, zulu-8, zulu8.76...
    # (ancorado para nao pegar jdk-18.0 / jdk-18u)
    $padrao = '(^|[^\d])1\.8\.0|(jdk|jre)-?8(u|\.0\.)|(^|[^\d])8u\d+|zulu-?8([^\d]|$)'
    $doPath = Get-Command java.exe -ErrorAction SilentlyContinue
    $candidatos = @(
        Get-ChildItem "${env:ProgramFiles(x86)}\Java\*\bin\java.exe", "$env:ProgramFiles\Java\*\bin\java.exe",
                      "$env:ProgramFiles\Eclipse Adoptium\*\bin\java.exe", "$env:ProgramFiles\Zulu\*\bin\java.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match $padrao } | Sort-Object LastWriteTime -Descending | ForEach-Object FullName
        $(if ($doPath) { $doPath.Source })
    ) | Where-Object { $_ } | Select-Object -Unique
    $Java = $null
    foreach ($c in $candidatos) {
        $v = Get-VersaoJava $c
        if ($v -match 'version "1\.8\.0') { $Java = $c; $versaoJava = $v; break }
    }
    if (-not $Java) { Sair 'Java 8 nao encontrado. Instale o Java 8 (Oracle JRE 8 ou Temurin/Zulu 8) ou informe -Java <caminho>.' }
}
$arq = if ($versaoJava -match '64-Bit') { 'Win64' } else { 'Win32' }

# --- Escolha do servidor ---
if (-not $Ip) {
    $servidores = Get-ListaServidores
    Write-Host "--- Servidores Disponiveis ---`n" -ForegroundColor DarkCyan
    for ($k = 0; $k -lt $servidores.Count; $k++) { Write-Host ("  {0}) {1,-20} {2}" -f ($k + 1), $servidores[$k].Nome, $servidores[$k].IP) }
    $escolha = "$(Read-Host "`nNumero da lista ou IP")".Trim()
    if ($escolha -match '^\d{1,4}$' -and [int]$escolha -ge 1 -and [int]$escolha -le $servidores.Count) { $Ip = $servidores[[int]$escolha - 1].IP }
    else { $Ip = $escolha }
}
if (-not (Test-IpValido $Ip)) { Sair "IP invalido: $Ip" }

# --- Certificado do iDRAC (trust-on-first-use) ---
try { $impressao = Confirm-CertificadoIdrac -Ip $Ip }
catch { Sair $_.Exception.Message }

# --- Componentes do console (cache por IP e arquitetura do Java) ---
$pasta    = Join-Path $PSScriptRoot "cache\$Ip-$arq"
$lib      = Join-Path $pasta 'lib'
$marcador = Join-Path $pasta 'componentes.sha256'   # so existe se o download ficou completo

function Get-ArquivosComponentes {
    @(Get-ChildItem $pasta -Filter '*.jar' -File -ErrorAction SilentlyContinue) +
    @(Get-ChildItem $lib -Filter '*.dll' -File -ErrorAction SilentlyContinue) |
        ForEach-Object { $_.FullName.Substring($pasta.Length + 1) }
}

if (Test-Path $marcador) {
    # Confere se nenhum jar/dll do cache foi alterado, removido ou adicionado desde o download
    $esperados = @{}
    foreach ($linha in Get-Content $marcador) {
        if ($linha -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $esperados[$Matches[2].Trim()] = $Matches[1].ToUpperInvariant() }
    }
    $atuais = @(Get-ArquivosComponentes)
    $problemas = @($atuais | Where-Object { -not $esperados.ContainsKey($_) } | ForEach-Object { "arquivo novo: $_" })
    foreach ($nome in $esperados.Keys) {
        $caminho = Join-Path $pasta $nome
        if (-not (Test-Path $caminho -PathType Leaf)) { $problemas += "faltando: $nome" }
        elseif ((Get-Sha256Arquivo $caminho) -ne $esperados[$nome]) { $problemas += "alterado: $nome" }
    }
    if (-not $esperados.ContainsKey('avctKVM.jar')) { $problemas += 'faltando: avctKVM.jar' }
    if ($problemas.Count) {
        Sair ("O cache dos componentes do console foi modificado ($($problemas -join '; ')).`n" +
              "Por seguranca o console nao sera aberto. Apague a pasta abaixo para baixar de novo do iDRAC:`n  $pasta")
    }
} else {
    Write-Host "Baixando componentes do console de $Ip ..."
    if (Test-Path $pasta) { Remove-Item $pasta -Recurse -Force }   # download anterior incompleto
    New-Item -ItemType Directory -Force $lib | Out-Null

    # Retorna 'ok', 'ausente' (HTTP 404) ou 'erro'
    function Baixar([string]$Nome) {
        $destino = Join-Path $pasta $Nome
        $url = "https://$Ip/software/$Nome"
        $web = Get-ParametrosWebIdrac
        try {
            Invoke-ComCertificadoIdrac -Ip $Ip -Impressao $impressao -Bloco {
                Invoke-WebRequest @web -Uri $url -OutFile $destino -TimeoutSec 60
            }
            return 'ok'
        } catch {
            if ((Get-StatusHttp $_) -eq 404) { return 'ausente' }
        }
        # iDRAC so com TLS 1.0 (ex.: iDRAC6 com firmware antigo): o Windows nao conecta, usa openssl
        try {
            $r = Invoke-OpenSslGet -Ip $Ip -Caminho "/software/$Nome" -Impressao $impressao
            if ($r.Status -eq 200) { [IO.File]::WriteAllBytes($destino, $r.Corpo); return 'ok' }
            if ($r.Status -eq 404) { return 'ausente' }
        } catch {
            if ($_.Exception.Message -match 'MUDOU') { Sair $_.Exception.Message }
            Write-Host $_.Exception.Message -ForegroundColor Yellow
        }
        Remove-Item $destino -ErrorAction SilentlyContinue
        'erro'
    }

    foreach ($j in 'avctKVM.jar', "avctKVMIO$arq.jar", "avctVM$arq.jar") {
        if ((Baixar $j) -ne 'ok') { Remove-Item $pasta -Recurse -Force; Sair "Nao consegui baixar $j de $Ip." }
    }
    # iDRAC7/8: validacao de certificado fica no VMAPI_DLL (nao existe no iDRAC6, que responde 404).
    # Qualquer outra falha nao pode ser confundida com iDRAC6: aborta sem gravar o marcador para tentar de novo.
    if ((Baixar "avctVMAPI_DLL$arq.jar") -eq 'erro') {
        Remove-Item $pasta -Recurse -Force
        Sair "Nao consegui baixar avctVMAPI_DLL$arq.jar de $Ip (erro diferente de 'nao existe'). Tente novamente."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Get-ChildItem $pasta -Filter "*$arq.jar" | ForEach-Object {
        $zip = [IO.Compression.ZipFile]::OpenRead($_.FullName)
        try {
            $zip.Entries | Where-Object Name -like '*.dll' | ForEach-Object {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path $lib $_.Name), $true)
            }
        } finally { $zip.Dispose() }
    }

    # Marcador de download completo + SHA-256 de cada componente (verificado nas proximas execucoes)
    $linhas = Get-ArquivosComponentes | ForEach-Object { '{0}  {1}' -f (Get-Sha256Arquivo (Join-Path $pasta $_)), $_ }
    [IO.File]::WriteAllLines($marcador, [string[]]$linhas)
}

# --- Credenciais ---
if (-not $Usuario) { $Usuario = Read-Host 'Usuario do iDRAC [root]' }
if (-not $Usuario) { $Usuario = 'root' }
$sec  = Read-Host 'Senha do iDRAC' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try { $senha = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

try {
    if (Test-Path (Join-Path $pasta "avctVMAPI_DLL$arq.jar")) {
        # iDRAC7/8 nao aceita usuario/senha direto no console: login web + token temporario do viewer.jnlp
        $web = Get-ParametrosWebIdrac
        try {
            $argsKvm = @(Invoke-ComCertificadoIdrac -Ip $Ip -Impressao $impressao -Bloco {
                $r = Invoke-WebRequest @web -Method Post -Uri "https://$Ip/data/login" -SessionVariable sessao `
                        -Body @{ user = $Usuario; password = $senha } -TimeoutSec 30
                $xml = [xml](ConvertTo-TextoResposta $r)
                $auth = $xml.SelectSingleNode('/root/authResult')
                if (-not $auth -or $auth.InnerText -ne '0') {
                    $msg = "Login recusado pelo iDRAC (authResult=$(if ($auth) { $auth.InnerText }))."
                    $bloqueio = $xml.SelectSingleNode('/root/blockingTime')
                    if ($bloqueio -and $bloqueio.InnerText -ne '0') { $msg += " Bloqueado por $($bloqueio.InnerText)s apos tentativas erradas." }
                    throw $msg
                }
                $destino = $xml.SelectSingleNode('/root/forwardUrl')
                $st1 = [regex]::Match($(if ($destino) { $destino.InnerText } else { '' }), 'ST1=([0-9a-fA-F]+)').Groups[1].Value
                $jnlp = Invoke-WebRequest @web -WebSession $sessao -TimeoutSec 30 `
                        -Uri "https://$Ip/viewer.jnlp($Ip@0@iDRAC@$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())@ST1=$st1)"
                ([xml](ConvertTo-TextoResposta $jnlp)).SelectNodes('//application-desc/argument') | ForEach-Object { $_.InnerText }
            })
        } catch {
            Sair "Falha no login web do iDRAC: $($_.Exception.Message)"
        }
        if (-not $argsKvm.Count) { Sair 'O iDRAC nao devolveu os argumentos do console (viewer.jnlp vazio).' }
    } else {
        # iDRAC6: o cliente da Dell so aceita a senha como argumento de linha de comando (limitacao conhecida,
        # visivel para outros processos do mesmo usuario/administradores enquanto o console estiver aberto).
        $argsKvm = @("ip=$Ip", 'kmport=5900', 'vport=5900', "user=$Usuario", "passwd=$senha",
            'apcp=1', 'version=2', 'vmprivilege=true', "helpurl=https://${Ip}:443/help/contents.html")
    }

    # --- Abre o console ---
    $argsJava = @(
        "-Djava.security.properties=$(Join-Path $PSScriptRoot 'idrac.security')"
        "-Djava.library.path=$lib"
        '-cp', (Join-Path $pasta 'avctKVM.jar')
        'com.avocent.idrac.kvm.Main'
    ) + $argsKvm
    Write-Host "Abrindo console de $Ip ..."
    Start-Process -FilePath $Java -ArgumentList (($argsJava | ForEach-Object { ConvertTo-ArgumentoCmd $_ }) -join ' ') `
        -WorkingDirectory $pasta -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $pasta 'console_out.log') -RedirectStandardError (Join-Path $pasta 'console_err.log')
} finally {
    # Remove as copias em texto da senha desta sessao (a SecureString continua protegida)
    Remove-Variable -Name senha, argsKvm, argsJava -ErrorAction SilentlyContinue
    $sec.Dispose()
}
