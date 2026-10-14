#Requires -Version 5.1
# Funcoes compartilhadas pelos scripts do idrac-legacy-toolkit.
# Uso: . (Join-Path $PSScriptRoot 'IdracComum.ps1')

$script:PastaCache = Join-Path $PSScriptRoot 'cache'

# Aceita somente IPv4 no formato a.b.c.d com octetos 0-255 (sem zeros a esquerda).
# Todo IP passa por aqui antes de ser usado em caminho de arquivo, URL ou argumento de processo.
function Test-IpValido {
    param([string]$Ip)
    $octeto = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    if ($Ip -notmatch "^$octeto(\.$octeto){3}$") { return $false }
    $endereco = $null
    [ipaddress]::TryParse($Ip, [ref]$endereco) -and $endereco.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
}

function Get-ListaServidores {
    param([string]$Arquivo = (Join-Path $PSScriptRoot 'servidores.txt'))
    if (-not (Test-Path $Arquivo)) { return @() }
    @(Get-Content $Arquivo | Where-Object { $_ -notmatch '^\s*(#|$)' -and $_ -match '=' } | ForEach-Object {
        $n, $i = $_ -split '=', 2
        $i = $i.Trim()
        if (Test-IpValido $i) { [pscustomobject]@{ Nome = $n.Trim(); IP = $i } }
        else { Write-Warning "servidores.txt: IP invalido ignorado na linha '$_'" }
    })
}

function Get-OpenSsl {
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    $candidatos = @(
        $(if ($cmd) { $cmd.Source })
        "$env:ProgramFiles\Git\usr\bin\openssl.exe"
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe"
    )
    $candidatos | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

# Aspas no padrao do Windows (CommandLineToArgvW) para um argumento de linha de comando.
function ConvertTo-ArgumentoCmd([string]$Valor) {
    if ($Valor -and $Valor -notmatch '[\s"]') { return $Valor }
    '"' + ($Valor -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

# Executa um programa sem passar por cmd.exe: argumentos em array, com aspas corretas e tempo limite.
# Retorna codigo de saida, stdout (bytes e texto) e stderr.
function Invoke-Externo {
    param(
        [Parameter(Mandatory)][string]$Programa,
        [string[]]$Argumentos = @(),
        [string]$Entrada,
        [int]$TimeoutSeg = 30
    )
    $psi = New-Object Diagnostics.ProcessStartInfo $Programa
    $psi.Arguments = ($Argumentos | ForEach-Object { ConvertTo-ArgumentoCmd $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)
    try {
        $mem = New-Object IO.MemoryStream
        $copia = $p.StandardOutput.BaseStream.CopyToAsync($mem)
        $erro = $p.StandardError.ReadToEndAsync()
        try {
            if ($Entrada) { $p.StandardInput.Write($Entrada); $p.StandardInput.Flush() }
            $p.StandardInput.Close()
        } catch [IO.IOException] { }   # processo ja terminou
        if (-not $p.WaitForExit($TimeoutSeg * 1000)) {
            try { $p.Kill() } catch { }
            throw "Tempo esgotado executando $([IO.Path]::GetFileName($Programa))."
        }
        $null = $copia.Wait(5000)
        $bytes = $mem.ToArray()
        [pscustomobject]@{
            Codigo = $p.ExitCode
            Bytes  = $bytes
            Saida  = [Text.Encoding]::UTF8.GetString($bytes)
            Erro   = $(if ($erro.Wait(5000)) { $erro.Result } else { '' })
        }
    } finally { $p.Dispose() }
}

function Test-PortaTcp {
    param([string]$Ip, [int]$Porta, [int]$TimeoutMs = 3000)
    $tcp = New-Object Net.Sockets.TcpClient
    try { $tcp.BeginConnect($Ip, $Porta, $null, $null).AsyncWaitHandle.WaitOne($TimeoutMs) -and $tcp.Connected }
    catch { $false }
    finally { $tcp.Close() }
}

# ---------------------------------------------------------------------------------------------
# Certificado do iDRAC: trust-on-first-use (TOFU)
# Na primeira conexao a um iDRAC o SHA-256 do certificado TLS e gravado em cache\<IP>\cert.sha256.
# Nas conexoes seguintes, um certificado diferente e recusado (possivel ataque man-in-the-middle).
# ---------------------------------------------------------------------------------------------

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))) -replace '-', '' } finally { $sha.Dispose() }
}

function Get-Sha256Arquivo([string]$Caminho) {
    Get-Sha256Hex ([IO.File]::ReadAllBytes($Caminho))
}

# Extrai o primeiro certificado PEM de um texto (saida do openssl).
function ConvertFrom-PemCertificado([string]$Texto) {
    $m = [regex]::Match($Texto, '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    if (-not $m.Success) { return $null }
    New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', '')))
}

# Le o certificado que o iDRAC apresenta na porta informada (sem validar).
# Tenta primeiro o SslStream do .NET; se o Windows recusar o protocolo/cifra (ex.: iDRAC so com TLS 1.0), usa openssl.
function Get-CertificadoIdrac {
    param([Parameter(Mandatory)][string]$Ip, [int]$Porta = 443)
    if (-not (Test-IpValido $Ip)) { throw "IP invalido: $Ip" }
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        try {
            if (-not $tcp.BeginConnect($Ip, $Porta, $null, $null).AsyncWaitHandle.WaitOne(10000)) { throw 'tempo esgotado' }
            $tcp.ReceiveTimeout = 15000; $tcp.SendTimeout = 15000
            # O callback roda de forma sincrona nesta mesma thread; so captura o certificado, a decisao e feita pelo pin.
            $aceita = [Net.Security.RemoteCertificateValidationCallback] { $true }
            $tls = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $aceita)
            try {
                $tls.AuthenticateAsClient($Ip, $null, [Security.Authentication.SslProtocols]'Tls, Tls11, Tls12', $false)
                return New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, $tls.RemoteCertificate.GetRawCertData())
            } finally { $tls.Dispose() }
        } finally { $tcp.Close() }
    } catch {
        $ssl = Get-OpenSsl
        if (-not $ssl) { throw "Nao consegui ler o certificado de ${Ip}:$Porta ($($_.Exception.Message)) e o openssl nao foi encontrado." }
        $r = Invoke-Externo -Programa $ssl -Argumentos @('s_client', '-connect', "${Ip}:$Porta", '-cipher', 'ALL:@SECLEVEL=0') -TimeoutSeg 30
        $cert = ConvertFrom-PemCertificado $r.Saida
        if (-not $cert) { throw "Nao consegui ler o certificado de ${Ip}:$Porta." }
        $cert
    }
}

function Get-ArquivoPinIdrac([string]$Ip) { Join-Path (Join-Path $script:PastaCache $Ip) 'cert.sha256' }

# Compara a impressao digital com o pin gravado (ou grava na primeira vez). Lanca excecao se divergir.
function Assert-PinIdrac {
    param([Parameter(Mandatory)][string]$Ip, [Parameter(Mandatory)][string]$Impressao)
    $arquivo = Get-ArquivoPinIdrac $Ip
    if (Test-Path $arquivo) {
        $esperado = ((Get-Content $arquivo -TotalCount 1) -replace '\s', '').ToUpperInvariant()
        if ($esperado -ne $Impressao.ToUpperInvariant()) {
            throw ("O certificado de $Ip MUDOU desde a primeira conexao (possivel ataque man-in-the-middle).`n" +
                   "  Esperado: $esperado`n  Recebido: $Impressao`n" +
                   "Se o certificado foi trocado de proposito (sslresetcfg, atualizacao de firmware, troca de placa), " +
                   "confira a impressao digital no proprio iDRAC e apague o arquivo:`n  $arquivo")
        }
    } else {
        New-Item -ItemType Directory -Force (Split-Path $arquivo) | Out-Null
        [IO.File]::WriteAllText($arquivo, $Impressao.ToUpperInvariant() + "`r`n")
        Write-Host "Primeira conexao com ${Ip}: certificado registrado (SHA-256 $Impressao)." -ForegroundColor Yellow
    }
}

# Le o certificado atual do iDRAC e confere com o pin (TOFU). Retorna a impressao digital SHA-256 (hex).
function Confirm-CertificadoIdrac {
    param([Parameter(Mandatory)][string]$Ip)
    $cert = Get-CertificadoIdrac -Ip $Ip
    $impressao = Get-Sha256Hex $cert.RawData
    Assert-PinIdrac -Ip $Ip -Impressao $impressao
    $impressao
}

# GET HTTPS via openssl s_client. Funciona com iDRACs que so falam TLS 1.0 / cifras antigas,
# coisa que o curl.exe e o Invoke-WebRequest do Windows 11 nao conseguem mais.
# Com -Impressao, o certificado da PROPRIA conexao usada no download (lido da sessao TLS salva) precisa bater com o pin.
function Invoke-OpenSslGet {
    param([string]$Ip, [string]$Caminho = '/', [int]$Porta = 443, [int]$TimeoutSeg = 60, [string]$Impressao)
    if (-not (Test-IpValido $Ip)) { throw "IP invalido: $Ip" }
    if ($Caminho -notmatch '^/[\x21-\x7E]*$') { throw "Caminho invalido: $Caminho" }
    $ssl = Get-OpenSsl
    if (-not $ssl) { throw 'openssl nao encontrado. Instale o Git for Windows ou coloque o openssl.exe no PATH.' }

    $sessao = [IO.Path]::GetTempFileName()
    try {
        $r = Invoke-Externo -Programa $ssl -TimeoutSeg $TimeoutSeg `
                -Argumentos @('s_client', '-quiet', '-ign_eof', '-connect', "${Ip}:$Porta", '-cipher', 'ALL:@SECLEVEL=0', '-sess_out', $sessao) `
                -Entrada "GET $Caminho HTTP/1.0`r`nHost: $Ip`r`nConnection: close`r`n`r`n"
        if ($Impressao) {
            $s = Invoke-Externo -Programa $ssl -Argumentos @('sess_id', '-in', $sessao, '-cert')
            $cert = ConvertFrom-PemCertificado $s.Saida
            if (-not $cert) { throw "Nao consegui confirmar o certificado da conexao com $Ip." }
            Assert-PinIdrac -Ip $Ip -Impressao (Get-Sha256Hex $cert.RawData)
        }
    } finally { Remove-Item $sessao -ErrorAction SilentlyContinue }
    $bytes = $r.Bytes

    # Separa cabecalho e corpo (\r\n\r\n)
    $fim = -1
    for ($k = 0; $k -le $bytes.Length - 4; $k++) {
        if ($bytes[$k] -eq 13 -and $bytes[$k + 1] -eq 10 -and $bytes[$k + 2] -eq 13 -and $bytes[$k + 3] -eq 10) { $fim = $k; break }
    }
    if ($fim -lt 0) { throw "Resposta invalida de https://${Ip}:$Porta$Caminho" }
    $cabecalho = [Text.Encoding]::ASCII.GetString($bytes, 0, $fim)
    $corpo = New-Object byte[] ($bytes.Length - $fim - 4)
    [Array]::Copy($bytes, $fim + 4, $corpo, 0, $corpo.Length)
    $status = [regex]::Match($cabecalho, '^HTTP/\S+\s+(\d+)').Groups[1].Value
    [pscustomobject]@{
        Status    = $(if ($status) { [int]$status } else { 0 })
        Cabecalho = $cabecalho
        Corpo     = $corpo
        Texto     = [Text.Encoding]::UTF8.GetString($corpo)
    }
}

# Testa se o servidor aceita uma versao de TLS / cifra. Retorna o protocolo e a cifra negociados ou $null.
function Test-TlsOpenSsl {
    param([string]$Ip, [int]$Porta = 443, [ValidateSet('tls1', 'tls1_1', 'tls1_2', 'tls1_3')][string]$Versao = 'tls1_2', [string]$Cifra = 'ALL:@SECLEVEL=0')
    if (-not (Test-IpValido $Ip)) { throw "IP invalido: $Ip" }
    $ssl = Get-OpenSsl
    if (-not $ssl) { return $null }
    try { $r = Invoke-Externo -Programa $ssl -Argumentos @('s_client', '-connect', "${Ip}:$Porta", "-$Versao", '-cipher', $Cifra) -TimeoutSeg 20 }
    catch { return $null }
    $saida = $r.Saida + "`n" + $r.Erro
    $cifraNeg = [regex]::Match($saida, 'Cipher is (\S+)').Groups[1].Value
    if (-not $cifraNeg -or $cifraNeg -eq '(NONE)') { return $null }
    [pscustomobject]@{ Protocolo = [regex]::Match($saida, 'Protocol\s*:\s*(\S+)').Groups[1].Value; Cifra = $cifraNeg }
}

# Identifica a geracao do iDRAC sem autenticacao.
function Get-GeracaoIdrac {
    param([string]$Ip)
    try {
        $raiz = Invoke-OpenSslGet -Ip $Ip -Caminho '/' -TimeoutSeg 20
        if ($raiz.Cabecalho -match 'Server:\s*Mbedthis') { return 'iDRAC6 (11G)' }
        $gen = Invoke-OpenSslGet -Ip $Ip -Caminho '/data?get=prodServerGen' -TimeoutSeg 20
        switch -Regex ($gen.Texto) {
            '<prodServerGen>12G' { return 'iDRAC7 (12G)' }
            '<prodServerGen>13G' { return 'iDRAC8 (13G)' }
        }
        if ((Invoke-OpenSslGet -Ip $Ip -Caminho '/restgui/start.html' -TimeoutSeg 20).Status -eq 200) { return 'iDRAC9+ (14G ou mais novo)' }
    } catch { }
    'Desconhecida'
}

# ---------------------------------------------------------------------------------------------
# Requisicoes web (Invoke-WebRequest / Invoke-RestMethod) aceitando SOMENTE o certificado fixado do iDRAC.
# ---------------------------------------------------------------------------------------------

if ($PSVersionTable.PSEdition -ne 'Core' -and -not ('IdracPin' -as [type])) {
    # PowerShell 5.1: callback em C# (callbacks em scriptblock rodam em outra thread e derrubam o PowerShell).
    # Aceita o certificado apenas se o host da requisicao tiver pin registrado e o SHA-256 bater.
    # Requisicoes para outros hosts seguem a validacao normal do Windows.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class IdracPin
{
    public static readonly ConcurrentDictionary<string, string> Pins =
        new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public static readonly RemoteCertificateValidationCallback Callback = Validar;

    public static bool Validar(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors erros)
    {
        HttpWebRequest req = sender as HttpWebRequest;
        string esperado;
        if (req == null || !Pins.TryGetValue(req.RequestUri.Host, out esperado))
            return erros == SslPolicyErrors.None;
        if (cert == null) return false;
        using (SHA256 sha = SHA256.Create())
        {
            string atual = BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-", "");
            return string.Equals(atual, esperado, StringComparison.OrdinalIgnoreCase);
        }
    }
}
'@
}

# Parametros extras para Invoke-WebRequest/Invoke-RestMethod contra o iDRAC.
# PowerShell 7 (HttpClient) ignora o ServicePointManager: usa -SkipCertificateCheck so nestas chamadas,
# e o pin e conferido por Confirm-CertificadoIdrac antes (em conexao separada).
function Get-ParametrosWebIdrac {
    $p = @{ UseBasicParsing = $true }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $p.SkipCertificateCheck = $true
        $p.SslProtocol = 'Tls, Tls11, Tls12'
    }
    $p
}

# Executa $Bloco com TLS 1.0/1.1/1.2 habilitados e o certificado do iDRAC fixado; restaura tudo ao final.
function Invoke-ComCertificadoIdrac {
    param([Parameter(Mandatory)][string]$Ip, [Parameter(Mandatory)][string]$Impressao, [Parameter(Mandatory)][scriptblock]$Bloco)
    if ($PSVersionTable.PSEdition -eq 'Core') { return & $Bloco }

    $protocoloAnterior = [Net.ServicePointManager]::SecurityProtocol
    $callbackAnterior  = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        # Firmwares antigos de iDRAC7/8 so falam TLS 1.0/1.1
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        [IdracPin]::Pins[$Ip] = $Impressao
        [Net.ServicePointManager]::ServerCertificateValidationCallback = [IdracPin]::Callback
        & $Bloco
    } finally {
        $removido = $null
        $null = [IdracPin]::Pins.TryRemove($Ip, [ref]$removido)
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $callbackAnterior
        [Net.ServicePointManager]::SecurityProtocol = $protocoloAnterior
    }
}

# Codigo HTTP de um erro do Invoke-WebRequest (0 se nao houve resposta, ex.: falha de TLS).
function Get-StatusHttp($Erro) {
    $resp = $Erro.Exception.PSObject.Properties['Response']
    if ($resp -and $resp.Value) { try { return [int]$resp.Value.StatusCode } catch { } }
    0
}

# PowerShell 5.1 devolve bytes para tipos de conteudo que nao reconhece como texto (ex.: .jnlp)
function ConvertTo-TextoResposta($Resposta) {
    if ($Resposta.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($Resposta.Content).TrimStart([char]0xFEFF) }
    else { $Resposta.Content }
}
