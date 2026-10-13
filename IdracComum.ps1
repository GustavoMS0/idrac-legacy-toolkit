# Funcoes compartilhadas pelos scripts do idrac-legacy-toolkit.
# Uso: . (Join-Path $PSScriptRoot 'IdracComum.ps1')

function Get-ListaServidores {
    param([string]$Arquivo = (Join-Path $PSScriptRoot 'servidores.txt'))
    if (-not (Test-Path $Arquivo)) { return @() }
    @(Get-Content $Arquivo | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
        $n, $i = $_ -split '=', 2
        [pscustomobject]@{ Nome = $n.Trim(); IP = $i.Trim() }
    })
}

function Get-OpenSsl {
    $candidatos = @(
        (Get-Command openssl.exe -ErrorAction SilentlyContinue).Source
        "$env:ProgramFiles\Git\usr\bin\openssl.exe"
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe"
    )
    $candidatos | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

function Test-PortaTcp {
    param([string]$Ip, [int]$Porta, [int]$TimeoutMs = 3000)
    $tcp = New-Object Net.Sockets.TcpClient
    try { $tcp.BeginConnect($Ip, $Porta, $null, $null).AsyncWaitHandle.WaitOne($TimeoutMs) -and $tcp.Connected }
    catch { $false }
    finally { $tcp.Close() }
}

# GET HTTPS via openssl s_client. Funciona com iDRACs que so falam TLS 1.0 / cifras antigas,
# coisa que o curl.exe e o Invoke-WebRequest do Windows 11 nao conseguem mais.
function Invoke-OpenSslGet {
    param([string]$Ip, [string]$Caminho = '/', [int]$Porta = 443, [int]$TimeoutSeg = 60)
    $ssl = Get-OpenSsl
    if (-not $ssl) { throw 'openssl nao encontrado. Instale o Git for Windows ou coloque o openssl.exe no PATH.' }

    $psi = New-Object Diagnostics.ProcessStartInfo $ssl
    $psi.Arguments = "s_client -quiet -ign_eof -connect ${Ip}:$Porta -cipher ALL:@SECLEVEL=0"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)
    $mem = New-Object IO.MemoryStream
    $copia = $p.StandardOutput.BaseStream.CopyToAsync($mem)
    $null = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Write("GET $Caminho HTTP/1.0`r`nHost: $Ip`r`nConnection: close`r`n`r`n")
    $p.StandardInput.Flush()
    if (-not $p.WaitForExit($TimeoutSeg * 1000)) { $p.Kill(); throw "Tempo esgotado ao baixar https://${Ip}:$Porta$Caminho" }
    $copia.Wait()
    $bytes = $mem.ToArray()

    # Separa cabecalho e corpo (\r\n\r\n)
    $fim = -1
    for ($k = 0; $k -le $bytes.Length - 4; $k++) {
        if ($bytes[$k] -eq 13 -and $bytes[$k + 1] -eq 10 -and $bytes[$k + 2] -eq 13 -and $bytes[$k + 3] -eq 10) { $fim = $k; break }
    }
    if ($fim -lt 0) { throw "Resposta invalida de https://${Ip}:$Porta$Caminho" }
    $cabecalho = [Text.Encoding]::ASCII.GetString($bytes, 0, $fim)
    $corpo = New-Object byte[] ($bytes.Length - $fim - 4)
    [Array]::Copy($bytes, $fim + 4, $corpo, 0, $corpo.Length)
    [pscustomobject]@{
        Status    = [int]([regex]::Match($cabecalho, '^HTTP/\S+\s+(\d+)').Groups[1].Value)
        Cabecalho = $cabecalho
        Corpo     = $corpo
        Texto     = [Text.Encoding]::UTF8.GetString($corpo)
    }
}

# Testa se o servidor aceita uma versao de TLS / cifra. Retorna o protocolo e a cifra negociados ou $null.
function Test-TlsOpenSsl {
    param([string]$Ip, [int]$Porta = 443, [string]$Versao = 'tls1_2', [string]$Cifra = 'ALL:@SECLEVEL=0')
    $ssl = Get-OpenSsl
    if (-not $ssl) { return $null }
    $saida = cmd /c "`"$ssl`" s_client -connect ${Ip}:$Porta -$Versao -cipher `"$Cifra`" < NUL 2>&1"
    $cifraNeg = [regex]::Match(($saida -join "`n"), 'Cipher is (\S+)').Groups[1].Value
    if (-not $cifraNeg -or $cifraNeg -eq '(NONE)') { return $null }
    [pscustomobject]@{ Protocolo = [regex]::Match(($saida -join "`n"), 'Protocol\s*:\s*(\S+)').Groups[1].Value; Cifra = $cifraNeg }
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

# Ignora certificado autoassinado/vencido em Invoke-WebRequest (PowerShell 5.1)
function Set-AceitaCertificadoIdrac {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not ('AceitaCertIdrac' -as [type])) {
        Add-Type 'using System.Net; using System.Security.Cryptography.X509Certificates;
            public class AceitaCertIdrac : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }'
    }
    [Net.ServicePointManager]::CertificatePolicy = New-Object AceitaCertIdrac
}

# PowerShell 5.1 devolve bytes para tipos de conteudo que nao reconhece como texto (ex.: .jnlp)
function ConvertTo-TextoResposta($Resposta) {
    if ($Resposta.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($Resposta.Content).TrimStart([char]0xFEFF) }
    else { $Resposta.Content }
}
