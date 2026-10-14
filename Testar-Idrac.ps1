#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostica iDRACs antigos: geracao, versoes de TLS, cifras da porta do console, certificado e firmware.

.DESCRIPTION
    Responde as perguntas que costumam aparecer com iDRAC6/7/8 em navegadores modernos:
    - ERR_SSL_VERSION_OR_CIPHER_MISMATCH  -> o iDRAC so fala TLS 1.0/1.1
    - Console HTML5 "The network connection has been dropped" -> porta 5900 sem cifras ECDHE
      (Chrome/Edge 131+ removeram as cifras com troca de chave RSA)
    - Certificado vencido

    Requer openssl.exe (vem com o Git for Windows).

.PARAMETER Ip
    Um ou mais IPs. Se omitido, usa servidores.txt.

.PARAMETER Credencial
    Opcional. Com credencial, le a versao do firmware via Redfish (iDRAC7/8/9).

.EXAMPLE
    .\Testar-Idrac.ps1
    .\Testar-Idrac.ps1 -Ip 192.0.2.10, 192.0.2.11 -Credencial (Get-Credential root)
#>
param(
    [string[]]$Ip,
    [pscredential]$Credencial
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'IdracComum.ps1')

Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│          DELL iDRAC LEGACY TOOLKIT - DIAGNOSTICO TLS        │" -ForegroundColor Cyan
Write-Host "│      Varredura de TLS, cifras, certificados e firmware      │" -ForegroundColor DarkGray
Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "│  Autor:   Gustavo Martins (@GustavoMS0)                     │" -ForegroundColor White
Write-Host "│  Projeto: https://github.com/GustavoMS0/idrac-legacy-toolkit│" -ForegroundColor DarkGray
Write-Host "└─────────────────────────────────────────────────────────────┘`n" -ForegroundColor Cyan

if (-not (Get-OpenSsl)) { Write-Host 'openssl.exe nao encontrado. Instale o Git for Windows.' -ForegroundColor Red; exit 1 }

$alvos = if ($Ip) {
    foreach ($i in $Ip) {
        if (Test-IpValido $i) { [pscustomobject]@{ Nome = $i; IP = $i } }
        else { Write-Host "IP invalido ignorado: $i" -ForegroundColor Yellow }
    }
} else { Get-ListaServidores }
if (-not $alvos) { Write-Host 'Informe -Ip ou crie o servidores.txt (veja servidores.exemplo.txt).' -ForegroundColor Yellow; exit 1 }

$resultado = foreach ($s in $alvos) {
    Write-Host "Testando $($s.Nome) ($($s.IP)) ..."
    $info = [ordered]@{ Nome = $s.Nome; IP = $s.IP }
    $avisos = New-Object Collections.Generic.List[string]

    $info.Porta443  = Test-PortaTcp $s.IP 443
    $info.Porta5900 = Test-PortaTcp $s.IP 5900
    if (-not $info.Porta443) { $avisos.Add('Porta 443 inacessivel'); $info.Avisos = $avisos -join '; '; [pscustomobject]$info; continue }

    $info.Geracao = Get-GeracaoIdrac $s.IP

    $tls = @(foreach ($v in 'tls1', 'tls1_1', 'tls1_2', 'tls1_3') {
        $cifra = if ($v -eq 'tls1_3') { 'ALL' } else { 'ALL:@SECLEVEL=0' }
        if (Test-TlsOpenSsl -Ip $s.IP -Versao $v -Cifra $cifra) { $v -replace 'tls1_?', 'TLS1.' -replace 'TLS1\.$', 'TLS1.0' }
    })
    $info.TLS443 = ($tls -join ' ')
    if ($tls -notcontains 'TLS1.2' -and $tls -notcontains 'TLS1.3') {
        $avisos.Add('So aceita TLS 1.0/1.1: Chrome/Edge/Firefox atuais dao ERR_SSL_VERSION_OR_CIPHER_MISMATCH. Atualize o firmware.')
    }

    if ($info.Porta5900) {
        $fs = Test-TlsOpenSsl -Ip $s.IP -Porta 5900 -Versao 'tls1_2' -Cifra 'ECDHE:DHE:@SECLEVEL=0'
        $info.Console5900 = if ($fs) { "OK ($($fs.Cifra))" } else { 'Sem ECDHE/DHE' }
        if (-not $fs -and $info.Geracao -notmatch 'iDRAC6') {
            $avisos.Add('Porta 5900 sem ECDHE: console HTML5 cai no Chrome/Edge 131+ ("network connection has been dropped"). Atualize o firmware ou use o console Java.')
        }
    }

    # Certificado: validade e conferencia com o pin (trust-on-first-use, cache\<IP>\cert.sha256)
    $impressao = $null
    try {
        $cert = Get-CertificadoIdrac -Ip $s.IP
        $info.CertValidoAte = $cert.NotAfter.ToString('yyyy-MM-dd')
        if ($cert.NotAfter -lt (Get-Date)) { $avisos.Add('Certificado vencido: gere um novo (iDRAC6: racadm sslresetcfg).') }
        $info.CertSHA256 = Get-Sha256Hex $cert.RawData
        Assert-PinIdrac -Ip $s.IP -Impressao $info.CertSHA256
        $impressao = $info.CertSHA256
    } catch {
        $avisos.Add("Certificado: $($_.Exception.Message -replace '\s*\r?\n\s*', ' ')")
    }

    if ($Credencial -and $impressao -and $info.Geracao -notmatch 'iDRAC6') {
        try {
            $web = Get-ParametrosWebIdrac
            $url = "https://$($s.IP)/redfish/v1/Managers/iDRAC.Embedded.1"
            $m = Invoke-ComCertificadoIdrac -Ip $s.IP -Impressao $impressao -Bloco {
                Invoke-RestMethod @web -Uri $url -Credential $Credencial -TimeoutSec 30
            }
            $info.Firmware = $m.FirmwareVersion
            if ($info.Geracao -match 'iDRAC8' -and [version]$m.FirmwareVersion -lt [version]'2.86.86.86') {
                $avisos.Add("Firmware $($m.FirmwareVersion) desatualizado (ultimo iDRAC8: 2.86.86.86; a partir de < 2.70 passe antes pela 2.70.70.70).")
            }
        } catch { $info.Firmware = "erro: $($_.Exception.Message)" }
    }

    $info.Avisos = $avisos -join ' | '
    [pscustomobject]$info
}

$resultado | Format-List
