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
. (Join-Path $PSScriptRoot 'IdracComum.ps1')

if (-not (Get-OpenSsl)) { Write-Host 'openssl.exe nao encontrado. Instale o Git for Windows.' -ForegroundColor Red; exit 1 }

$alvos = if ($Ip) { $Ip | ForEach-Object { [pscustomobject]@{ Nome = $_; IP = $_ } } } else { Get-ListaServidores }
if (-not $alvos) { Write-Host 'Informe -Ip ou crie o servidores.txt (veja servidores.exemplo.txt).' -ForegroundColor Yellow; exit 1 }

$resultado = foreach ($s in $alvos) {
    Write-Host "Testando $($s.Nome) ($($s.IP)) ..."
    $info = [ordered]@{ Nome = $s.Nome; IP = $s.IP }
    $avisos = New-Object Collections.Generic.List[string]

    $info.Porta443  = Test-PortaTcp $s.IP 443
    $info.Porta5900 = Test-PortaTcp $s.IP 5900
    if (-not $info.Porta443) { $avisos.Add('Porta 443 inacessivel'); $info.Avisos = $avisos -join '; '; [pscustomobject]$info; continue }

    $info.Geracao = Get-GeracaoIdrac $s.IP

    $tls = foreach ($v in 'tls1', 'tls1_1', 'tls1_2', 'tls1_3') {
        $cifra = if ($v -eq 'tls1_3') { 'ALL' } else { 'ALL:@SECLEVEL=0' }
        if (Test-TlsOpenSsl -Ip $s.IP -Versao $v -Cifra $cifra) { $v -replace 'tls1_?', 'TLS1.' -replace 'TLS1\.$', 'TLS1.0' }
    }
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

    $ssl = Get-OpenSsl
    $fim = cmd /c "`"$ssl`" s_client -connect $($s.IP):443 -cipher ALL:@SECLEVEL=0 < NUL 2>NUL | `"$ssl`" x509 -noout -enddate 2>NUL"
    if ("$fim" -match 'notAfter=(\w{3})\s+(\d+)\s+([\d:]+)\s+(\d{4})') {
        $validade = [datetime]::ParseExact("$($Matches[1]) $($Matches[2]) $($Matches[3]) $($Matches[4])", 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture)
        $info.CertValidoAte = $validade.ToString('yyyy-MM-dd')
        if ($validade -lt (Get-Date)) { $avisos.Add('Certificado vencido: gere um novo (iDRAC6: racadm sslresetcfg).') }
    }

    if ($Credencial -and $info.Geracao -notmatch 'iDRAC6') {
        try {
            Set-AceitaCertificadoIdrac
            $m = Invoke-RestMethod -Uri "https://$($s.IP)/redfish/v1/Managers/iDRAC.Embedded.1" -Credential $Credencial -TimeoutSec 30
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
