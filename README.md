# idrac-legacy-toolkit

Ferramentas em PowerShell para acessar e diagnosticar **iDRAC6, iDRAC7 e iDRAC8** (Dell PowerEdge 11G, 12G e 13G) a partir de um Windows 10/11 atual, onde o navegador e o Java Web Start não funcionam mais com esses equipamentos.

| Script | O que faz |
|---|---|
| `Abrir-ConsoleIdrac.bat` / `.ps1` | Abre o **Console Virtual** (KVM Java) sem o arquivo `.jnlp` |
| `Testar-Idrac.ps1` | Diagnóstico: geração, TLS, cifras da porta do console, certificado e firmware |

## Problemas que resolve

| Sintoma | Causa | O que fazer |
|---|---|---|
| `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` ao abrir o iDRAC | Firmware só fala TLS 1.0 (iDRAC6 1.x) | Atualizar o firmware (iDRAC6 1.99 já tem TLS 1.2). Enquanto isso, use o Firefox com `security.tls.version.min=1` e `security.tls.version.enable-deprecated=true` |
| O `.jnlp` baixado não abre | Nome do arquivo sem extensão `.jnlp`, Java 8 recente bloqueia certificado vencido e algoritmos antigos | `Abrir-ConsoleIdrac.bat` |
| Console Java: `UnsatisfiedLinkError ... X509CertificateJNI` | iDRAC7/8 precisa de `avctVMAPI_DLL*.jar`, que não está no pacote básico | `Abrir-ConsoleIdrac.bat` baixa automaticamente |
| Console Java: `Access denied` / `Reconnecting` no iDRAC7/8 | O console do iDRAC7/8 não aceita usuário/senha diretos, só o token gerado pelo login web | `Abrir-ConsoleIdrac.bat` faz o login web e usa o token |
| Console HTML5: `The network connection has been dropped` | Porta 5900 só com cifras de troca de chave RSA, removidas no Chrome/Edge 131+ | Atualizar o iDRAC8 (2.70.70.70 → 2.86.86.86) ou usar o console Java |
| Certificado vencido | Certificado padrão de fábrica | iDRAC6: `racadm sslresetcfg` e `racadm racreset` via SSH |

## Requisitos

- Windows 10/11 com PowerShell 5.1 (já vem no Windows)
- **Java 8** (Oracle JRE 8, Temurin 8 ou Zulu 8), 32 ou 64 bits. O script detecta sozinho ou use `-Java <caminho>`.
- **Git for Windows** (fornece o `openssl.exe`): usado pelo diagnóstico e para baixar os componentes de iDRACs que só falam TLS 1.0

## Uso

```powershell
git clone https://github.com/GustavoMS0/idrac-legacy-toolkit.git
cd idrac-legacy-toolkit
copy servidores.exemplo.txt servidores.txt   # edite com seus iDRACs
```

### Console Virtual

Duplo clique em `Abrir-ConsoleIdrac.bat` e escolha o servidor. Ou direto:

```powershell
.\Abrir-ConsoleIdrac.ps1 -Ip 192.0.2.10 -Usuario root
```

Na primeira vez para cada iDRAC, os componentes do console são baixados **do próprio iDRAC** para `cache\<IP>-<arquitetura>\`. Se você atualizar o firmware do iDRAC, apague essa pasta.

Os logs do Java ficam em `cache\<IP>-<arquitetura>\console_out.log` e `console_err.log`.

### Diagnóstico

```powershell
.\Testar-Idrac.ps1                                   # todos de servidores.txt
.\Testar-Idrac.ps1 -Ip 192.0.2.10, 192.0.2.11
.\Testar-Idrac.ps1 -Credencial (Get-Credential root) # inclui versão do firmware (iDRAC7/8/9)
```

Exemplo de saída:

```
Nome          : R630-EXEMPLO
Geracao       : iDRAC8 (13G)
TLS443        : TLS1.1 TLS1.2
Console5900   : Sem ECDHE/DHE
CertValidoAte : 2027-01-05
Firmware      : 2.40.40.40
Avisos        : Porta 5900 sem ECDHE: console HTML5 cai no Chrome/Edge 131+ ... | Firmware 2.40.40.40 desatualizado ...
```

## Atualização de firmware (referência)

| iDRAC | Caminho testado | Arquivo enviado em *Update* |
|---|---|---|
| iDRAC6 (R610/R710/T610…) | 1.70 → **1.99** → **2.92** | `firmimg.d6` |
| iDRAC8 (R630/R730…) | 2.40.40.40 → **2.70.70.70** → **2.86.86.86** | `firmimg.d7` |

Baixe os pacotes no site de suporte da Dell (pela Service Tag), extraia o `.exe` com 7-Zip ou `pacote.exe /s /e=C:\pasta` e envie o `firmimg.*` em **iDRAC Settings → Update**. O servidor continua rodando durante a atualização; só o iDRAC reinicia.

## Segurança

- O arquivo `idrac.security` libera algoritmos antigos (TLS 1.0, RC4, 3DES, MD5) **apenas para o processo Java do console**. O Java do sistema não é alterado.
- A senha é pedida de forma oculta e não é gravada em disco. No iDRAC6, ela é passada como argumento para o processo Java, porque é assim que o cliente da Dell funciona.
- iDRAC6/7/8 estão fora de suporte da Dell. Mantenha-os em uma rede ou VLAN de gerência isolada.
- Este repositório não contém nenhum arquivo da Dell. Os componentes do console são baixados do seu próprio iDRAC.

## Licença

MIT
