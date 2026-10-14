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
- **Git for Windows** (fornece o `openssl.exe`): usado pelo diagnóstico e para ler o certificado e baixar os componentes de iDRACs que só falam TLS 1.0

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

Na primeira vez para cada iDRAC, os componentes do console são baixados **do próprio iDRAC** para `cache\<IP>-<arquitetura>\`, junto com o arquivo `componentes.sha256` (SHA-256 de cada `.jar`/`.dll`). Esse arquivo só é gravado quando o download fica completo; se algo falhar no meio, a próxima execução baixa tudo de novo. Nas execuções seguintes os hashes são conferidos e, se algum arquivo do cache tiver sido alterado, removido ou adicionado, o console **não** é aberto. Se você atualizar o firmware do iDRAC, apague essa pasta.

### Certificado fixado na primeira conexão (TOFU)

Os iDRACs usam certificados autoassinados, então não dá para validar pela cadeia do Windows. Em vez de aceitar qualquer certificado, os scripts usam *trust-on-first-use*:

- Na **primeira** conexão com um iDRAC, o SHA-256 do certificado TLS é gravado em `cache\<IP>\cert.sha256` (a mensagem mostra a impressão digital; se quiser, confira com a exibida no próprio iDRAC).
- Nas conexões seguintes (download dos componentes, login web, Redfish do diagnóstico), um certificado diferente é **recusado** com a mensagem “O certificado de … MUDOU”.
- Se o certificado foi trocado de propósito (`racadm sslresetcfg`, atualização de firmware, troca da placa), confira a nova impressão digital e **apague `cache\<IP>\cert.sha256`** para registrar a nova na próxima execução. Apague também `cache\<IP>-<arquitetura>\` se o firmware mudou.

No PowerShell 5.1 (o usado pelo `.bat`) o pin é conferido na própria conexão de cada requisição. No PowerShell 7 o `Invoke-WebRequest` não permite isso: o pin é conferido numa conexão separada logo antes das requisições.

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

- O arquivo `idrac.security` libera algoritmos antigos (TLS 1.0, RC4, 3DES, MD5) **apenas para o processo Java do console**. O Java do sistema não é alterado. A verificação de assinatura dos jars também fica desligada (eles são assinados com algoritmos antigos); a integridade é garantida pelo certificado fixado e pelos hashes do cache (veja acima).
- Os scripts não alteram mais a validação de certificados do processo inteiro: o certificado fixado só é aceito nas requisições ao iDRAC, e a configuração anterior (protocolos TLS e callback) é restaurada logo depois.
- A senha é pedida de forma oculta e não é gravada em disco; o buffer não gerenciado é zerado e a variável com a senha em texto é removida ao final (strings do .NET não podem ser zeradas, então isso reduz, mas não elimina, a exposição em memória). No iDRAC6, ela é passada como argumento para o processo Java (visível para outros processos do mesmo usuário/administradores enquanto o console estiver aberto), porque é assim que o cliente da Dell funciona. No iDRAC7/8 o console recebe só o token temporário do login web.
- IPs informados ou lidos do `servidores.txt` são validados (IPv4, octetos 0–255) e os programas externos (`openssl`, `java`) são chamados sem `cmd /c`.
- iDRAC6/7/8 estão fora de suporte da Dell. Mantenha-os em uma rede ou VLAN de gerência isolada.
- Este repositório não contém nenhum arquivo da Dell. Os componentes do console são baixados do seu próprio iDRAC.

## Licença

MIT
