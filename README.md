# pentest_toolkit.py

Orquestrador único que automatiza a parte de recon/enumeração/detecção da
metodologia descrita em [pentest-metodologia](https://xmatheuscoelhox.github.io/pentest-metodologia/),
módulo por módulo.

**Aviso:** este script executa ferramentas de exploração de verdade
(sqlmap, dalfox, mimikatz, kerberoasting, etc.) contra alvos de verdade.
Rode SOMENTE contra alvos com autorização explícita por escrito (ROE/SOW
assinado ou programa de bug bounty com o asset em escopo) — o próprio
script exige digitar `AUTORIZADO <alvo>` antes de qualquer ação. Testar sem
autorização é crime (Lei 12.737/2012 BR / CFAA EUA / CMA UK).

## Onde fica

```
~/pentest-toolkit/pentest_toolkit.py
```

Roda de dentro dessa pasta (ou de qualquer lugar, o script não depende do
diretório atual).

## Antes de rodar: instale as ferramentas que faltarem

O script detecta sozinho quais ferramentas estão faltando e avisa o comando
de instalação na hora (não trava o script, só pula aquele passo). As
principais usadas: `subfinder`, `httpx`, `katana`, `nuclei`, `gau`,
`waybackurls`, `arjun`, `wafw00f`, `ffuf`, `dalfox`, `sqlmap`, `sslscan`,
`nmap`, `enum4linux`, `ldapsearch`, `rpcclient`, `smbclient`, `apktool`,
`jadx`, `aircrack-ng`, `aws`/`az`/`gcloud` (conforme o módulo). Todas já
documentadas no painel `(?)` do `pentest_metodologia.html`.

Pra enumeração de diretórios (ffuf) funcionar, precisa do **SecLists**
instalado em algum lugar do sistema (o script acha sozinho com `locate`/
`find`, não precisa estar num caminho específico):

```bash
git clone https://github.com/danielmiessler/SecLists ~/SecLists
```

## Como usar

### Modo interativo (menu)

```bash
python3 pentest_toolkit.py
```

Mostra um menu numerado pra escolher o módulo, e depois pergunta só o que
aquele módulo precisa (domínio, IP, caminho do APK, interface wifi, etc.) e
se quer habilitar detecção ativa.

### Modo direto (scriptável)

```bash
python3 pentest_toolkit.py --module web -d alvo.com -u https://alvo.com --active
python3 pentest_toolkit.py --module bugbounty -d alvo.com --program nome-do-programa
python3 pentest_toolkit.py --module api -d alvo.com --active
python3 pentest_toolkit.py --module cloud --provider aws --client "Nome do Cliente" --aws-profile meu-profile
python3 pentest_toolkit.py --module redteam -d alvo.com
python3 pentest_toolkit.py --module mobile --apk caminho/alvo.apk
python3 pentest_toolkit.py --module wireless --iface wlan0
python3 pentest_toolkit.py --module dcpt --ip 10.10.10.10
```

### Lote de URLs (vários alvos de uma vez)

Só pros módulos `web`, `api` e `bugbounty`. Cria um arquivo com um alvo por
linha (URL ou domínio, `#` comenta a linha):

```
alvo1.com
https://alvo2.com
# isso aqui e ignorado
alvo3.com
```

```bash
python3 pentest_toolkit.py --module web --urls-file lista.txt --active
```

A autorização é confirmada **uma vez pro lote inteiro**, não por alvo. Cada
alvo ganha sua própria subpasta e `RESULTADOS.md`, e tudo também soma num
relatório agregado do lote.

### Threads (velocidade das checagens)

As checagens de arquivos sensíveis, endpoints admin/API e buckets S3/GCS do
módulo `web` rodam em paralelo. Por padrão usa 20 requests simultâneos; pra
ajustar:

```bash
python3 pentest_toolkit.py --module web -d alvo.com --threads 40
```

### Wordlist e recursão do ffuf (módulo `web`)

Por padrão o script acha o SecLists sozinho e usa a wordlist **small**
(`--wordlist-size small`, o default). Testado na prática: `medium`/`large`
facilmente estouram o timeout do ffuf contra um alvo externo real, mesmo com
poucas extensões e profundidade baixa — por isso o default é o conservador,
não o mais "completo" na teoria.

```bash
python3 pentest_toolkit.py --module web -d alvo.com --wordlist-size medium
```

`--recursion-depth` controla a profundidade de recursão do ffuf (default
`1`). Cada nível multiplica bastante o número de requisições — `depth=2` com
wordlist grande não termina dentro do timeout em alvos com muitas pastas
reais. Use `--recursion-depth 0` pra desativar recursão por completo:

```bash
python3 pentest_toolkit.py --module web -d alvo.com --recursion-depth 0
```

Se você já sabe o caminho da wordlist de cabeça (ou quer usar uma diferente
do SecLists), pode forçar com `--wordlist /caminho/da/sua/wordlist.txt` — se
o caminho não existir, ele avisa e cai pra detecção automática sozinho.

## Persistência em timeout (retry automático)

Testes reais contra alvo externo mostraram que um `[WRN]` de timeout às
vezes é só uma falha transitória de rede/DNS, não um problema real da
ferramenta — e perder esse passo silenciosamente custava achados reais que
uma segunda tentativa teria pego. Por isso as etapas mais propensas a esse
tipo de falha transitória (recon em paralelo do M1.2 — subfinder+httpx,
katana, gau, waybackurls, arjun, wafw00f —, `sslscan` e `enum4linux`)
**tentam de novo automaticamente uma vez** antes de desistir e logar o
`[WRN]` final. Isso é por operação com timeout (não é retry em caso de
código de saída não-zero, que normalmente é erro real de sintaxe/alvo, não
transitório).

Internamente, todo processo rodado pelo script (`run()`/`run_nmap_live()`)
usa `start_new_session=True` + kill do grupo de processos inteiro no
timeout, pra nunca deixar ferramenta (ex.: `katana`, `arjun`) orfã rodando
em background depois que o script já seguiu pra próxima etapa — confirmado
com `ps aux` antes/depois da correção.

## Progresso em tempo real no terminal

- Operações com total conhecido de antemão (nmap via `--stats-every`,
  checagens Python internas como arquivos sensíveis/buckets) mostram uma
  barra `|###-----|` com **percentual real**, lido direto da própria
  ferramenta ou contado item a item — nunca uma estimativa.
- Operações sem total conhecido (`ffuf`, `gau`, `arjun`, chamadas externas em
  geral) mostram só spinner (`|/-\`) + tempo decorrido, de propósito **sem**
  barra fingindo um progresso que não existe.
- Tags curtas no estilo nuclei/subfinder (`[INF]`/`[OK ]`/`[WRN]`/`[SKP]`)
  com timestamp `hh:mm:ss`, cor por nível, banner compacto de uma linha —
  tudo em ASCII puro (sem blocos Unicode), porque terminal/fonte variam
  entre máquinas de quem for usar o script.

## Dados reais, nunca chute (princípio central do script)

Todo comando sugerido na seção "próximos passos manuais" do relatório é
**montado a partir do que o próprio scan achou de verdade** sempre que
tecnicamente possível — nunca um exemplo genérico apresentado como se fosse
um achado real. Concretamente:

- **`web`**: login/SSRF/upload/sqlmap usam URLs e parâmetros reais, extraídos
  de `recon/gau.txt`, `katana.txt`, `waybackurls.txt` e `enum/arjun_api.txt`
  no momento de gerar o relatório. Se o recon não achou nada daquele tipo, o
  passo diz isso explicitamente ("recon NAO achou X") em vez de inventar um
  endpoint.
- **`api`**: se um spec OpenAPI/Swagger ficar confirmado como exposto
  (status 200 validado, não um 404 genérico de SPA), o script baixa e
  parseia o JSON de verdade e usa os endpoints reais extraídos dele nos
  exemplos de BOLA/mass assignment/webhook. Sem spec confirmado, cai num
  template `<recurso_real>` com aviso "NAO rode sem substituir".
- **`mobile`**: o nome real do pacote Android é extraído do
  `AndroidManifest.xml` já decodificado pelo apktool e usado nos comandos de
  `objection`/`drozer`/`adb` (M5.3/M5.4/M5.6) — nunca o placeholder genérico
  `<package_name>` quando o dado real já está disponível.
- **`dcpt`**: os passos de SQLi manual (M7.7) deixam explícito que esse
  módulo só faz recon de rede/AD (não navega a aplicação web do alvo), então
  não há path/parâmetro real conhecido — o comando é sintaxe de exemplo com
  aviso pra achar a URL real primeiro, não um path inventado.
- **`bugbounty`**: o teste de 2FA bypass (M2.7) instrui a capturar a
  requisição real no Burp primeiro e só então reutilizar essa URL capturada
  — nunca chuta um endpoint tipo `/api/verify-2fa`.

Onde o dado real genuinamente não existe e não tem como existir (BSSID/canal
wifi, que exige escolha em tempo real; credenciais de domínio; grupo de
ameaça do red team), o placeholder fica explícito (`<BSSID>`, `<user>:<pass>`
etc.) — isso não é chute, é o que realmente falta ser informado por quem vai
rodar o comando.

## Scoring de confiança (reduz falso positivo, substitui "juiz de IA")

Todo achado baseado em "o caminho respondeu 200" passa por três camadas
antes de contar como achado de verdade:

1. **Baseline**: pede um caminho aleatório que nunca existiria e compara. Se
   o alvo responde 200 genérico pra tudo (comum em SPA/Angular/React), isso
   já descarta a maioria dos falso positivos.
2. **Validação de conteúdo**: pros que sobraram, busca um pedaço do corpo
   da resposta e confirma que parece o conteúdo esperado de verdade (ex.:
   um `.env`/`.json` não devia vir como página HTML; um bucket S3 público
   precisa ter a assinatura `<ListBucketResult>` de verdade, não só status
   200 de qualquer coisa).
3. **Scoring ponderado por múltiplos sinais** (`score_finding_confidence`):
   cada achado que passou das duas camadas acima ganha uma pontuação
   transparente e logada (motivo por motivo) — penaliza HTML-shell em
   extensão que devia ser dado bruto, body idêntico ao baseline, etc.; soma
   ponto por padrão sensível real no corpo (senha/chave/connection string) e
   por content-type coerente com a extensão. Tiers: **ALTA** (score ≥ 70,
   conta como achado confirmado), **MÉDIA** (40–69, vai pra "revisar
   manualmente" no relatório, não conta sozinho) e **BAIXA** (< 40,
   descartado, mas listado — nunca some).

O que **não passou** fica listado como "REVISAR MANUALMENTE"/"DESCARTADO" no
arquivo de saída (não some, só não conta como achado automático no
relatório final). Aplicado em: arquivos sensíveis, endpoints admin/API,
specs de API, buckets S3/GCS.

Isso não é um "juiz de IA" genérico (um script não consegue julgar como um
modelo julgaria) — é validação estrutural + scoring estatístico específico
por tipo de achado, que é o que realmente é automatizável de forma
confiável e auditável (cada motivo do score fica logado, não é caixa-preta).

## Achados que antes ficavam "escondidos" no arquivo bruto

Além do fluxo normal de detecção, o script agora também conta como achado
qualquer sinal que a própria ferramenta externa já confirmou, mas que
anteriormente ficava só no arquivo `.txt` bruto sem virar linha no
`RESULTADOS.md`:

- `dalfox` (XSS) e `sqlmap` (SQLi, até 5 URLs com parâmetro testadas) em modo
  `--active` do módulo `web`.
- `sslscan`: protocolo ou cifra fraca aceita (SSLv2/v3, RC4, export, etc.).
- `enum4linux`: tanto o caso negado (`NT_STATUS_ACCESS_DENIED`) quanto o caso
  em que a sessão null **funciona de verdade** (usuários de domínio
  enumerados, share listável) — antes só o primeiro caso virava achado,
  mesmo o segundo sendo o sinal mais forte de AD mal configurado.
- `nmap -sC` (NSE scripts) no módulo `dcpt`: toda linha com `VULNERABLE`
  confirmada pelo próprio script NSE vira achado, não fica só no `.nmap`
  bruto.
- Módulo `cloud`: `aws iam list-users`/`list-roles`, `az account show` e
  `gcloud auth list`/`projects list` agora contam no relatório quando
  retornam dado de verdade (antes só a AWS tinha essa paridade).
- Módulo `dcpt`, fallback M7.10 quando SMB null session é negado: bind
  anônimo LDAP e enumeração via `rpcclient` sem credencial, mais download e
  grep por `cpassword` real nos XML do SYSVOL (GPP), não só a listagem de
  arquivos.

## O gate de autorização

Todo módulo, antes de rodar qualquer coisa, pede pra digitar
`AUTORIZADO <alvo>` exatamente. Isso existe de propósito e não tem flag pra
pular no uso normal (só `--skip-auth-gate`, marcado como "uso
interno/CI apenas" — não usar em teste real).

## Módulos disponíveis

| Módulo | O que automatiza | O que fica manual (de propósito) |
|---|---|---|
| `web` | Recon (subfinder/httpx/katana/gau), enumeração (ffuf, arquivos sensíveis, JS secrets, **virtual hosts**, **buckets S3/GCS**), auth passiva (cookies), detecção (nuclei/dalfox/sqlmap em modo detecção) | Força bruta de login/2FA, extração via sqlmap `--dump`, upload de webshell, IDOR, SSRF, deserialização |
| `bugbounty` | Recon contínuo com diff de subdomínios, nuclei nos alvos ativos | Triagem de impacto, 2FA bypass, relatório no formato da plataforma |
| `redteam` | Só leitura de TTPs públicas do MITRE ATT&CK | C2, phishing, evasão — exigem infraestrutura e julgamento dedicados |
| `cloud` | Enumeração credenciada (AWS/Azure/GCP) com as CLIs oficiais | Pacu interativo (privesc), trufflehog em buckets/repos, container escape |
| `mobile` | Análise estática de um APK (apktool + jadx + grep de segredos + extração do pacote real) | Instrumentação dinâmica (frida/objection), precisa de device/emulador |
| `wireless` | Setup do modo monitor | Captura de handshake e crack, exige escolha de BSSID em tempo real |
| `api` | Recon de parâmetros, spec exposta (baixada e parseada se confirmada), rate limit indicativo, nuclei com tag `api` | BOLA em massa com 2 tokens, mass assignment, kid injection no JWT |
| `dcpt` | Recon (varredura híbrida SYN+connect, NSE, enum4linux + fallback LDAP/rpcclient + SYSVOL/GPP) | **Tudo o resto é manual de propósito** — a certificação DCPT proíbe ferramentas de auto-exploit |

### Grupo de ameaça (módulo `redteam`)

O M3.1 pede pra escolher um grupo real do MITRE ATT&CK, mapeado por setor —
não faz sentido emular APT29 (espionagem/governo) num engajamento de banco,
por exemplo:

| # | Grupo | Setor |
|---|---|---|
| 1 | APT29 (Cozy Bear) | Governo / diplomacia |
| 2 | FIN7 | Financeiro / varejo |
| 3 | Wizard Spider | Saúde / educação (ransomware) |
| 4 | Lazarus Group | Fintech / criptomoedas |
| 5 | APT28 (Fancy Bear) | Governo / militar |
| 6 | APT41 | Tecnologia / gaming / supply chain |

No modo interativo, pergunta qual escolher. No modo direto, use o ID MITRE:

```bash
python3 pentest_toolkit.py --module redteam -d alvo.com --apt-group G0046
```

Aceita qualquer ID de grupo do MITRE ATT&CK, não só os 6 do menu (ex.:
`--apt-group G0096`). Sem informar nada e fora do modo interativo, usa
APT29 (G0016) como padrão.

### Cliente/engajamento (módulo `cloud`)

O módulo `cloud` não tem domínio/IP pra identificar o alvo (ele só enumera
a conta já autenticada no ambiente), então `--client "Nome do Cliente"` é
**obrigatório** — nomeia a pasta de resultados e aparece na autorização, em
vez do genérico "alvo". `--aws-profile` é opcional, escolhe qual profile da
AWS CLI usar (sem isso, usa o profile default/já ativo).

## Varredura de portas do módulo `dcpt` (SYN + connect, 2 etapas)

Descoberto em teste real: SYN scan em alta taxa (`--min-rate` alto) através
de NAT (WSL2, VPN corporativa) perde pacotes RST e o nmap confunde "sem
resposta" com "aberto" — chegou a reportar ~300 portas falsas abertas num
host que só tinha 3 de verdade. TCP connect completo em todas as 65535
portas é confiável, mas demora demais. A solução: SYN scan rápido só pra
achar candidatos, depois TCP connect **só nos candidatos** (rápido, porque
são poucas portas) pra confirmar de verdade. Só a lista confirmada conta
como achado; o resto fica registrado como falso positivo descartado.

## Onde ficam os resultados

```
~/pentest/<modulo>/<alvo>/
├── recon/
├── enum/
├── exploit/
├── evidence/
├── session.log       (log completo, com timestamp)
└── RESULTADOS.md      (resumo dos achados + próximos passos manuais)
```

## Isenção de responsabilidade

Este script é disponibilizado como está, pra fins educacionais e de
pentest/bug bounty autorizado. O autor não se responsabiliza por uso
indevido. Use por sua conta e risco, dentro da lei e só com autorização
explícita do dono do alvo.
