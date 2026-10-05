# ThurSec — Backlog de Produto e Roadmap

> Documento vivo de produto. Organiza o trabalho em épicos, user stories e
> critérios de aceite. Revisado a cada fechamento de sprint pelo PO.

---

## Fronteira ética do produto (inegociável)

ThurSec é um toolkit de **security assessment para uso autorizado e defensivo**.
Serve para o que você possui ou foi contratado/autorizado por escrito a testar:
sua própria infraestrutura, pentests contratados, CTFs e laboratórios.

**O que ThurSec NÃO terá — por decisão de produto, não por falta de tempo:**

| Categoria vetada | Por que fica de fora | Versão legítima que entra no roadmap |
| --- | --- | --- |
| **DoS / DDoS** | Causa indisponibilidade; dano sem consentimento. | **Teste de resiliência / carga** na *própria* infra, com orçamento de erro definido. |
| **Phishing / roubo de credencial** | Engana e lesa terceiros. | **Simulação de conscientização** só para os *próprios* funcionários, com autorização explícita. |
| **RAT / acesso não autorizado** | Controle de máquina sem consentimento. | **Agente de endpoint** da *própria* frota, instalado e gerenciado pela organização. |
| **Alvo em massa** (varrer a internet) | Escala o abuso; sem escopo. | **Attack Surface Management (ASM)** dos *próprios* ativos, a partir de um inventário declarado. |

Toda contribuição respeita o **scope gate**: módulos `ACTIVE`/`INTRUSIVE` só
rodam contra alvos listados num `scope.yaml` autorizado. Módulos `PASSIVE`
rodam livres (não enviam pacotes ao alvo). Um PR que fure essa fronteira é
recusado no review, independentemente da qualidade técnica.

---

## Legenda de status

- `[FEITO]` — já no `main`, com testes.
- `[EM DEV]` — em desenvolvimento neste ciclo.
- `[PRÓXIMO]` — priorizado para o próximo sprint.
- `[BACKLOG]` — aceito no roadmap, ainda sem data.

---

## Estado atual (baseline no `main`)

- `[FEITO]` **Núcleo de plugins** (`thursec/core/`): `Finding`/`Severity`,
  `Scope` + scope gate, `Module` base + `Category`/`Intensity`, `CommandRunner`
  async sem shell com timeout, `Engine`/`Registry` com descoberta automática,
  `RunContext`, relatórios JSON/Markdown/HTML.
- `[FEITO]` **CLI** (`thursec/cli.py`): `list`, `run` (por `-m` módulo, `-c`
  categoria, ou passivo por padrão), saída `-o`; persistência opt-in com
  `run --store`, comando `diff` entre runs (PLAT1) e comando `dashboard`
  (HTML de postura sobre o store, PLAT2).
- `[FEITO]` **Validador de target compartilhado** (`thursec/core/target.py`) —
  defesa contra *argument injection* em alvos passados a binários externos;
  usado por `recon.nmap` e `vuln.nuclei`.
- `[FEITO]` **Findings store histórico** (`thursec/core/store.py`, PLAT1) —
  SQLite local, dedup por fingerprint (first_seen/last_seen) e diff entre scans.
- `[FEITO]` **Dashboard de postura** (`thursec/core/dashboard.py`, PLAT2) —
  render HTML de tendência/diff/severidade sobre o findings store, exposto pelo
  comando `dashboard` da CLI.
- `[FEITO]` **10 módulos no `main`:**
  - `recon.ct_subdomains` (`PASSIVE`) — subdomínios via Certificate Transparency.
  - `recon.dns` (`PASSIVE`) — resolução/enumeração DNS via DNS-over-HTTPS.
  - `recon.whois` (`PASSIVE`) — registro de domínio via RDAP/WHOIS.
  - `recon.nmap` (`ACTIVE`, scope-gated) — port/service scan via `nmap`.
  - `vuln.nuclei` (`ACTIVE`, scope-gated) — wrapper do `nuclei`.
  - `vuln.http_methods` (`ACTIVE`, scope-gated) — métodos HTTP perigosos e
    exposição de informação (read-only).
  - `deps_secrets.secret_scan` (`PASSIVE`) — scanner de segredos por padrões.
  - `deps_secrets.dep_audit` (`PASSIVE`) — auditoria de dependências via OSV.
  - `config_audit.supabase` (`PASSIVE`) — auditoria de postura Supabase.
  - `config_audit.tls_headers` (`ACTIVE`) — expiração de cert, TLS e headers HTTP.
- `[FEITO]` **TUI em Textual** (UX1.1) — navegação de módulos e findings sobre o
  engine, respeitando o scope gate.
- `[FEITO]` **Cobertura de testes** do núcleo (scope, findings, engine) e dos
  módulos entregues.

---

# ÉPICOS POR FRENTE

As quatro frentes são as categorias do produto (`Category` em
`thursec/core/module.py`): `recon`, `vuln`, `deps_secrets`, `config_audit`.
A quinta seção é a visão de **plataforma unificada** — as versões legítimas das
ideias vetadas acima.

---

## Frente 1 — RECON (reconhecimento)

### Épico R1 — Descoberta passiva de superfície
**Objetivo:** mapear a superfície exposta de um alvo autorizado usando apenas
fontes públicas, sem enviar pacotes ao alvo (`PASSIVE`, roda sem scope gate).
**Valor:** dá o inventário inicial de onde procurar — o primeiro passo de todo
assessment, e seguro de rodar por ser passivo.

- **R1.1 `[FEITO]` Enumeração de subdomínios via Certificate Transparency**
  (`recon.ct_subdomains`)
  - *Como* analista, *quero* listar subdomínios de um domínio consultando logs
    de CT públicos, *para* conhecer a superfície sem tocar no alvo.
  - **Critério de aceite:** dado um domínio, retorna `Finding`s `INFO` com os
    subdomínios únicos encontrados; `intensity = PASSIVE`; sem scope gate;
    respeita timeout do runner; deduplica resultados; funciona offline-safe
    (falha de rede vira erro tratado, não exceção).

- **R1.2 `[FEITO]` Consulta WHOIS / RDAP** (`recon.whois`)
  - *Como* analista, *quero* dados de registro do domínio (registrante, datas,
    nameservers), *para* contextualizar o alvo.
  - **Critério de aceite:** `PASSIVE`; parse de RDAP com fallback; findings
    `INFO` com evidência bruta preservada.

- **R1.3 `[FEITO]` Resolução DNS e enumeração de registros** (`recon.dns`)
  - *Como* analista, *quero* registros A/AAAA/MX/TXT/CNAME do alvo, *para*
    entender a topologia.
  - **Critério de aceite:** marcado `PASSIVE` (consulta a resolvers públicos,
    não ao alvo); findings `INFO`; flag de registros sensíveis (ex.: SPF/DMARC
    ausentes → `LOW`).

### Épico R2 — Enumeração ativa de serviços
**Objetivo:** identificar portas e serviços vivos em alvos **autorizados**.
**Valor:** transforma o inventário passivo em alvos concretos para as frentes de
vuln e config.

- **R2.1 `[BACKLOG]` Port scan TCP com asyncio**
  - *Como* analista, *quero* escanear portas comuns de um host em escopo, *para*
    saber o que está exposto.
  - **Critério de aceite:** `ACTIVE` → scope-gated; concorrência limitada;
    timeout por porta; findings `INFO`/`LOW` por serviço; recusa alvo fora do
    `scope.yaml`.

- **R2.2 `[BACKLOG]` Banner grabbing / fingerprint de serviço**
  - *Como* analista, *quero* identificar produto e versão por banner, *para*
    priorizar o que investigar.
  - **Critério de aceite:** `ACTIVE`; evidência = banner cru; não assume que o
    banner é confiável (apenas reporta).

- **R2.3 `[FEITO]` Port/service scan via `nmap`**
  - *Como* analista, *quero* rodar `nmap` contra um host em escopo e receber
    portas/serviços como `Finding`s, *para* ter o primeiro módulo `ACTIVE` "de
    verdade" que exercita o scope gate de ponta a ponta.
  - **Critério de aceite:** `ACTIVE` → scope-gated (recusa alvo fora do
    `scope.yaml`); `requires_tools = ("nmap",)` com pré-flight e dica de
    instalação; invoca via `CommandRunner` (sem shell) com timeout; parse da
    saída XML (`-oX`) para `Finding`s `INFO`/`LOW` por porta/serviço, com
    produto/versão quando disponível na `evidence`; sem flags intrusivas por
    padrão (sem `-sU`/scripts NSE disruptivos); primeiro caso que valida o scope
    gate fim-a-fim com binário externo.

---

## Frente 2 — VULN (varredura de vulnerabilidades)

### Épico V1 — Checagens de vulnerabilidade web seguras
**Objetivo:** detectar fraquezas comuns sem ações destrutivas.
**Valor:** encontra problemas exploráveis antes de um atacante, dentro de um
escopo autorizado.

- **V1.1 `[FEITO]` Métodos HTTP perigosos e exposição de informação**
  (`vuln.http_methods`)
  - *Como* analista, *quero* detectar métodos como `TRACE`/`PUT` habilitados e
    vazamento de versão em headers/erros, *para* reportar hardening.
  - **Critério de aceite:** `ACTIVE`; nenhuma requisição que altere estado;
    severidade coerente (`LOW`→`MEDIUM`); recomendação acionável.

- **V1.2 `[BACKLOG]` Checagem de configuração TLS fraca**
  - *Como* analista, *quero* identificar cifras/protocolos obsoletos aceitos,
    *para* recomendar correção.
  - **Critério de aceite:** `ACTIVE`; reaproveita infra do `tls_headers`;
    findings com referência a padrão (ex.: recomendações TLS 1.2+).

- **V1.3 `[EM DEV]` Verificação de CVEs por produto/versão identificado**
  (`vuln.cve_lookup`)
  - *Como* analista, *quero* cruzar o fingerprint de serviço (R2.2) com uma base
    de CVEs, *para* apontar vulnerabilidades conhecidas.
  - **Critério de aceite:** `PASSIVE` (consulta base externa, não o alvo); marca
    confiança da correlação; nunca afirma exploração, só exposição potencial.

### Épico V2 — Checks `INTRUSIVE` com confirmação
**Objetivo:** permitir verificações que podem alterar estado, com dupla
barreira (scope gate + confirmação explícita).
**Valor:** cobre casos que exigem interação mais forte sem abrir mão da
segurança operacional.

- **V2.1 `[BACKLOG]` Protótipo de check `INTRUSIVE` + fluxo de confirmação**
  - *Como* analista, *quero* que módulos `INTRUSIVE` exijam confirmação além do
    escopo, *para* evitar disrupção acidental.
  - **Critério de aceite:** engine solicita confirmação para `INTRUSIVE`; sem
    confirmação, módulo é `skipped` com `skip_reason`; documentado no contrato.

### Épico V3 — Wrapper do `nuclei` com parse estruturado `[FEITO]`
**Objetivo:** integrar o scanner `nuclei` ao engine, convertendo seus resultados
em `Finding`s do ThurSec, como primeiro grande salto de cobertura para pentest.
**Valor:** o maior incremento de valor para pentest autorizado — milhares de
templates da comunidade entram no toolkit com findings normalizados e reporte
unificado, sem perder scope gate nem padronização.

- **V3.1 `[FEITO]` Módulo `vuln.nuclei` (ACTIVE, scope-gated)**
  - *Como* pentester, *quero* rodar o `nuclei` contra um alvo em escopo e receber
    os achados como `Finding`s, *para* aproveitar os templates sem sair do fluxo.
  - **Critério de aceite:** `ACTIVE` → scope-gated (recusa alvo fora do
    `scope.yaml`); `requires_tools = ("nuclei",)` com pré-flight e dica de
    instalação se ausente; invoca via `CommandRunner` (sem shell) com timeout;
    saída JSON do nuclei parseada para `Finding`, mapeando a severidade do nuclei
    para `Severity` e preservando a linha crua na `evidence`; `references` com o
    link do template; nunca roda templates destrutivos por padrão.

- **V3.2 `[BACKLOG]` Seleção de templates e perfis de intensidade**
  - *Como* pentester, *quero* escolher tags/severidades de template e ter um
    perfil "seguro" por padrão, *para* controlar ruído e risco.
  - **Critério de aceite:** filtros expostos via `ctx.options`; perfil padrão
    exclui categorias disruptivas; templates que alteram estado só sob
    `INTRUSIVE` + confirmação.

---

## Frente 3 — DEPS_SECRETS (dependências e segredos)

### Épico D1 — Varredura de segredos em repositórios próprios
**Objetivo:** encontrar credenciais vazadas no código antes que virem incidente.
**Valor:** prevenção barata de um dos vetores de comprometimento mais comuns;
`PASSIVE` (lê arquivos locais, não toca em alvo remoto).

- **D1.1 `[FEITO]` Scanner de segredos por padrões** (`deps_secrets.secret_scan`)
  - *Como* desenvolvedor, *quero* varrer uma árvore de arquivos em busca de
    chaves/tokens/segredos, *para* removê-los antes do commit.
  - **Critério de aceite:** `PASSIVE`; conjunto de regex para padrões comuns
    (AWS, chaves privadas, tokens genéricos de alta entropia); findings
    `HIGH`/`CRITICAL` com arquivo e linha na evidência; evita mascarar o segredo
    por completo apenas quando necessário para verificação; respeita
    `.gitignore`/exclusões; sem falsos positivos óbvios em fixtures de teste.

- **D1.2 `[BACKLOG]` Detecção por entropia (complemento aos regex)**
  - *Como* desenvolvedor, *quero* flaggar strings de alta entropia não cobertas
    por padrões, *para* pegar segredos custom.
  - **Critério de aceite:** limiar configurável; reduz ruído com allowlist;
    severidade `MEDIUM` por padrão (menor confiança que regex).

### Épico D2 — Auditoria de dependências vulneráveis
**Objetivo:** identificar dependências com vulnerabilidades conhecidas.
**Valor:** cobre o risco de supply chain nos projetos da própria organização.

- **D2.1 `[FEITO]` Parser de manifestos (requirements/pyproject/lock)**
  (`deps_secrets.dep_audit`)
  - *Como* desenvolvedor, *quero* extrair o grafo de dependências e versões,
    *para* ter a base da auditoria.
  - **Critério de aceite:** `PASSIVE`; suporta pelo menos Python; findings `INFO`
    com inventário; tolerante a formatos parciais.

- **D2.2 `[FEITO]` Cruzamento com base de advisories** (`deps_secrets.dep_audit`,
  via OSV)
  - *Como* desenvolvedor, *quero* saber quais dependências têm CVE/advisory,
    *para* priorizar upgrades.
  - **Critério de aceite:** `PASSIVE`; severidade herda do advisory; recomendação
    = versão corrigida; modo offline com base em cache.

- **D2.3 `[BACKLOG]` Parsear vetor CVSS do OSV para score numérico**
  - *Como* desenvolvedor, *quero* que a severidade derive do score real quando o
    OSV entrega o CVSS como **vetor** (`CVSS:3.1/AV:.../...`) e não como número,
    *para* não colapsar advisories distintos no mesmo nível.
  - **Contexto:** hoje `deps_secrets.dep_audit` (`_cvss_score` em
    `thursec/modules/deps_secrets/dep_audit.py`) só lê `score` numérico; quando o
    OSV devolve um vetor CVSS, o valor é ignorado e o módulo cai no **default
    `HIGH`** conservador. Follow-up: parsear o vetor (base score CVSS v3.x) e
    mapear para `Severity` por faixa, mantendo o `HIGH` só como fallback real.
  - **Critério de aceite:** `PASSIVE`; deriva base score a partir do vetor CVSS
    v3.x; mapeia faixa → `Severity`; `HIGH` deixa de ser default quando o vetor
    está presente; coberto por teste com advisory de vetor.

---

## Frente 4 — CONFIG_AUDIT (auditoria de configuração)

### Épico C1 — Hardening de superfície web
**Objetivo:** validar a postura de configuração de serviços expostos.
**Valor:** correções de alto retorno e baixo risco; é a frente mais madura.

- **C1.1 `[FEITO]` Auditoria TLS + headers HTTP** (`config_audit.tls_headers`)
  - *Como* defensor, *quero* checar expiração de cert, versão de TLS e headers de
    segurança, *para* corrigir hardening básico.
  - **Critério de aceite:** `ACTIVE`, scope-gated; pure-stdlib; findings por
    header ausente com recomendação. **Entregue.**

- **C1.2 `[EM DEV]` Checagem de cookies e políticas de sessão**
  (`config_audit.cookies`)
  - *Como* defensor, *quero* validar flags `Secure`/`HttpOnly`/`SameSite`,
    *para* reduzir risco de sequestro de sessão.
  - **Critério de aceite:** `ACTIVE`; findings `LOW`/`MEDIUM` por flag ausente.

### Épico C2 — Auditoria de configuração de infraestrutura
**Objetivo:** checar configs de arquivos/infra da própria organização.
**Valor:** estende a auditoria para além do perímetro web.

- **C2.1 `[EM DEV]` Lint de arquivos de configuração (ex.: nginx, SSH)**
  (`config_audit.server_configs`)
  - *Como* defensor, *quero* detectar diretivas inseguras em configs locais,
    *para* endurecer servidores.
  - **Critério de aceite:** `PASSIVE` (lê arquivo local); regras documentadas;
    findings com a linha ofensora na evidência.

- **C2.2 `[BACKLOG]` Baseline de nuvem (IaC / recursos próprios)**
  - *Como* defensor, *quero* checar configs de IaC contra boas práticas, *para*
    evitar exposição acidental.
  - **Critério de aceite:** `PASSIVE`; escopo restrito aos ativos próprios
    declarados; severidade por regra.

### Épico C3 — Auditoria de postura Supabase / cloud `[FEITO]`
**Objetivo:** auditar a configuração de segurança de projetos Supabase/cloud da
*própria* organização (casa com a infra real da Raiô, que usa Supabase).
**Valor:** detecta exposições de alto impacto — RLS desligado, policies
permissivas, chaves vazadas, buckets públicos — direto no stack em produção,
com achados acionáveis.

- **C3.1 `[FEITO]` Checagem de RLS e policies**
  - *Como* defensor, *quero* verificar se Row Level Security está habilitado nas
    tabelas e se as policies não são permissivas demais, *para* evitar vazamento
    de dados.
  - **Critério de aceite:** `PASSIVE` sobre o projeto *próprio* (credencial de
    auditoria fornecida pelo dono, nunca varredura de terceiros); `Finding`
    `HIGH`/`CRITICAL` por tabela sem RLS ou com policy aberta; evidência com
    nome da tabela/policy; recomendação acionável.

- **C3.2 `[FEITO]` Chaves expostas e segredos de configuração**
  - *Como* defensor, *quero* detectar uso indevido da `service_role`/chaves
    sensíveis expostas no cliente, *para* cortar um vetor crítico.
  - **Critério de aceite:** `PASSIVE`; `CRITICAL` para chave de serviço exposta;
    reaproveita padrões do `deps_secrets.secret_scan` quando aplicável; nunca
    loga o segredo completo além do necessário para verificação.

- **C3.3 `[FEITO]` Buckets de storage públicos e exposição de dados**
  - *Como* defensor, *quero* listar buckets/objetos com acesso público não
    intencional, *para* fechar exposições de dados.
  - **Critério de aceite:** `PASSIVE` sobre o projeto próprio; `Finding` por
    bucket público com severidade conforme sensibilidade; opera apenas sobre
    recursos declarados como próprios.

---

## Frente 5 — PLATAFORMA UNIFICADA (visão)

As versões **legítimas** das categorias vetadas. Cada uma reinterpreta a ideia
para o uso defensivo/autorizado do produto. Todas respeitam o scope gate e, nos
casos sensíveis, exigem inventário/autorização declarados.

### Épico P1 — Teste de resiliência / carga da própria infra (legítima do "DoS")
**Objetivo:** medir como a *própria* infra se comporta sob carga, com orçamento
de erro definido — não derrubar, mas conhecer o limite.
**Valor:** capacity planning e validação de SLOs sem risco a terceiros.
**Pré-requisito:** depende da **primitiva de confirmação `INTRUSIVE` (V2.1)** —
sem o fluxo de confirmação + scope gate em dupla barreira, este épico não começa.
**Exige design antes:** modelo de orçamento de erro, teto de RPS e kill-switch
precisam de desenho e revisão de produto/segurança antes de qualquer código.

- **P1.1 `[BACKLOG]` Teste de carga com teto de requisições e kill-switch**
  - *Como* SRE, *quero* gerar carga controlada contra meu serviço em escopo,
    *para* medir latência/erro sob pressão.
  - **Critério de aceite:** `INTRUSIVE` → scope-gated + confirmação (V2.1); teto
    de RPS obrigatório; parada automática ao atingir limiar de erro; relatório de
    latência. **Recusa qualquer alvo não listado no `scope.yaml`.**

### Épico P2 — Simulação de conscientização (legítima do "phishing")
**Objetivo:** treinar os *próprios* funcionários a reconhecer golpes, com
autorização e sem coletar credenciais reais.
**Valor:** reduz o maior vetor humano de risco, de forma ética e mensurável.

**Borda do produto (inegociável):** o escopo legítimo é **página educativa +
métrica de clique** sobre uma **lista interna autorizada** de funcionários da
*própria* organização. **Sem captura de credencial** (a página ensina, nunca
coleta senha) e **sem envio enganoso em massa** (nada de varrer ou iludir
terceiros). **Registro de autorização é obrigatório** antes de qualquer disparo.
Qualquer desenho que resvale em roubo de credencial ou engano em massa é
recusado — é exatamente a fronteira que separa esta simulação do phishing vetado.
**Exige design antes:** fluxo de consentimento, anonimização de métricas e trilha
de autorização precisam ser desenhados e aprovados antes de implementar.

- **P2.1 `[BACKLOG]` Campanha de simulação interna com consentimento**
  - *Como* time de segurança, *quero* enviar simulações só para funcionários da
    minha org (lista autorizada), *para* medir e treinar reação.
  - **Critério de aceite:** destinatários restritos a domínio/lista autorizada;
    **nunca** captura senha real (página educativa, não coletora); **sem envio
    enganoso em massa**; registro de autorização obrigatório; métrica = apenas
    clique em lista interna autorizada; métricas agregadas, não punitivas.

### Épico P3 — Agente de endpoint da própria frota (legítima do "RAT")
**Objetivo:** visibilidade de postura dos endpoints que a organização
**possui e gerencia**, instalado com consentimento.
**Valor:** inventário e detecção de desvio de configuração na frota própria.

- **P3.1 `[BACKLOG]` Agente de coleta de postura (read-only)**
  - *Como* admin, *quero* coletar estado de segurança dos endpoints da frota,
    *para* detectar máquinas fora de conformidade.
  - **Critério de aceite:** instalação explícita e identificável; apenas leitura
    de postura (sem controle remoto); dados fluem para o dono da frota;
    desinstalação simples e documentada.

### Épico P4 — Attack Surface Management dos próprios ativos (legítima do "alvo em massa")
**Objetivo:** monitorar continuamente a superfície exposta dos ativos
**declarados como próprios** — nunca varrer a internet.
**Valor:** descobre exposições novas (shadow IT, portas abertas) antes do
atacante.

- **P4.1 `[BACKLOG]` Inventário contínuo a partir de ativos declarados**
  - *Como* time de segurança, *quero* reavaliar periodicamente os ativos do meu
    inventário, *para* detectar mudanças na superfície.
  - **Critério de aceite:** opera **apenas** sobre o inventário/scope declarado;
    diff entre execuções; alerta de superfície nova; reaproveita os módulos de
    recon.

---

# EXPERIÊNCIA E PLATAFORMA (transversal)

### Épico UX1 — Interface de terminal (TUI)
**Objetivo:** tornar o toolkit usável por menu, além da CLI.
**Valor:** acessibilidade para quem não decora flags; visualização de findings.

- **UX1.1 `[FEITO]` TUI em Textual**
  - *Como* usuário, *quero* navegar módulos, configurar escopo e ver findings em
    uma interface de terminal, *para* operar sem decorar comandos.
  - **Critério de aceite:** lista módulos do registry; respeita o scope gate
    (não deixa rodar `ACTIVE` fora de escopo); exibe findings ordenados por
    severidade; depende do extra `[tui]` (textual/rich) já declarado no
    `pyproject.toml`; não quebra quando o extra não está instalado (mensagem
    clara).

### Épico PLAT1 — Persistência central de findings (findings store histórico)

**Objetivo:** dar ao ThurSec uma memória. Hoje cada run produz findings e um
relatório efêmero; este épico introduz um **store histórico** (SQLite local no
MVP) que guarda runs ao longo do tempo, deduplica por fingerprint e permite
**diff entre scans**.

**Valor:** transforma scans isolados em acompanhamento de postura: saber o que
**surgiu, sumiu ou mudou de severidade** entre duas execuções é o que torna o
produto útil de forma contínua (regressões, confirmação de correções, tendência)
— e é a base de dados sobre a qual o dashboard futuro é construído.

**Arquitetura (MVP):**
- Backend **SQLite local** (um arquivo, zero dependências externas; cabe no
  espírito pure-stdlib do projeto). Abstração de storage para permitir outros
  backends depois sem mexer nos módulos.
- Chave de deduplicação/identidade: `Finding.fingerprint` (já existe em
  `thursec/core/finding.py` — `module|target|title|severity`, exclui timestamp e
  evidência de propósito), garantindo que re-scan do mesmo problema não vire
  "novo".
- Cada execução vira um **run** (id, timestamp, escopo, módulos). Cada finding é
  persistido ligado ao seu run; o histórico por fingerprint permite reconstruir a
  linha do tempo de uma issue (primeira vez vista, última vez vista, status).
- O engine ganha um passo opcional de persistência após coletar findings; sem o
  store, o comportamento atual (relatório efêmero) permanece inalterado.

**Pré-requisito do épico "Dashboard" (PLAT2):** o dashboard consome o store; não
há dashboard sem persistência.

- **PLAT1.1 `[FEITO]` Persistir runs e findings em SQLite**
  - *Como* operador, *quero* que cada run e seus findings sejam gravados num
    store local, *para* manter histórico entre execuções.
  - **Critério de aceite:** schema de `runs` e `findings` em SQLite; grava run
    (timestamp, alvo/escopo, módulos executados) e cada finding via `to_dict()`;
    idempotente por `(run_id, fingerprint)`; store é opt-in (flag na CLI) e não
    quebra o fluxo efêmero atual; coberto por testes.

- **PLAT1.2 `[FEITO]` Deduplicação e histórico por fingerprint**
  - *Como* operador, *quero* que o mesmo problema reaparecendo não gere registro
    novo, *para* medir persistência de uma issue ao longo do tempo.
  - **Critério de aceite:** dedup por `Finding.fingerprint`; registra
    first_seen/last_seen por fingerprint; não cria duplicata ao re-scanear alvo
    inalterado (verificado em teste).

- **PLAT1.3 `[FEITO]` Diff entre dois scans**
  - *Como* operador, *quero* comparar o run atual com um anterior, *para* ver o
    que surgiu, sumiu ou mudou de severidade.
  - **Critério de aceite:** comando/API que, dados dois run ids (ou "último vs
    penúltimo"), retorna conjuntos **novos**, **resolvidos** e **alterados**
    (mudança de severidade por fingerprint); saída exportável (JSON/MD/HTML
    reaproveitando o reporter); coberto por testes com fixtures de dois runs.

- **PLAT1.4 `[BACKLOG]` Camada de consulta para consumo externo**
  - *Como* desenvolvedor do dashboard, *quero* uma API de leitura sobre o store,
    *para* alimentar visualizações sem acoplar ao schema.
  - **Critério de aceite:** funções de consulta (runs recentes, findings por
    severidade, tendência por fingerprint) desacopladas do schema; servem de
    contrato estável para o dashboard.

### Épico PLAT2 — Dashboard de postura (depende de PLAT1) `[EM DEV]`
**Objetivo:** visualizar o histórico do findings store — tendência, diffs e
severidade ao longo do tempo.
**Valor:** leitura executiva e operacional da evolução da postura de segurança.
**Dependência:** requer o findings store (PLAT1) pronto; **sem PLAT1 não há
dashboard.**

- **PLAT2.1 `[EM DEV]` Visão de tendência e diff sobre o store**
  - *Como* líder de segurança, *quero* ver evolução de findings por severidade e
    o diff entre scans, *para* acompanhar progresso.
  - **Critério de aceite:** consome a camada de consulta (PLAT1.4); mostra
    tendência, novos/resolvidos e distribuição por severidade; não reimplementa
    acesso ao schema.

### Épico PLAT3 — Empacotamento / Distribuição e CI `[EM DEV]`
**Objetivo:** tornar o ThurSec instalável, reproduzível e testado de forma
contínua — fechar o ciclo de engenharia que falta para uma primeira release
pública.
**Valor:** reduz o atrito de adoção (rodar sem montar ambiente na mão), protege
a fronteira ética e o scope gate contra regressões (testes em cada PR) e dá uma
versão citável para quem consome o toolkit.

- **PLAT3.1 `[EM DEV]` Imagem Docker do toolkit**
  - *Como* operador, *quero* uma imagem container com o ThurSec e suas deps
    (incl. binários externos opcionais como `nmap`/`nuclei`), *para* rodar sem
    montar o ambiente na mão.
  - **Critério de aceite:** `Dockerfile` reproduzível; imagem roda a CLI por
    padrão; extras (`[tui]`) documentados; não embute segredos nem `scope.yaml`.

- **PLAT3.2 `[EM DEV]` CI no GitHub Actions rodando os testes**
  - *Como* mantenedor, *quero* que cada PR rode a suíte de testes automaticamente,
    *para* proteger o núcleo, o scope gate e a fronteira ética contra regressão.
  - **Critério de aceite:** workflow do GitHub Actions executa os testes em push
    e PR; falha bloqueia o merge; matriz mínima de versões de Python suportadas.

- **PLAT3.3 `[EM DEV]` Release 0.1.0 + CHANGELOG**
  - *Como* usuário, *quero* uma versão marcada e um CHANGELOG, *para* saber o que
    entrou e instalar um ponto estável.
  - **Critério de aceite:** `CHANGELOG.md` seguindo Keep a Changelog; versão
    `0.1.0` no `pyproject.toml`; tag de release com as entregas dos primeiros
    ciclos consolidadas.

---

## Próximo sprint (priorizado)

### Já entregue (no `main`, com testes)

Fechamos os dois primeiros ciclos de features e a base de plataforma:

1. **R1.1** `recon.ct_subdomains` — subdomínios via Certificate Transparency
   (`PASSIVE`). **Entregue.**
2. **D1.1** `deps_secrets.secret_scan` — scanner de segredos por padrões
   (`PASSIVE`). **Entregue.**
3. **UX1.1** TUI em Textual — camada de usabilidade sobre o engine. **Entregue.**
4. **V3.1** `vuln.nuclei` — wrapper do `nuclei` com parse estruturado
   (`ACTIVE`, scope-gated). **Entregue.**
5. **C3** Auditoria de postura **Supabase** (RLS, policies, chaves expostas,
   buckets públicos) — `config_audit.supabase` (`PASSIVE`). **Entregue.**
6. **R2.3** `recon.nmap` — port/service scan via `nmap`, primeiro módulo
   `ACTIVE` "de verdade" exercitando o scope gate fim-a-fim. **Entregue.**
7. **PLAT1** Findings store histórico (SQLite + dedup por fingerprint + diff
   entre scans), exposto na CLI via `run --store` e `diff`. **Entregue.**
8. **Plataforma/segurança:** validador de target compartilhado
   (`thursec/core/target.py`), defesa contra *argument injection*, usado por
   `recon.nmap` e `vuln.nuclei`. **Entregue.**
9. **R1.2** `recon.whois` — registro de domínio via RDAP/WHOIS (`PASSIVE`).
   **Entregue.**
10. **R1.3** `recon.dns` — resolução/enumeração DNS via DNS-over-HTTPS
    (`PASSIVE`). **Entregue.**
11. **V1.1** `vuln.http_methods` — métodos HTTP perigosos e exposição de
    informação (`ACTIVE`, read-only). **Entregue.**
12. **D2.1/D2.2** `deps_secrets.dep_audit` — auditoria de dependências via OSV
    (`PASSIVE`). **Entregue.**

Total: **10 módulos** no `main` + núcleo + CLI (`list`/`run`/`diff`/`dashboard`)
+ findings store + TUI.

### Em andamento

- **PLAT2 — Dashboard de postura** (`[EM DEV]`): visualização do findings store
  (tendência, diffs e distribuição por severidade). Construído agora sobre a
  memória que o PLAT1 passou a fornecer.
- **C1.2** `config_audit.cookies` (`[EM DEV]`) — flags `Secure`/`HttpOnly`/
  `SameSite` e políticas de sessão.
- **V1.3** `vuln.cve_lookup` (`[EM DEV]`) — CVEs por fingerprint de serviço
  (`PASSIVE`).
- **C2.1** `config_audit.server_configs` (`[EM DEV]`) — lint de configs locais
  (nginx/SSH).
- **PLAT3 — Empacotamento / Distribuição e CI** (`[EM DEV]`): Docker, GitHub
  Actions rodando os testes e release `0.1.0` + CHANGELOG.

### Candidatos aos próximos sprints

Ampliam cobertura sem abrir novas frentes de risco; sem datas definidas:

- **P1** Teste de resiliência / carga da própria infra (versão legítima do
  "DoS") — `INTRUSIVE`, scope-gated + confirmação (V2.1) + teto de RPS;
  **exige design antes**.
- **P2** Simulação de conscientização interna (versão legítima do "phishing") —
  página educativa + métrica de clique em lista interna autorizada, **sem
  captura de credencial e sem envio enganoso em massa**, com registro de
  autorização obrigatório; **exige design antes**.
- **D2.3** Parsear vetor CVSS do OSV para score numérico — hoje `dep_audit` cai
  no default `HIGH` quando o OSV entrega o CVSS como vetor.
- **V2.1** Primitiva de check `INTRUSIVE` + fluxo de confirmação (pré-requisito
  do P1).

**Critério de pronto de cada item:** testes, documentação no README/contrato de
módulo, respeitando a fronteira ética e o scope gate.
