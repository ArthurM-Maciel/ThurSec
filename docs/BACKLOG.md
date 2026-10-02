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
  categoria, ou passivo por padrão), saída `-o`.
- `[FEITO]` **Módulo `config_audit.tls_headers`** — expiração de certificado,
  versão de TLS, headers de segurança HTTP. Pure-stdlib, `ACTIVE`.
- `[FEITO]` **Cobertura de testes** do núcleo (scope, findings, engine).

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

- **R1.1 `[EM DEV]` Enumeração de subdomínios via Certificate Transparency**
  (`recon.ct_subdomains`)
  - *Como* analista, *quero* listar subdomínios de um domínio consultando logs
    de CT públicos, *para* conhecer a superfície sem tocar no alvo.
  - **Critério de aceite:** dado um domínio, retorna `Finding`s `INFO` com os
    subdomínios únicos encontrados; `intensity = PASSIVE`; sem scope gate;
    respeita timeout do runner; deduplica resultados; funciona offline-safe
    (falha de rede vira erro tratado, não exceção).

- **R1.2 `[BACKLOG]` Consulta WHOIS / RDAP**
  - *Como* analista, *quero* dados de registro do domínio (registrante, datas,
    nameservers), *para* contextualizar o alvo.
  - **Critério de aceite:** `PASSIVE`; parse de RDAP com fallback; findings
    `INFO` com evidência bruta preservada.

- **R1.3 `[BACKLOG]` Resolução DNS e enumeração de registros**
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

---

## Frente 2 — VULN (varredura de vulnerabilidades)

### Épico V1 — Checagens de vulnerabilidade web seguras
**Objetivo:** detectar fraquezas comuns sem ações destrutivas.
**Valor:** encontra problemas exploráveis antes de um atacante, dentro de um
escopo autorizado.

- **V1.1 `[BACKLOG]` Métodos HTTP perigosos e exposição de informação**
  - *Como* analista, *quero* detectar métodos como `TRACE`/`PUT` habilitados e
    vazamento de versão em headers/erros, *para* reportar hardening.
  - **Critério de aceite:** `ACTIVE`; nenhuma requisição que altere estado;
    severidade coerente (`LOW`→`MEDIUM`); recomendação acionável.

- **V1.2 `[BACKLOG]` Checagem de configuração TLS fraca**
  - *Como* analista, *quero* identificar cifras/protocolos obsoletos aceitos,
    *para* recomendar correção.
  - **Critério de aceite:** `ACTIVE`; reaproveita infra do `tls_headers`;
    findings com referência a padrão (ex.: recomendações TLS 1.2+).

- **V1.3 `[BACKLOG]` Verificação de CVEs por produto/versão identificado**
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

---

## Frente 3 — DEPS_SECRETS (dependências e segredos)

### Épico D1 — Varredura de segredos em repositórios próprios
**Objetivo:** encontrar credenciais vazadas no código antes que virem incidente.
**Valor:** prevenção barata de um dos vetores de comprometimento mais comuns;
`PASSIVE` (lê arquivos locais, não toca em alvo remoto).

- **D1.1 `[EM DEV]` Scanner de segredos por padrões** (`deps_secrets.secret_scan`)
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

- **D2.1 `[BACKLOG]` Parser de manifestos (requirements/pyproject/lock)**
  - *Como* desenvolvedor, *quero* extrair o grafo de dependências e versões,
    *para* ter a base da auditoria.
  - **Critério de aceite:** `PASSIVE`; suporta pelo menos Python; findings `INFO`
    com inventário; tolerante a formatos parciais.

- **D2.2 `[BACKLOG]` Cruzamento com base de advisories**
  - *Como* desenvolvedor, *quero* saber quais dependências têm CVE/advisory,
    *para* priorizar upgrades.
  - **Critério de aceite:** `PASSIVE`; severidade herda do advisory; recomendação
    = versão corrigida; modo offline com base em cache.

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

- **C1.2 `[BACKLOG]` Checagem de cookies e políticas de sessão**
  - *Como* defensor, *quero* validar flags `Secure`/`HttpOnly`/`SameSite`,
    *para* reduzir risco de sequestro de sessão.
  - **Critério de aceite:** `ACTIVE`; findings `LOW`/`MEDIUM` por flag ausente.

### Épico C2 — Auditoria de configuração de infraestrutura
**Objetivo:** checar configs de arquivos/infra da própria organização.
**Valor:** estende a auditoria para além do perímetro web.

- **C2.1 `[BACKLOG]` Lint de arquivos de configuração (ex.: nginx, SSH)**
  - *Como* defensor, *quero* detectar diretivas inseguras em configs locais,
    *para* endurecer servidores.
  - **Critério de aceite:** `PASSIVE` (lê arquivo local); regras documentadas;
    findings com a linha ofensora na evidência.

- **C2.2 `[BACKLOG]` Baseline de nuvem (IaC / recursos próprios)**
  - *Como* defensor, *quero* checar configs de IaC contra boas práticas, *para*
    evitar exposição acidental.
  - **Critério de aceite:** `PASSIVE`; escopo restrito aos ativos próprios
    declarados; severidade por regra.

---

## Frente 5 — PLATAFORMA UNIFICADA (visão)

As versões **legítimas** das categorias vetadas. Cada uma reinterpreta a ideia
para o uso defensivo/autorizado do produto. Todas respeitam o scope gate e, nos
casos sensíveis, exigem inventário/autorização declarados.

### Épico P1 — Teste de resiliência / carga da própria infra (legítima do "DoS")
**Objetivo:** medir como a *própria* infra se comporta sob carga, com orçamento
de erro definido — não derrubar, mas conhecer o limite.
**Valor:** capacity planning e validação de SLOs sem risco a terceiros.

- **P1.1 `[BACKLOG]` Teste de carga com teto de requisições e kill-switch**
  - *Como* SRE, *quero* gerar carga controlada contra meu serviço em escopo,
    *para* medir latência/erro sob pressão.
  - **Critério de aceite:** `INTRUSIVE` → scope-gated + confirmação; teto de RPS
    obrigatório; parada automática ao atingir limiar de erro; relatório de
    latência. **Recusa qualquer alvo não listado no `scope.yaml`.**

### Épico P2 — Simulação de conscientização (legítima do "phishing")
**Objetivo:** treinar os *próprios* funcionários a reconhecer golpes, com
autorização e sem coletar credenciais reais.
**Valor:** reduz o maior vetor humano de risco, de forma ética e mensurável.

- **P2.1 `[BACKLOG]` Campanha de simulação interna com consentimento**
  - *Como* time de segurança, *quero* enviar simulações só para funcionários da
    minha org (lista autorizada), *para* medir e treinar reação.
  - **Critério de aceite:** destinatários restritos a domínio/ lista autorizada;
    **nunca** captura senha real (página educativa, não coletora); registro de
    autorização obrigatório; métricas agregadas, não punitivas.

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

- **UX1.1 `[EM DEV]` TUI em Textual**
  - *Como* usuário, *quero* navegar módulos, configurar escopo e ver findings em
    uma interface de terminal, *para* operar sem decorar comandos.
  - **Critério de aceite:** lista módulos do registry; respeita o scope gate
    (não deixa rodar `ACTIVE` fora de escopo); exibe findings ordenados por
    severidade; depende do extra `[tui]` (textual/rich) já declarado no
    `pyproject.toml`; não quebra quando o extra não está instalado (mensagem
    clara).

---

## Próximo sprint (priorizado)

Foco do ciclo corrente — já em desenvolvimento:

1. **R1.1** `recon.ct_subdomains` — primeiro módulo de recon (`PASSIVE`).
2. **D1.1** `deps_secrets.secret_scan` — scanner de segredos (`PASSIVE`).
3. **UX1.1** TUI em Textual — camada de usabilidade sobre o engine existente.

**Critério de pronto do sprint:** os três itens com testes, documentados no
README/contrato de módulo, respeitando a fronteira ética e o scope gate.

**Candidatos ao sprint seguinte:** R1.2 (WHOIS/RDAP), D2.1 (parser de
manifestos), C1.2 (cookies de sessão) — todos `PASSIVE`/`ACTIVE` de baixo risco
e alto valor, que ampliam cobertura sem abrir novas frentes de risco.
