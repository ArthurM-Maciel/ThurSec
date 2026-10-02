# Contribuindo com o ThurSec

Obrigado por contribuir. Este guia reúne as convenções do projeto: como nomear
branches, escrever commits, abrir PRs, rodar os testes e adicionar um módulo.

Antes de tudo, leia a **fronteira ética** do produto em
[`docs/BACKLOG.md`](docs/BACKLOG.md). ThurSec é um toolkit de security
assessment **para uso autorizado e defensivo**. Contribuições de DoS/DDoS,
phishing/roubo de credencial, RAT/acesso não autorizado ou alvo em massa são
recusadas no review, independentemente da qualidade técnica. As versões
legítimas dessas ideias estão no roadmap.

---

## Fluxo de trabalho

A regra de ouro: **1 feature = 1 branch = 1 PR = review antes do merge.**

1. Atualize o `main` local.
2. Crie uma branch a partir do `main` (padrão de nome abaixo).
3. Faça commits pequenos e atômicos em Conventional Commits.
4. Rode os testes localmente (`pytest`) — eles precisam passar.
5. Abra um PR com `--base main`, título em Conventional Commit e corpo
   descrevendo o que muda e como testar.
6. **Não faça merge do seu próprio PR.** Um reviewer aprova e faz o merge.

Nunca commite direto no `main`. Nunca misture features diferentes numa mesma
branch/PR.

---

## Nomenclatura de branches

Formato: `<tipo>/<área>-<descrição-curta>`

- `<tipo>` — um de: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.
- `<área>` — a frente/módulo tocado: `recon`, `vuln`, `deps_secrets`,
  `config_audit`, `core`, `cli`, `tui`, `docs`.
- `<descrição-curta>` — em kebab-case, objetiva.

Exemplos:

```
feat/recon-ct-subdomains
feat/deps_secrets-secret-scan
fix/core-scope-wildcard-match
refactor/core-runner-timeout
test/config_audit-tls-headers
docs/backlog-roadmap
chore/ci-pytest-matrix
```

---

## Conventional Commits

Mensagens seguem [Conventional Commits](https://www.conventionalcommits.org/):

```
<tipo>(<escopo opcional>): <descrição no imperativo>

[corpo opcional explicando o porquê]

[rodapé opcional: BREAKING CHANGE, refs, co-autoria]
```

- **Tipos:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore` (mesmos dos
  branches), além de `perf` e `ci` quando fizer sentido.
- **Escopo:** a área, entre parênteses — ex.: `feat(recon):`, `fix(core):`.
- **Descrição:** imperativo, minúscula, sem ponto final.

Exemplos:

```
feat(recon): add ct_subdomains passive module
fix(core): match single-label wildcards in scope gate
docs(backlog): add product backlog and ethical boundary
test(config_audit): cover expired-certificate path
```

---

## Rodando os testes

Setup do ambiente e execução da suíte:

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/python -m pytest -q
```

Para desenvolvimento da TUI, instale também o extra `[tui]`:

```bash
.venv/bin/pip install -e ".[tui,dev]"
```

Todo PR deve manter a suíte verde. Features novas chegam com testes; correções
de bug chegam com um teste que falha antes e passa depois.

---

## Contrato de módulo

Um módulo é **uma classe** que herda de `Module`. O engine descobre a classe
automaticamente (varre `thursec/modules/`), aplica o scope gate, mede tempo,
trata erros e coleta os findings. Você só implementa `run` e retorna findings.

### Atributos obrigatórios

Definidos em `thursec/core/module.py`:

- `id` — identificador único, no formato `<categoria>.<nome>`
  (ex.: `recon.ct_subdomains`). **Obrigatório e não vazio** (o engine falha no
  import se faltar).
- `category` — um valor de `Category`: `RECON`, `VULN`, `DEPS_SECRETS`,
  `CONFIG_AUDIT`. **Obrigatório.**
- `name` — nome legível para menu/relatório.
- `intensity` — `Intensity.PASSIVE`, `ACTIVE` (padrão) ou `INTRUSIVE`.
- `requires_tools` — tupla de binários externos necessários (vazia = Python
  puro, sempre disponível).

### Regra de intensity: PASSIVE vs ACTIVE/INTRUSIVE

Esta é a decisão de segurança mais importante ao escrever um módulo. A
`intensity` define se o **scope gate** se aplica:

- **`PASSIVE`** — o módulo **não envia pacotes ao alvo**. Usa fontes públicas
  (Certificate Transparency, WHOIS/RDAP, resolvers DNS) ou lê arquivos locais
  (scan de segredos, lint de config). Roda **sem** `scope.yaml`.
- **`ACTIVE`** — interação normal com o alvo (requisições HTTP, port scan).
  **Só roda contra alvos listados num `scope.yaml` autorizado** (scope gate).
- **`INTRUSIVE`** — pode alterar estado ou ser disruptivo. Scope-gated **e**
  exige confirmação explícita.

Classifique com honestidade: tocar no alvo é `ACTIVE` no mínimo. Marcar um
módulo que envia pacotes como `PASSIVE` para fugir do scope gate é uma violação
da fronteira do produto e será barrado no review. A propriedade
`requires_scope` (em `Module`) retorna `True` para `ACTIVE`/`INTRUSIVE`.

### Como adicionar um plugin

1. Escolha a categoria e crie o arquivo no pacote dela:
   `thursec/modules/<categoria>/<nome>.py`.
2. Implemente a subclasse de `Module`.
3. Produza findings via `ctx.finding(...)` (preenche `target` por você) e
   retorne a lista.
4. Adicione testes em `tests/`.
5. Branch + commit + PR seguindo os padrões acima.

### Exemplo mínimo

```python
from thursec.core.context import RunContext
from thursec.core.finding import Finding, Severity
from thursec.core.module import Category, Intensity, Module


class MyCheck(Module):
    id = "config_audit.my_check"
    name = "My check"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.ACTIVE          # => scope-gated
    requires_tools = ()                    # binários externos, se houver

    async def run(self, ctx: RunContext) -> list[Finding]:
        return [
            ctx.finding(
                self.id,
                "Something worth reporting",
                Severity.LOW,
                recommendation="Do the thing.",
                evidence="raw proof the human can verify",
            )
        ]
```

Mantenha o `run` focado em **produzir findings**. Escopo, tempo e tratamento de
erro são responsabilidade do engine — não os reimplemente no módulo.
