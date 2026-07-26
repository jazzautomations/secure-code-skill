# 🔐 secure-code — Skill de segurança para agentes de IA (vibe coding)

Uma **Skill do Claude Code** (e um conjunto de regras portável para Cursor, Copilot, Lovable, etc.)
que impede agentes de IA de gerarem código inseguro — e os ensina a **detectar e corrigir** essas
falhas em projetos já existentes.

Feita para **vibe coders**: quem constrói apps rápido com IA e não quer vazar os dados dos usuários
(nem a fatura da conta de nuvem).

> **Regra de ouro:** nunca confie no cliente, nunca confie no default do framework, todo segredo
> fica no servidor.

---

## Por que isso existe

A IA otimiza o código para "funcionar", não para "ser seguro". O resultado aparece nos números
que a imprensa de segurança vem reportando sobre apps gerados por IA / vibe-coded:

- Grande parte do código gerado por IA falha em testes de segurança básicos (XSS, SQLi, secrets).
  *(OX Security, Cloud Security Alliance)*
- Auditorias em milhares de apps vibe-coded encontraram **milhares de vulnerabilidades críticas**,
  **centenas de segredos expostos** (API keys, tokens) e **PII vazada**. *(Escape.tech)*
- Uma fração enorme dos apps Supabase gerados por IA subiu com **Row Level Security desligada** —
  ou seja, qualquer pessoa com a chave pública (que fica no front) lê o banco inteiro. *(byteiota, Precursor Security)*
- Apps que embutiram **service keys / API keys direto no JavaScript do cliente**, dando acesso
  total ao banco de produção. *(Wiz, relatos públicos de incidentes)*
- **Denial of Wallet**: chaves de LLM roubadas gerando dezenas de milhares de dólares em horas.
  *(ToxSec, LayerX)*
- **Slopsquatting**: a IA "alucina" nomes de pacotes que não existem; atacantes registram esses
  nomes com malware. *(Cloud Security Alliance)*

> As estatísticas acima são reportadas pelas fontes citadas — trate-as como ordem de grandeza, não
> como número absoluto. O que **não** muda é o padrão: código de IA precisa ser revisado como
> código de terceiro não-confiável. Fontes completas no fim deste README.

---

## O que a skill cobre (33 vetores)

> Sempre começa por **contexto + stack + versões** (deps desatualizadas, versões com CVE conhecida,
> runtime EOL) antes de aplicar qualquer regra — regra na stack errada é ruído.

Segredos expostos · RLS ausente/quebrada (Supabase) · IDOR/BOLA · confiar no cliente (preço/role) ·
webhook sem verificação · token em localStorage · XSS · SQL/command injection · headers de
segurança · CORS · rate limit / denial of wallet · upload inseguro / SSRF · **supply chain**
(slopsquatting, deps vulneráveis, **CI/CD sem pin de SHA**, Docker sem digest, script de terceiro
sem SRI, dependency confusion) · auth e reset de senha fracos · erros verbosos & logs com PII ·
prompt injection · **subdomain takeover** · **JWT alg confusion / none / secret fraco** · **race
condition / TOCTOU** · `.git`/`.env`/source maps/Swagger expostos · open redirect / OAuth · path
traversal / SSTI · GraphQL · **SPF/DKIM/DMARC** · sessão insegura · object storage público ·
logging & monitoramento · validação server-side · **cache poisoning (CDN/edge)** · **excessive data
exposure / over-fetching** · **WebSocket inseguro** · **PII → LLM de terceiro** · **query sem limite
(data dump/DoS)** · **versões vulneráveis / runtime EOL**.

**Multi-linguagem:** os detectores (grep por vetor) cobrem **JS/TS, Go, Python e PHP** — o toolkit
white-box traz o padrão equivalente em cada stack.

Cada vetor tem o padrão **❌ errado → ✅ certo** em [`secure-code/references/vectors.md`](secure-code/references/vectors.md).

---

## 🚀 Scanner rodável (não é só doc — é ferramenta)

Além da skill (que o agente lê), tem um **scanner** que roda os detectores sozinho:

```bash
bash scan.sh .                      # white-box: varre o repositório atual
bash scan.sh --url https://alvo     # black-box: headers, CORS, .git/.env, SPF/DMARC, Supabase
bash scan.sh --url URL .            # grey-box (os dois)
bash scan.sh --json .               # saída JSON pra CI/pipeline
# ou: make test   |   make scan   |   make scan URL=https://exemplo.com
```

Saída ordenada por severidade (🔴 crítico → ℹ️ info), com `arquivo:linha` e exit code ≠ 0 se houver
crítico/alto (pronto pra CI). **Cada achado é ponto de partida, não veredito** — o scanner aponta,
você confirma lendo (verify-before-flag). Requer `bash`, `grep`, `curl`, `dig`; usa `gitleaks`,
`osv-scanner`, `govulncheck` se estiverem instalados.

### Provado por testes
`tests/` tem código **vulnerável de propósito** (um por vetor) e código **limpo**. `make test`
verifica que cada detector dispara **e** que o código limpo não gera falso-positivo (inclusive o
caso clássico: `NEXT_PUBLIC_SUPABASE_ANON_KEY` no front **não** é bug se a RLS está ligada). O CI
(`.github/workflows/scan.yml`) roda isso em todo push — com a Action **pinada por SHA** (praticando
o vetor 13 da própria skill).

### Como agente do Claude Code
`agents/security-reviewer.md` é um subagente pronto: copie para `~/.claude/agents/` e peça
*"revisa a segurança deste projeto"*. Ele roda o scanner, aplica verify-before-flag e entrega o
relatório priorizado.

## Como funciona — 3 modos

A skill dá ao agente um comportamento em 3 modos (detalhe em [`secure-code/SKILL.md`](secure-code/SKILL.md)):

1. **PREVENIR** — 16 regras invioláveis que o agente aplica *antes de entregar* qualquer código
   que toque em auth, dados, pagamentos, uploads, env vars, DNS ou chamadas externas.
2. **DETECTAR** — fluxo `DETECTAR → VERIFICAR → REPORTAR` em dois tracks: **white-box** (você tem
   o código — track principal, com grep por vetor + [playbook de revisão](secure-code/references/code-review-playbook.md))
   e **black-box** (alvo no ar — headers, RLS probe, subdomínios, SPF/DMARC). Com
   **verify-before-flag** (o agente *testa* a falha antes de acusar, reduzindo falso-positivo),
   escala de severidade e [template de relatório](secure-code/references/audit-report-template.md).
3. **CORRIGIR** — separa o que a IA pode consertar sozinha do que ela **tem que parar e escalar
   para um humano** (rotacionar chave, mexer em RLS de produção, deletar DNS, reescrever histórico
   do git) — evitando que a "correção" quebre a produção.

Inclui uma **lista de falso-positivos** (ex: `NEXT_PUBLIC_SUPABASE_ANON_KEY` no front é *correto*
se a RLS estiver ligada) para o agente não marcar coisa certa como bug.

---

## Instalação

### Claude Code (skill nativa)

```bash
git clone https://github.com/SEU-USUARIO/secure-code-skill.git
mkdir -p ~/.claude/skills
cp -r secure-code-skill/secure-code ~/.claude/skills/secure-code
```

Pronto. A skill é descoberta no próximo boot do Claude Code. Ela ativa sozinha quando você escreve
ou audita código sensível, ou invoque na mão com `/secure-code`.

> Para o projeto inteiro (compartilhando com o time), copie para `.claude/skills/secure-code/`
> dentro do repositório em vez de `~/.claude/`.

### Cursor / Copilot / Lovable / outros agentes

Esses não usam skills do Claude Code. Copie o bloco **MODO 1** de
[`secure-code/SKILL.md`](secure-code/SKILL.md) para o `.cursorrules`, as *custom instructions* ou o
`CLAUDE.md` do seu projeto. O detalhe de cada vetor fica em
[`secure-code/references/vectors.md`](secure-code/references/vectors.md).

---

## Uso

- **Escrevendo código:** a skill guia o agente a gerar código seguro por padrão.
- **Auditando:** peça *"audite a segurança deste projeto usando a skill secure-code"*. O agente roda
  o toolkit (grep de segredos, probe de RLS, checagem de headers/CORS, subdomain takeover, SPF/DMARC),
  verifica cada achado e entrega um relatório priorizado por severidade.
- **Corrigindo:** peça a correção; o agente aplica o que é seguro e sinaliza o que precisa da sua mão.

---

## Estrutura

```
├── scan.sh                           # 🚀 scanner rodável (white-box + black-box)
├── Makefile                          # make test / make scan
├── tests/                            # suíte que PROVA que os detectores disparam
│   ├── run.sh
│   └── fixtures/{vulnerable,clean}/  # código vulnerável de propósito + código limpo
├── agents/
│   └── security-reviewer.md          # subagente do Claude Code que usa a skill
├── .github/workflows/scan.yml        # CI: roda os testes + self-scan (actions pinada por SHA)
└── secure-code/                      # a SKILL
    ├── SKILL.md                      # o cérebro: 3 modos + regras + falso-positivos
    └── references/
        ├── vectors.md                # 33 vetores: ❌ errado → ✅ certo + toolkit white-box E black-box
        ├── code-review-playbook.md   # metodologia de revisão de código, passo a passo
        └── audit-report-template.md  # formato do relatório de auditoria
```

> **White-box e black-box.** A skill foi feita para os dois cenários: revisar/construir o **próprio
> código** (você tem o repo → grep por vetor + playbook de revisão) e auditar um **alvo no ar**
> (sem código → probing externo). O ideal é combinar: o código diz *onde* olhar, o alvo vivo *confirma*.

---

## Contribuindo

Achou um vetor comum que falta? Um exemplo `errado → certo` melhor? Abra uma issue ou um PR.
Veja [`CONTRIBUTING.md`](CONTRIBUTING.md). Quanto mais gente revisar, mais forte fica.

## Aviso

Isto é uma camada de defesa, não uma garantia. Nenhum documento transforma um agente em pentester
perfeito — achados **críticos** merecem conferência humana antes de agir. Use como guardrail, não
como carimbo de "está seguro".

## Licença

[MIT](LICENSE) — use, copie, adapte, inclusive comercialmente. Só mantenha o aviso de licença.

---

## Fontes

- OX Security — *Vibe Coding Security*: https://www.ox.security/blog/vibe-coding-security/
- Cloud Security Alliance — *AI-Generated Code Vulnerability Surge*: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/
- Cloud Security Alliance — *Slopsquatting*: https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/
- SecurityWeek — *Vibe-Coded Apps Riddled With Flaws*: https://www.securityweek.com/vibe-coded-apps-riddled-with-exploitable-security-flaws/
- byteiota — *Supabase apps exposed by missing RLS*: https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/
- Precursor Security — *Testing Supabase RLS*: https://www.precursorsecurity.com/blog/row-level-recklessness-testing-supabase-security
- ToxSec — *Denial of Wallet*: https://www.toxsec.com/p/denial-of-wallet
- LayerX — *Denial of Wallet attacks*: https://layerxsecurity.com/generative-ai/denial-of-wallet-attacks/
- OWASP — *Cheat Sheet Series* (REST, JWT, GraphQL, Session): https://cheatsheetseries.owasp.org/
- OWASP — *Top 10 for LLM Applications*: https://genai.owasp.org/
- HackerOne — *Securely signing webhooks*: https://www.hackerone.com/blog/securely-signing-webhooks-best-practices-your-application
- Censys — *Dangling DNS / subdomain takeover*: https://censys.com/blog/dangling-dns-subdomain-takeover/
- DMARCLY — *Implementar SPF/DKIM/DMARC*: https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide
