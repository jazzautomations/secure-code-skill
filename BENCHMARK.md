# Benchmark & honestidade do scanner

Medido, não afirmado. Reproduza com `make test` e rodando `scan.sh` nos alvos.

## 1. Self-test (detectores + falso-positivo)
`make test` → **18/18**. Cada vetor tem fixture vulnerável (deve disparar) e o conjunto limpo
não pode gerar crítico/alto (inclui o caso clássico: `NEXT_PUBLIC_SUPABASE_ANON_KEY` no front **não**
é bug se a RLS está ligada; `service_role` em Edge Function/migration **não** é bug).

## 2. Benchmark externo — OWASP NodeGoat (app vulnerável de propósito)
Ground-truth: vulns estáticas documentadas do NodeGoat.

| Vuln documentada | Detecta? |
|---|---|
| `eval(req.body...)` — SSJI/RCE (A1) | ✅ SSJI |
| `cookieSecret` hardcoded (A6) | ✅ SECRETS-HARDCODED |
| crypto fraco `createCipheriv` estático (A6) | ✅ CRYPTO |
| open redirect `res.redirect(req...)` (A10) | ✅ OPENREDIR |

**Recall nas 4 vulns-estrela: 0/4 → 4/4** depois de corrigir os detectores (o scanner cru passava batido).

### Benchmark 2 — DVWA (PHP vulnerável de propósito)
Testa fora do mundo JS/Go. Ground-truth: SQLi, command injection, crypto fraco, XSS.

| Vuln DVWA | Detecta? |
|---|---|
| SQL injection PHP (`"...'$id'"` + mysqli) | ✅ SQLI (12 hits em `vulnerabilities/sqli`) — era **0** antes de adicionar o padrão PHP de interpolação |
| Command injection (`shell_exec('ping '.$target)`) | ✅ CMDI (8) |
| Crypto fraco (md5 etc.) | ✅ CRYPTO (11) |
| eval/SSJI, secret hardcoded | ✅ SSJI (6), SECRETS-HARDCODED (6) |

## 3. Precisão em código real (repos próprios, bem construídos)
`mastersinger` e `360aa-platform`:

| | scanner cru | depois do tuning |
|---|---|---|
| 🔴 críticos (soma) | **167** (100% falso-positivo) | **0** |
| 🟠 altos mastersinger | 62 | 8 (reais: `using(true)` a revisar) |
| 🟠 altos 360aa | 5 | 2 (1 `os.system` em script, real) |
| 🟡 médios mastersinger | 76 | 2 (CICD sem pin de SHA, real) |
| 🟡 médios 360aa | 175 | 2 (`.env` no gitignore, 1 dangerouslySetInnerHTML) |

Os 167 falsos eram `service_role` em `.sql`/migrations/Edge Functions (uso legítimo server-side).
Os mediums caíram triando: CORS `*` em edge (boilerplate) → INFO; `innerHTML=''` (limpar) e
comentários → não são XSS; ruído de lockfile fora do escopo.

## ⚠️ Limitações honestas (o que o scanner NÃO faz)
1. **IDOR é heurístico grosso (nível de arquivo).** Flag arquivo sem nenhuma referência a dono/
   sessão; NÃO pega IDOR por-handler num arquivo que tem ownership em outra função. É candidato,
   o agente confirma lendo.
2. **Grep não vê runtime/lógica.** Race condition, bypass de fluxo de auth, lógica de negócio →
   só com leitura (o agente `security-reviewer`), não com regex.
3. **Dois benchmarks externos (NodeGoat + DVWA).** Cobrem vulns estáticas (JS + PHP). App de vuln
   puramente runtime (ex: Juice Shop) pontuaria baixo — grep tem teto.
4. **Mediums triados** (crítico/alto/médio limpos nos repos reais). O que sobra em INFO é
   heurística de baixa confiança (CORS edge, over-fetch, PII-LLM) — de propósito, pra revisão.
5. **Requer bash 4+ e GNU grep** (arrays associativos, `grep -P`). Não roda no bash 3.2 do macOS puro.
6. **shellcheck não rodado** (ausente no ambiente); validado com `bash -n` + testes de robustez
   (dir vazio / path com espaço / inexistente não quebram).

## Veredito medido
Primeira-passada mecânica **sólida e precisa** (0 falso-crítico em código real, 4/4 no benchmark),
que **estreita** o trabalho — não substitui a leitura do agente para IDOR/lógica. É copiloto, não
carimbo de "seguro".
