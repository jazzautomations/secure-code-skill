# Benchmark & honestidade do scanner

Medido, não afirmado. Reproduza: `make test` e rode `scan.sh` em qualquer alvo.

## 1. Self-test (detectores + falso-positivo)
`make test` → **18/18**. Cada vetor tem fixture vulnerável (deve disparar) e um conjunto limpo
que **não pode** gerar crítico/alto. Inclui os casos clássicos que confundem scanner cru:
`NEXT_PUBLIC_SUPABASE_ANON_KEY` no front **não** é bug se a RLS está ligada; `service_role` em
Edge Function/migration **não** é bug (uso legítimo server-side). Esses passam limpo.

## 2. Benchmark externo — OWASP NodeGoat (app vulnerável de propósito)
Ground-truth: vulns estáticas documentadas do NodeGoat.

| Vuln documentada | Detecta? |
|---|---|
| `eval(req.body...)` — SSJI/RCE (A1) | ✅ SSJI |
| `cookieSecret` hardcoded (A6) | ✅ SECRETS-HARDCODED |
| crypto fraco `createCipheriv` estático (A6) | ✅ CRYPTO |
| open redirect `res.redirect(req...)` (A10) | ✅ OPENREDIR |

**Recall nas 4 vulns-estrela: 4/4.**

### Benchmark 2 — DVWA (PHP vulnerável de propósito)
Testa fora do mundo JS/Go. Ground-truth: SQLi, command injection, crypto fraco, XSS.

| Vuln DVWA | Detecta? |
|---|---|
| SQL injection PHP (`"...'$id'"` + mysqli) | ✅ SQLI (12 hits em `vulnerabilities/sqli`) |
| Command injection (`shell_exec('ping '.$target)`) | ✅ CMDI (8) |
| Crypto fraco (md5 etc.) | ✅ CRYPTO (11) |
| eval/SSJI, secret hardcoded | ✅ SSJI (6), SECRETS-HARDCODED (6) |

## 3. Precisão em código real (baixo falso-positivo)
Rodado em **2 apps reais em produção, bem construídos** (Next.js + Supabase e Python/Flask).
Grep cru é ruidoso por natureza — por isso o scanner é **calibrado** para não gritar em uso
legítimo. Resultado medido nesses 2 apps:

| Severidade | Resultado |
|---|---|
| 🔴 Críticos | **0 falso-positivo** |
| 🟠 Altos | só achados reais a revisar (ex: policy RLS permissiva) |
| 🟡 Médios | só achados reais (ex: CI/CD sem pin de SHA) |

A calibração que zera o ruído: `service_role` em `.sql`/migration/Edge Function é legítimo (não
crítico); `Math.random` só é alto em contexto de segurança (token/senha), não em UI; RLS `using(true)`
pula comentário e teste; hash bcrypt/argon não é "secret hardcoded"; CORS `*` em boilerplate de
Edge vira INFO, não médio. O que sobra é sinal, não barulho.

## 4. Prevenção medida (o MODO 1 reduz vulnerabilidade?) — A/B
Dois agentes idênticos construíram a MESMA API (login, `/users/:id`, webhook Stripe, busca,
credenciais, CORS). Um **sem** guardrail, um **com** o MODO 1 injetado. Scanner nos dois:

| | Baseline (sem MODO 1) | Com MODO 1 |
|---|---|---|
| 🔴 Crítico | 1 (secret hardcoded) | **0** |
| 🟠 Alto | 2 (token em localStorage) | **0** |
| 🟡 Médio | 2 (CORS aberto + IDOR) | **0** |

O baseline saiu com senha em texto, `/users/:id` sem auth, `cors()` aberto e token em localStorage;
o guarded usou bcrypt, ownership check, cookie HttpOnly, HMAC no webhook e CORS allowlist.
**Caveat honesto:** n=1 task, medido pelo scanner (não por pentester humano). É sinal forte e
direcional, não prova estatística.

## ⚠️ Limitações honestas (o que o scanner NÃO faz)
1. **IDOR é heurístico grosso (nível de arquivo).** Flag arquivo sem nenhuma referência a dono/
   sessão; NÃO pega IDOR por-handler num arquivo que tem ownership em outra função. É candidato,
   o agente confirma lendo.
2. **Grep não vê runtime/lógica.** Race condition, bypass de fluxo de auth, lógica de negócio →
   só com leitura (o agente `security-reviewer`), não com regex.
3. **Dois benchmarks externos (NodeGoat + DVWA).** Cobrem vulns estáticas (JS + PHP). App de vuln
   puramente runtime (ex: Juice Shop) pontuaria baixo — grep tem teto.
4. **Requer bash 4+ e GNU grep** (arrays associativos, `grep -P`). Não roda no bash 3.2 do macOS puro.
5. **shellcheck não rodado** (ausente no ambiente); validado com `bash -n` + testes de robustez
   (dir vazio / path com espaço / inexistente não quebram).

## Veredito medido
Primeira-passada mecânica **sólida e precisa** (0 falso-crítico em código real, 4/4 nos benchmarks
externos), que **estreita** o trabalho — não substitui a leitura do agente para IDOR/lógica. É
copiloto, não carimbo de "seguro".
