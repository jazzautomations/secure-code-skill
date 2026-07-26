---
name: secure-code
description: >-
  Guardrails de segurança para escrever E auditar web apps — especialmente apps de IA /
  vibe-coded (Supabase, Next.js, Node, React). Use ANTES de escrever ou editar código que
  toque em auth, banco de dados, pagamentos, uploads, segredos/env vars, rotas de API,
  webhooks, JWT/sessão, cookies/tokens, CORS/headers ou DNS; e quando pedirem para revisar,
  auditar, endurecer (harden) ou fazer security review de um projeto. Previne e detecta:
  segredos expostos, RLS ausente/quebrada, IDOR/BOLA, XSS/SQLi/SSTI, token em localStorage,
  falhas de JWT (alg confusion/none), falta de rate limit (denial of wallet), webhook sem
  verificação, CORS/headers mal configurados, SSRF, race condition/TOCTOU, subdomain
  takeover, SPF/DKIM/DMARC ausente, .git/.env/source maps expostos, slopsquatting e mais.
---

# Secure Code — Guardrails para escrever e auditar apps

Você tem 3 modos. **Regra de ouro:** nunca confie no cliente, nunca confie no default do
framework, todo segredo fica no servidor. A IA otimiza pra "funcionar", não pra "ser seguro" —
segurança é responsabilidade sua, não default dela.

**Material de apoio (carregue sob demanda, não tudo de uma vez):**
- Detalhe de cada vetor com exemplo `errado → certo` + toolkit de comandos → leia `references/vectors.md`.
- Template de relatório de auditoria → `references/audit-report-template.md`.

---

## MODO 1 — PREVENIR (escrevendo/editando código)

Antes de entregar QUALQUER código que toque em auth, dados, pagamentos, uploads, env vars, DNS
ou chamadas externas, aplique estas regras. Se violar uma, PARE e corrija. Não peça permissão
pra ser seguro — seja seguro por padrão.

1. **Segredos** só no servidor via env var. Nunca hardcode, nunca client-side, nunca com prefixo
   público (`NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_`). Garanta `.env*` no `.gitignore`.
2. **Cliente é hostil:** preço, role, user_id, total, permissão SEMPRE revalidados no servidor
   contra o banco. Cliente manda "qual"; servidor decide "quanto/se pode".
3. **Autorização em toda rota** com dado de usuário: sessão + ownership (previne IDOR/BOLA).
   Admin checa role no backend. Update com allowlist de campos (previne mass assignment).
4. **Supabase/Postgres:** RLS ligada em toda tabela de usuário; policy por operação com
   `auth.uid()`; nunca `USING(true)`. `service_role` só no servidor.
5. **Injeção:** SQL parametrizado (nunca concatenar). Saída HTML sanitizada (XSS). Sem input cru
   em shell/eval/template/path (RCE/SSTI/path traversal).
6. **Sessão/token:** cookie HttpOnly+Secure+SameSite (não localStorage). IDs/tokens via CSPRNG
   (`crypto`), nunca `Math.random`. Regenerar sessão no login, invalidar no logout.
7. **JWT:** `algorithms` travado na verificação; rejeitar `none`/assinatura vazia; HS256 secret
   ≥32 bytes; nunca usar chave pública como secret HMAC.
8. **Headers** (CSP, HSTS, X-Frame-Options, nosniff) + **CORS** com allowlist (nunca `*`+credentials).
9. **Rate limit** em login/signup/reset/OTP e em endpoints de IA (limite por CUSTO/tokens). Key
   do LLM nunca no cliente — proxie no backend.
10. **Webhook:** verificar HMAC do corpo CRU + timestamp + `timingSafeEqual`; secret obrigatório;
    idempotência por `event.id`.
11. **Dependências:** só importar pacote confirmado (nome exato, mantenedor, downloads). Nunca
    inventar nome (slopsquatting). Fixar versões.
12. **Upload/SSRF:** validar magic bytes (não extensão) + tamanho; servir de bucket isolado sem
    execução; sem fetch de URL do usuário sem allowlist + bloqueio de IP privado/metadata.
13. **Prod:** sem stack trace/erro verboso/debug; sem `.git`/`.env`/source maps/Swagger/
    introspection expostos. Logs sem PII/segredo.
14. **Concorrência:** saldo/estoque/cupom/limite atualizados atomicamente (`UPDATE ... WHERE`,
    `FOR UPDATE` ou constraint) — nunca read-then-write (race condition/TOCTOU).
15. **Redirect/OAuth:** redirect e `redirect_uri` por match exato (sem wildcard/prefixo/URL crua).
16. **Validação server-side** de TODO input com schema (zod/pydantic). Front é UX, não segurança.

Para o exemplo `errado → certo` de qualquer item, abra `references/vectors.md` no vetor
correspondente.

---

## MODO 2 — DETECTAR (auditar projeto existente)

Fluxo obrigatório: **DETECTAR → VERIFICAR → REPORTAR**. Nunca reporte por "parece"; confirme.

1. **Mapeie a stack** (framework, banco, auth, deploy) antes de aplicar regras — adapte os
   exemplos JS/Supabase/Next à realidade do projeto.
2. **Rode as detecções mecânicas** (toolkit completo em `references/vectors.md`): grep de
   segredos, RLS probe com anon key, `curl` em `/.git` e `/.env`, headers, CORS, subdomain
   takeover (`dig`/`subfinder`), SPF/DMARC.
3. **verify-before-flag** (reduz falso-positivo — confirme o COMPORTAMENTO, não o formato):
   - RLS suspeita? Leia a tabela com a ANON key via REST. Volta dado de outro usuário → CONFIRMADO.
   - Segredo no front? Confirme que é segredo real E está no bundle servido. anon key COM RLS não é bug.
   - IDOR? Tente acessar o recurso de outro usuário com sua sessão. Só confirma se retornar.
   - Header ausente? Cheque na resposta HTTP real de produção, não só na config.
4. **Reporte** usando `references/audit-report-template.md`, ordenado por severidade.

**Severidade:** CRÍTICO (exposição total de dados/dinheiro: RLS off, service key no cliente,
segredo vivo, `.git`/`.env` acessível, IDOR sensível, webhook sem verificação, race em saldo,
subdomain takeover) · ALTO (takeover/fraude condicional: token em localStorage+XSS, JWT alg
confusion, reset fraco, sem rate limit em IA, CORS `*`+credentials) · MÉDIO (headers, source
maps/Swagger em prod, open redirect, SPF/DMARC, logs com PII, validação só no front) · BAIXO
(higiene: versões não fixadas, MFA opcional).

---

## MODO 3 — CORRIGIR

**✅ Pode corrigir sozinho (reversível, no código):** trocar localStorage por cookie HttpOnly;
parametrizar query; sanitizar saída; travar `algorithms` do JWT; adicionar headers/helmet; fechar
CORS; adicionar rate limit e validação de schema; verificar assinatura de webhook; tornar
operação de saldo atômica; adicionar `.env*` ao `.gitignore`; remover log de segredo.

**⛔ NUNCA auto-execute — PARE e escale ao humano:** rotacionar/revogar keys; mudar RLS/policies
em banco de PRODUÇÃO (gere migration, peça revisão); reescrever auth/pagamento inteiro; deletar
registros DNS; purgar segredo do histórico do git; qualquer coisa destrutiva/irreversível.

**Ao corrigir:** uma correção por vez, testável; não misture refactor com fix; depois RE-VERIFIQUE
(rode a mesma prova do MODO 2); se remover segredo do código, avise que ele **continua válido**
até ser rotacionado.

---

## 🚫 Falso-positivos comuns (NÃO reporte como bug)
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` / anon key no front → **correto** se a RLS estiver ligada (o bug é RLS off, não a key).
- `NEXT_PUBLIC_*`/`VITE_*` com valor não-sensível (URL pública, ID) → OK.
- JWT em cookie HttpOnly → correto.
- `service_role` dentro de Edge Function / código server-side → OK.
- CORS `*` em API 100% pública sem credenciais nem dado sensível → aceitável (confirme).
- ID/nome de plano vindo do cliente QUANDO o servidor revalida preço no banco → OK.
- `dangerouslySetInnerHTML` com conteúdo já sanitizado por DOMPurify → OK.
- Stack trace detalhado só em DEV → só é bug em produção.

Na dúvida entre CRÍTICO e falso-positivo, **teste** antes de reportar. Sem teste possível, marque
**PLAUSÍVEL** e diga qual teste manual confirma.

---

## Como injetar isto em outros agentes (Cursor/Copilot/Lovable/etc.)
Estes não usam skills do Claude Code. Para eles, copie o bloco do **MODO 1** para `.cursorrules`,
custom instructions ou `CLAUDE.md` do projeto. O detalhe de cada vetor está em `references/vectors.md`.
