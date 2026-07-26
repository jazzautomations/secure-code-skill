# Playbook de Revisão de Código (White-box)

Metodologia sistemática para revisar a segurança de um repositório. Siga a ordem — ela vai do
mais grave (exposição total) ao endurecimento. Cada passo aponta o vetor correspondente em
`vectors.md` e o grep do TOOLKIT WHITE-BOX. Não pule o **verify-before-flag**: o grep aponta, você
confirma lendo o arquivo.

> Vale tanto **ao construir** (revise seu próprio diff antes de commitar) quanto **ao auditar** um
> repo inteiro. Ao construir, rode isto no diff (`git diff`); ao auditar, no repo todo.

---

## Passo 0 — Contexto, stack e versões (SEMPRE PRIMEIRO)
Antes de caçar bug, entenda o projeto — regra aplicada na stack errada é ruído:
- **O que o projeto FAZ** e quem usa (define o que é dado sensível e o modelo de ameaça).
- **Stack:** leia `package.json`/`requirements.txt`/`go.mod` — framework, ORM, libs de auth/pagamento.
- **Versões (crítico):** deps desatualizadas, **versões com CVE conhecida** e **runtime EOL** (Node/
  Python/PHP sem suporte). Rode `npm audit`/`npm outdated`, `pip-audit`, `govulncheck ./...`,
  `osv-scanner -r .`. Cheque runtime no endoflife.date. Versão vulnerável de framework/lib é bug
  por si só (às vezes o mais grave e o mais fácil de corrigir: subir a versão).
- **Deploy & env:** `vercel.json`/`netlify.toml`/`Dockerfile`, `.env.example`, `next.config.js`.
- **Estrutura:** onde ficam as **rotas/endpoints**, a **camada de dados** (queries/ORM/migrations)
  e o **código de auth**. Esses três são 80% da superfície de ataque.
- **Fronteira cliente/servidor:** o que roda no browser vs no servidor. Tudo que é client-side é
  público — trate como tal.

## Passo 1 — Segredos (vetor 1) 🔴
- Rode o grep de segredos + `NEXT_PUBLIC_` sensível + `gitleaks` + `git log -p -- .env`.
- Confirme: a string é segredo real? Está em código que vai pro bundle client?
- Cheque `.gitignore` cobre `.env*`.
- **Se achar segredo vivo:** reporte CRÍTICO e avise que precisa ROTACIONAR (git history mantém vivo).

## Passo 2 — Camada de dados / RLS (vetores 2, 26) 🔴
- Abra as **migrations/SQL**. Para cada tabela com dado de usuário: tem `enable row level security`?
  Tem policy por operação filtrando por `auth.uid()`? Existe `using(true)`?
- Procure `service_role` fora de código server-only (Edge Function/API route). No client = CRÍTICO.
- Storage/buckets: privados? policies por dono?

## Passo 3 — Autenticação & autorização (vetores 3, 6, 14, 16-JWT, 25) 🔴🟠
- **Toda rota/endpoint** que lê ou escreve dado de usuário: checa sessão E ownership? (grep IDOR)
  Abra cada uma — confia no `id` da request ou filtra por dono?
- **Rotas admin:** checam role no servidor (não só escondem botão)?
- **Update:** allowlist de campos ou `update(req.body)` cru (mass assignment)?
- **JWT:** `verify` com `algorithms` explícito? rejeita `none`? secret forte de env?
- **Sessão:** token em cookie HttpOnly (não localStorage)? regenera no login? invalida no logout?
- **Reset de senha:** token CSPRNG, hasheado, curto, uso único? sem user enumeration?
- **Hash de senha:** argon2/bcrypt (não md5/sha1)?

## Passo 4 — Confiança no cliente & dinheiro (vetores 4, 5, 19) 🔴🟠
- Preço/total/role/quantidade vêm do cliente e são usados sem revalidar no banco?
- Pagamento: entitlement liberado por **webhook verificado** ou no redirect de sucesso?
- Webhook: verifica assinatura do corpo cru + secret não-vazio + idempotência?
- Saldo/estoque/cupom: operação **atômica** (`UPDATE ... WHERE`/`FOR UPDATE`/transação) ou
  read-then-write (race/TOCTOU)?

## Passo 5 — Injeção & entrada (vetores 7, 8, 22, 28, 12) 🟠
- SQL: parametrizado ou concatenado?
- Saída HTML: escapada ou `dangerouslySetInnerHTML`/`innerHTML` sem sanitizar (XSS)?
- Shell/eval/template/filesystem com input do usuário (RCE/SSTI/path traversal)?
- **Validação server-side:** rotas com `req.body` têm schema (zod/pydantic)? (grep 28)
- Upload: valida conteúdo (magic bytes) e não extensão? SSRF em `fetch` de URL do usuário?

## Passo 6 — Configuração & rede (vetores 9, 10, 11, 20, 21, 13) 🟡
- Headers de segurança (helmet/CSP/HSTS/X-Frame/nosniff) configurados?
- CORS: allowlist ou `*` (+credentials)?
- Rate limit em login/signup/reset/OTP e em endpoints de IA (por custo)?
- Prod não expõe `.git`/`.env`/source maps/Swagger/introspection; sem erro verboso?
- Redirect/OAuth `redirect_uri` por match exato?
- Dependências: lockfile presente? `npm audit`/`pip-audit` limpo? algum pacote inventado (slopsquatting)?

## Passo 7 — App com IA/agente (vetor 16) 🟠
Se o projeto usa LLM: tools com least privilege? human-in-the-loop em ação destrutiva? saída do
LLM sanitizada antes de virar SQL/HTML/shell? defesa contra prompt injection?

## Passo 8 — Logging & detecção (vetores 15, 27) 🟡
- Logs sem PII/segredo? input sanitizado antes de logar (log injection)?
- Eventos de segurança logados + alerta de anomalia/spend?

---

## Fechamento
1. **Ordene por severidade** e reporte com `audit-report-template.md`.
2. **Liste os falso-positivos descartados** (dá confiança no relatório).
3. **Correção:** aplique o que é seguro (MODO 3), escale o que é destrutivo (rotacionar key, RLS em
   prod, DNS, histórico do git).
4. **Re-verifique** cada fix rodando de novo a prova que confirmou a falha.
