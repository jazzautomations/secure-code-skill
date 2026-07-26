# Vetores — referência errado→certo + toolkit

Referência condensada dos 28 vetores para o agente consultar no ponto de uso. Cada item traz o
padrão inseguro (❌) e o seguro (✅). Contexto e casos reais que motivam cada vetor estão no
`README.md` do repositório.

---

## 1. Segredos expostos
❌ `new Stripe("sk_live_...")` · `process.env.NEXT_PUBLIC_OPENAI_API_KEY`
✅ `new Stripe(process.env.STRIPE_SECRET_KEY)` (sem prefixo público) · `.env*` no `.gitignore`
> `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` = vão pro browser. Se vazou, rotacione a key (git history mantém viva).

## 2. RLS (Supabase/Postgres)
❌ tabela sem RLS · `create policy p on t for select using (true)`
✅ `alter table t enable row level security;` + policy por operação `using (auth.uid() = user_id)`
> service_role bypassa RLS → só no servidor. Cuidado com tabelas de token/OTP/reset legíveis por anon.

## 3. IDOR / BOLA
❌ `db.order.findUnique({ where: { id: req.params.id }})`
✅ `db.order.findFirst({ where: { id: req.params.id, userId: session.userId }})` → 404 se não achar
> Mass assignment: nunca `update(req.body)` cru; selecione campos. Admin checa role no backend.

## 4. Confiar no cliente / pagamentos
❌ `unit_amount: req.body.amount`
✅ servidor busca `plan.stripePriceId` pelo slug do plano e usa o preço do banco
> Entitlement só via webhook verificado, nunca no `/success`. Idempotência por event.id.

## 5. Webhook sem assinatura
✅ `stripe.webhooks.constructEvent(req.rawBody, sig, WEBHOOK_SECRET)` (corpo CRU)
✅ genérico: HMAC-SHA256 do body cru + `crypto.timingSafeEqual` + timestamp anti-replay. Secret obrigatório.

## 6. Token em localStorage
❌ `localStorage.setItem("token", jwt)`
✅ `res.cookie("session", jwt, { httpOnly:true, secure:true, sameSite:"lax" })` + CSRF

## 7. XSS
❌ `<div dangerouslySetInnerHTML={{__html: comment.body}}/>`
✅ `<div>{comment.body}</div>` · se precisar HTML: `DOMPurify.sanitize(...)` + CSP

## 8. Injeção SQL/comando
❌ `db.query(\`... email='${email}'\`)` · `exec(\`convert ${f} out.png\`)`
✅ `db.query("... email=$1", [email])` · `execFile("convert",[safePath,"out.png"])`

## 9. Headers de segurança
✅ CSP · HSTS `max-age=63072000; includeSubDomains; preload` · X-Content-Type-Options: nosniff ·
   X-Frame-Options: DENY · Referrer-Policy · Permissions-Policy. Next: `headers()`; Express: `helmet`. Desligue X-Powered-By.

## 10. CORS
❌ `cors({ origin:"*", credentials:true })`
✅ `cors({ origin:(o,cb)=>cb(null,allow.includes(o)), credentials:true })`

## 11. Rate limit / Denial of Wallet
✅ `rateLimit({ windowMs:60000, max:5, keyGenerator:r=>r.ip+r.body.email })`
✅ IA: key proxied no backend · `max_tokens` + timeout · teto diário/usuário · spend cap no provedor.

## 12. Upload / SSRF
❌ validar por extensão · `fetch(req.body.imageUrl)`
✅ magic bytes + tamanho + nome novo + bucket isolado sem execução; SVG tratado.
✅ SSRF: allowlist de host + bloqueio de IP privado/link-local/metadata (169.254.169.254); sem redirects.

## 13. Slopsquatting / dependências
✅ só importar pacote confirmado (nome exato, mantenedor, downloads). Lockfile + versões fixas. `npm audit`/`pip-audit`.

## 14. Auth / reset de senha
✅ token de reset CSPRNG ≥128 bits, HASHEADO no banco, expira 15-30min, uso único · sem user enumeration ·
   rate limit · argon2/bcrypt · MFA.

## 15. Erros verbosos / logs / PII
✅ prod: erro genérico pro cliente, detalhe só no log interno · nunca logar senha/token/PII/cartão ·
   sanitizar input antes de logar (log injection).

## 16. Prompt injection (app com IA)
✅ tools com least privilege (sem service_role) · human-in-the-loop em ação destrutiva ·
   tratar saída do LLM como não-confiável (sanitize antes de SQL/HTML/shell).

## 17. Subdomain takeover / dangling DNS
✅ apague o DNS ANTES de deletar o recurso; audite CNAMEs pendurados (staging/dev/old/test);
   monitoramento contínuo. Vetor comum: bucket/CloudFront deletado com CNAME vivo.

## 18. JWT alg confusion / none / secret fraco
❌ `jwt.verify(token, key)` (aceita o alg do token)
✅ `jwt.verify(token, secret, { algorithms:["HS256"] })` · rejeitar `none`/assinatura vazia ·
   HS256 secret ≥32 bytes aleatórios · nunca chave pública como secret HMAC.

## 19. Race condition / TOCTOU
❌ `find(); if(balance>=x) update(balance-x)` (dois passos)
✅ `UPDATE users SET balance=balance-${x} WHERE id=${id} AND balance>=${x}` (atômico) ou `SELECT ... FOR UPDATE` ou constraint única.

## 20. Arquivos/rotas expostos
✅ prod não serve `.git`/`.env`/`.bak`/`.sql` do webroot · source maps off ou restritos ·
   Swagger/GraphQL playground/introspection off · `/admin` com auth+role · directory listing off.

## 21. Open redirect / OAuth redirect_uri
❌ `res.redirect(req.query.next)`
✅ só path relativo interno (`startsWith("/") && !startsWith("//")`) ou allowlist exata. OAuth: match exato.

## 22. Path traversal / SSTI
❌ `fs.readFile("./uploads/"+req.query.file)` · `ejs.render("Olá "+req.body.name)`
✅ `path.basename` + `path.resolve` confinado ao dir · `ejs.render("Olá <%= name %>", { name })` (dado como variável)

## 23. GraphQL
✅ introspection off em prod · depth/complexity limit · batching/alias limitado · authz no resolver · rate limit por custo.

## 24. Email spoofing (SPF/DKIM/DMARC)
✅ SPF `v=spf1 include:... -all` · DKIM ativo · DMARC começa `p=none`+`rua=`, sobe pra `p=reject`.
   Domínios que não enviam email: SPF `-all` + DMARC `p=reject`.

## 25. Sessão: randomness / fixation / logout
❌ `Math.random().toString(36)` como token
✅ `crypto.randomBytes(32).toString("hex")` · regenerar ID no login/privilégio · logout invalida no servidor.

## 26. Object storage público (S3/GCS/Supabase Storage)
✅ buckets privados por default · signed URLs de curta duração · policies por dono · sem listagem pública.

## 27. Logging & monitoramento (detecção)
✅ logar login falho / mudança de senha-role / acesso negado / pico de custo de IA · alerta de anomalia · sem PII/segredo.

## 28. Validação server-side
✅ schema (zod/pydantic/joi) em TODO input no servidor: tipo, tamanho, range, enum allowlist, rejeitar campos extras.

---

# 🔍 TOOLKIT BLACK-BOX (alvo no ar)

```bash
# 1. Segredos hardcoded
grep -rEn "sk_live|sk_test|service_role|eyJ[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE)" \
  --include=*.{js,ts,jsx,tsx,py,env,json,yml,yaml} .
gitleaks detect --source .        # ou trufflehog filesystem .
git log --all --full-history -- .env

# 2. Segredo no bundle client-side
grep -rn "NEXT_PUBLIC_\|VITE_\|REACT_APP_" . | grep -iE "secret|service|key|token|password"

# 3. Arquivos sensíveis expostos em PROD (troque o host)
for p in .git/config .env .env.production .git/HEAD config.php settings.py backup.sql; do
  echo -n "$p -> "; curl -s -o /dev/null -w "%{http_code}\n" https://SEU-HOST/$p
done   # != 403/404 é problema

# 4. Headers
curl -sI https://SEU-HOST | grep -iE "content-security|strict-transport|x-frame|x-content-type|referrer-policy"

# 5. CORS permissivo
curl -s -H "Origin: https://evil.com" -I https://SEU-HOST/api/qualquer | grep -i access-control

# 6. Supabase RLS na marra (anon key) — se voltar dado de outros = RLS quebrada
curl -s "https://SEU-PROJ.supabase.co/rest/v1/profiles?select=*" \
  -H "apikey: SUA_ANON_KEY" -H "Authorization: Bearer SUA_ANON_KEY"
# no SQL editor: select tablename,rowsecurity from pg_tables where schemaname='public';
#                select * from pg_policies where schemaname='public';  -- procure using 'true'

# 7. Subdomain takeover / DNS
subfinder -d DOMINIO | while read s; do echo -n "$s -> "; dig +short CNAME $s; done
# ou: nuclei -t takeovers/
# DOMÍNIO PRÓPRIO: não adivinhe por wordlist (wildcard "*" faz tudo resolver e nomes custom
# escapam). Puxe a lista REAL de deploys: `vercel ls` / `vercel domains ls`, painel Cloudflare,
# ou o provedor de DNS. Confirme cada host com HTTP: x-vercel-error DEPLOYMENT_NOT_FOUND = wildcard
# vazio (NÃO é takeover, a Vercel controla o IP), 200 = deploy real.
# crt.sh (pode ser lento): curl -s "https://crt.sh/?q=%25.DOMINIO&output=json"

# 8. Email auth
dig +short TXT DOMINIO | grep spf1
dig +short TXT _dmarc.DOMINIO

# 9. Dependências
npm audit --production   # ou pip-audit / osv-scanner -r .

# 10. Scanner de superfície
nuclei -u https://SEU-HOST
```

---

# 🔬 TOOLKIT WHITE-BOX (revisão de código — track principal)

Rode na raiz do repositório. **Cada hit é um PONTO DE PARTIDA, não um veredito** — abra o arquivo
e leia a lógica antes de reportar (regra verify-before-flag). Ajuste `--include` à linguagem.

```bash
# 1. Segredos hardcoded no código
grep -rEn "sk_live_|sk_test_|service_role|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE)|(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9/_+-]{16,}" \
  --include=*.{js,ts,jsx,tsx,py,go,rb,php,env,json,yml,yaml} . | grep -v node_modules
gitleaks detect --source .          # varredura dedicada
git log -p --all -- .env .env.* | head   # segredo já esteve no histórico?
test -f .gitignore && grep -q "^\.env" .gitignore || echo "⚠️ .env NÃO está no .gitignore"

# 1b. Segredo com prefixo público (vaza no bundle do browser)
grep -rEn "(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z_]*(SECRET|SERVICE|PRIVATE|PASSWORD|TOKEN|KEY)" . | grep -v node_modules
# (SUPABASE_ANON_KEY / URL pública aqui = OK; SERVICE_ROLE aqui = CRÍTICO)

# 2/4. RLS (Supabase) — nas migrations/SQL
grep -rEn "create table|enable row level security|create policy|using ?\(true\)|with check ?\(true\)" \
  supabase/ migrations/ **/*.sql 2>/dev/null
# Liste tabelas SEM 'enable row level security' e policies com using(true). E o pior:
grep -rEn "service_role|SERVICE_ROLE_KEY|serviceRole" src/ app/ components/ pages/ 2>/dev/null
# ^ service_role em código de CLIENTE = exposição total do banco (CRÍTICO)

# 3. IDOR/BOLA — queries que usam id da request sem ownership
grep -rEn "findUnique|findFirst|\.eq\(['\"]id|where.*(params|query)|req\.(params|query|body)\.(id|user_?[Ii]d)" src/ app/ pages/ 2>/dev/null
# Abra cada rota: ela filtra por dono (session.userId) ou confia no id que veio? Admin checa role no server?

# 4. Confiar no cliente (preço/role/permissão)
grep -rEn "req\.body\.(amount|price|total|role|is_?[Aa]dmin|isPremium)|unit_amount|price_data|body\.(role|amount|price)" . | grep -v node_modules

# 5. Webhook sem verificação
grep -rEn "webhook|constructEvent|verifyHeader|createHmac|timingSafeEqual|X-Hub-Signature|stripe-signature" . | grep -v node_modules
# O handler verifica assinatura do corpo CRU antes de agir? Secret vem de env e não é vazio?

# 6/25. Token/segredo em localStorage + randomness fraco
grep -rEn "localStorage|sessionStorage" . | grep -iE "token|jwt|auth|session|access" | grep -v node_modules
grep -rEn "Math\.random" . | grep -iE "token|id|secret|otp|reset|password|nonce|session" | grep -v node_modules

# 7. XSS — saída não sanitizada
grep -rEn "dangerouslySetInnerHTML|innerHTML|v-html|\.html\(|render_template_string|\|\s*safe" . | grep -v node_modules

# 8/22. Injeção SQL/comando/SSTI/path
grep -rEn "query\(\`|execute\(f['\"]|\.raw\(|SELECT .*(\+|\$\{)|child_process|exec\(|eval\(|os\.system|subprocess.*shell=True" . | grep -v node_modules
grep -rEn "readFile.*(req|params|query)|path\.join\(.*(req|params|query)" . | grep -v node_modules   # path traversal

# 9/10. Headers + CORS
grep -rEn "helmet|Content-Security-Policy|Strict-Transport|X-Frame-Options" . | grep -v node_modules   # ausência = gap
grep -rEn "origin: ?['\"]\*|origin: ?true|Access-Control-Allow-Origin.*\*|cors\(\)" . | grep -v node_modules

# 11. Rate limit (ausência em auth / IA = gap)
grep -rEn "rateLimit|express-rate-limit|Ratelimit|upstash/ratelimit|throttle|slow-?down" . | grep -v node_modules
grep -rEn "max_tokens|maxTokens" . | grep -v node_modules   # endpoint de IA sem teto de tokens?

# 14/16. Reset de senha, hash, JWT
grep -rEn "reset_?[Tt]oken|forgotPassword|bcrypt|argon2|scrypt|md5|sha1\b" . | grep -v node_modules
grep -rEn "jwt\.verify|jsonwebtoken|jose|decode\(|algorithms|['\"]none['\"]|HS256|RS256" . | grep -v node_modules
# jwt.verify tem { algorithms: [...] } explícito? Rejeita none?

# 19. Race condition / TOCTOU (read-then-write em saldo/estoque/cupom)
grep -rEn "balance|saldo|stock|estoque|quantity|coupon|cupom|credits|créditos" . | grep -iE "update|-=|\+=|- ?amount" | grep -v node_modules
grep -rEn "FOR UPDATE|\\\$transaction|BEGIN;|SELECT .* FOR|serializable" . | grep -v node_modules   # existe lock/transação?

# 28. Validação server-side (rotas usando req.body sem schema)
grep -rLEn "zod|yup|joi|pydantic|valibot|class-validator" $(grep -rlE "req\.body" src/ app/ pages/ 2>/dev/null) 2>/dev/null

# 12. Upload / SSRF
grep -rEn "multer|formidable|busboy|\.upload|fetch\(.*(req|params|query)|axios.*(req\.(body|query|params))" . | grep -v node_modules

# 13. Dependências (slopsquatting / vulneráveis)
test -f package-lock.json -o -f pnpm-lock.yaml -o -f yarn.lock || echo "⚠️ sem lockfile"
npm audit || pip-audit || osv-scanner -r .
```

> **Regra de leitura:** grep dá o *onde*, você dá o *veredito* abrindo o arquivo. Um `Math.random`
> num gerador de cor não é bug; num gerador de token de reset é CRÍTICO. Sempre leia o contexto.
