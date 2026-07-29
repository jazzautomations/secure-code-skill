#!/usr/bin/env bash
# secure-code scanner — white-box (repo) + black-box (URL)
# Parte da skill secure-code: https://github.com/jazzautomations/secure-code-skill
#
# Uso:
#   ./scan.sh [CAMINHO]                 white-box no repositório (default: .)
#   ./scan.sh --url https://alvo        black-box num alvo no ar
#   ./scan.sh --url URL [CAMINHO]       os dois (grey-box)
#   ./scan.sh --json [...]              saída JSON (findings[])
#
# Cada achado é PONTO DE PARTIDA, não veredito — leia o arquivo antes de agir (verify-before-flag).
# Requer: bash, grep, curl, dig. Usa se presentes: osv-scanner, govulncheck.
set -uo pipefail

TARGET_PATH=""
URL=""
JSON=0
PATH_ERR=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) TARGET_PATH="$1"; shift ;;
  esac
done
[ -z "$TARGET_PATH" ] && [ -z "$URL" ] && TARGET_PATH="."

FINDINGS="$(mktemp)"; trap 'rm -f "$FINDINGS"' EXIT
GREP_INCLUDE=(--include=*.js --include=*.ts --include=*.jsx --include=*.tsx --include=*.py
  --include=*.go --include=*.rb --include=*.php --include=*.sql --include=*.yml --include=*.yaml
  --include=*.json --include=*.env --include=*.tf --include=*.html --include=*.vue
  --include=*.svelte --include=*.astro)
EXCLUDE='node_modules|/\.git/|dist/|build/|\.next/|vendor/|\.min\.|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|/tutorial/'

finding() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$FINDINGS"; }

# service_role só é CRÍTICO se estiver em código CLIENT-SIDE. Em .sql (migrations/GRANT),
# Edge Functions e paths server-only é uso LEGÍTIMO → INFO. (mata falso-positivo em massa)
SERVER_ONLY='\.sql:|supabase/functions|/api/|/server/|/backend/|/functions/|/migrations/|\.server\.|/edge|/scripts/|/cli/|/cmd/'
hardcoded_secret_check() {
  # KEY : "valor-literal"  (secret/senha/apikey com string embutida, não env)
  grep -rPIin "${GREP_INCLUDE[@]}" -- '(secret|passwd|password|api_?key|apikey|private_?key|access_?key|auth_?token)[a-z_]*[\x22\x27]?\s*[:=]\s*[\x22\x27][^\x22\x27]{6,}[\x22\x27]' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -viE '\.(test|spec)\.|/__tests__/' \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"; local content="${rest#*:}"
        # pula comentário (código morto), env, import, placeholder e exemplo
        echo "$content" | grep -qE '^[[:space:]]*(//|--|\*|#|/\*)' && continue
        echo "$content" | grep -qiE 'process\.env|getenv|os\.environ|import |require\(|your_|example|placeholder|xxxx|\*\*\*|\$\{|<[a-z]+>|\$2[aby]\$|\$argon2|\$scrypt' && continue
        finding CRITICAL SECRETS-HARDCODED "$loc:$ln" "segredo/senha hardcoded em literal — mover para variável de ambiente"
      done
}

xss_check() {
  # dangerouslySetInnerHTML / v-html / innerHTML = <dinâmico> ; pula comentário e innerHTML='' (limpar)
  grep -rEn "${GREP_INCLUDE[@]}" -- 'dangerouslySetInnerHTML|v-html|\.innerHTML[[:space:]]*\+?=[[:space:]]*[^"'"'"' [:space:];]|\.outerHTML[[:space:]]*=[[:space:]]*[^"'"'"' [:space:];]|(insertAdjacentHTML|document\.write(ln)?)\([^)]*(\+|location|hash|search|href|req|request|params|query|input|value|user|data|\$\{)' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -viE '\.(test|spec)\.|/__tests__/' \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"; local content="${rest#*:}"
        echo "$content" | grep -qE '^[[:space:]]*(//|--|\*|#|/\*)' && continue
        finding MEDIUM XSS "$loc:$ln" "saída HTML dinâmica sem sanitização (XSS) — confirmar DOMPurify/escape"
      done
}

deser_check() {
  # desserialização insegura: pickle/marshal/yaml.load sem SafeLoader/unserialize
  grep -rEn "${GREP_INCLUDE[@]}" -- 'pickle\.loads?\(|marshal\.loads|yaml\.load\(|[^_]unserialize\(|node-serialize' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -viE '\.(test|spec)\.|/__tests__/' \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"; local content="${rest#*:}"
        echo "$content" | grep -qE '^[[:space:]]*(//|--|\*|#|/\*)' && continue
        # yaml.load COM SafeLoader/safe_load é uso legítimo → pula
        echo "$content" | grep -qiE 'yaml\.load\(' && echo "$content" | grep -qiE 'SafeLoader|safe_load' && continue
        finding HIGH DESERIAL "$loc:$ln" "desserialização de dado não confiável (RCE) — use formato seguro (json/safe_load)"
      done
}

idor_check() {
  # arquivo que pega id da request mas NÃO referencia dono/sessão → candidato a IDOR
  grep -rlEI "${GREP_INCLUDE[@]}" -- 'params\.id|Params\("id"\)|req\.query\.id|request\.args\[.id|\$_(GET|POST|REQUEST)\[[^]]*id' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -viE '\.(test|spec)\.|/__tests__/' \
    | while IFS= read -r f; do
        if ! grep -qiE 'user_?id|session|auth\.uid|locals\(.user_id|current_?user|owner|req\.user|getUser' "$f" 2>/dev/null; then
          finding MEDIUM IDOR "$f" "usa id da request sem referência a dono/sessão no arquivo — confirmar ownership (IDOR/BOLA)"
        fi
      done
}

rls_check() {
  grep -rEn "${GREP_INCLUDE[@]}" -- 'using ?\(true\)|with check ?\(true\)|USING ?\(TRUE\)' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -viE '/__tests__/|\.(test|spec)\.' \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"; local content="${rest#*:}"
        # pula linha de comentário (não é policy de verdade, é doc/aviso)
        echo "$content" | grep -qE '^[[:space:]]*(//|--|\*|#|/\*)' && continue
        finding HIGH RLS "$loc:$ln" "policy RLS libera geral (using(true)) — confirmar se a tabela é pública de propósito"
      done
}

random_check() {
  grep -rEn "${GREP_INCLUDE[@]}" -- 'Math\.random|math/rand|mt_rand\(|random\.(random|randint|choice)' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"; local content="${rest#*:}"
        echo "$content" | grep -qE '^[[:space:]]*(//|--|\*|#|/\*)' && continue
        if echo "$content" | grep -qiE 'token|secret|otp|passwo|reset|nonce|session|salt|csrf|auth|verif|api.?key|private.?key|signing|uuid|guid'; then
          finding HIGH RANDOM "$loc:$ln" "randomness fraca em contexto de segurança — use CSPRNG (crypto)"
        else
          finding INFO RANDOM "$loc:$ln" "Math.random/rand — ok se não for token/otp/senha/id de segurança"
        fi
      done
}

service_role_check() {
  grep -rEn "${GREP_INCLUDE[@]}" -- 'service_role|SERVICE_ROLE_KEY|serviceRole' "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" | grep -vE "$SERVER_ONLY" \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"
        if grep -qiE "NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|['\"]use client['\"]" "$loc" 2>/dev/null; then
          finding CRITICAL RLS-SERVICEROLE "$loc:$ln" "service_role em arquivo CLIENT-SIDE = bypassa RLS no browser"
        else
          finding INFO RLS-SERVICEROLE "$loc:$ln" "service_role — confirmar que é só server-side (ok em edge/api/migration)"
        fi
      done
}

# scan_grep SEV VECTOR REGEX MSG  -> gera 1 finding por linha casada (arquivo:linha)
scan_grep() {
  local sev="$1" vec="$2" pat="$3" msg="$4"
  grep -rEn "${GREP_INCLUDE[@]}" -- "$pat" "$TARGET_PATH" 2>/dev/null \
    | grep -vE "$EXCLUDE" \
    | while IFS= read -r hit; do
        local loc="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"
        finding "$sev" "$vec" "$loc:$ln" "$msg"
      done
}

########################## WHITE-BOX ##########################
white_box() {
  local P="$TARGET_PATH"
  [ -d "$P" ] || { echo "path '$P' não existe" >&2; PATH_ERR=1; return; }

  # --- Passo 0: contexto/stack/versões ---
  echo "▸ Passo 0: stack & versões" >&2
  for f in package.json go.mod requirements.txt composer.json Gemfile; do
    [ -f "$P/$f" ] && echo "  stack: $f encontrado" >&2
  done
  # runtime EOL (heurística simples)
  grep -rEn "${GREP_INCLUDE[@]}" -- '"node"[^0-9]*(1[0-8])\b|python_requires.*3\.[0-7]\b|^go 1\.(1[0-9]|20)\b|FROM (node|python|php|ruby):[0-9]' "$P" 2>/dev/null \
    | grep -vE "$EXCLUDE" | while IFS= read -r hit; do
        finding "MEDIUM" "VERSAO-EOL" "${hit%%:*}:$(x=${hit#*:}; echo ${x%%:*})" "possível runtime/dep antiga ou EOL — confirmar suporte e CVEs"
      done
  command -v govulncheck >/dev/null 2>&1 && [ -f "$P/go.mod" ] && \
    ( cd "$P" && govulncheck ./... 2>/dev/null | grep -q "Vulnerability" && finding "HIGH" "VERSAO-CVE" "$P/go.mod" "govulncheck achou CVE em dependência Go" )
  command -v osv-scanner >/dev/null 2>&1 && \
    ( osv-scanner -r "$P" 2>/dev/null | grep -qiE "CVE-|GHSA-" && finding "HIGH" "VERSAO-CVE" "$P" "osv-scanner achou dependência com vulnerabilidade conhecida" )

  # --- 1. Segredos hardcoded (CRÍTICO) ---
  scan_grep CRITICAL SECRETS 'sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE)|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[0-9A-Za-z]{8,}-[0-9A-Za-z-]{8,}|AIza[0-9A-Za-z_-]{35}|glpat-[0-9A-Za-z_-]{20}|npm_[A-Za-z0-9]{36}|sk-(ant-|proj-)?[A-Za-z0-9_-]{32,}' 'token/segredo de provedor hardcoded no código'
  scan_grep CRITICAL JWT-SECRET 'change-me|changeme|do-not-share|secret.{0,3}=.{0,3}["'"'"'](test|dev|123|password|secret)' 'segredo/JWT hardcoded fraco ou default'
  scan_grep CRITICAL SECRETS-PUBLIC '(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)' 'segredo com prefixo público (vaza no bundle do browser)'
  service_role_check

  # --- 2. RLS (pula comentários e testes) ---
  rls_check

  # --- 3b. IDOR heurístico (ponte scanner→agente: o agente confirma lendo) ---
  idor_check

  # --- 3/6. localStorage token, XSS ---
  scan_grep HIGH LOCALSTORAGE '(localStorage|sessionStorage)\.(set|get)Item\(["'"'"']?(token|jwt|auth|access|session)' 'token de sessão em localStorage (use cookie HttpOnly)'
  xss_check

  # --- 8. Injeção SQL / comando / SSJI (eval) ---
  scan_grep HIGH SQLI 'fmt\.Sprintf\([^)]*(SELECT|INSERT|UPDATE|DELETE)|query\(`[^`]*\$\{|execute\(f["'"'"'][^)]*(SELECT|INSERT)|cursor\.execute\([^,]*%|(SELECT|INSERT|UPDATE|DELETE|REPLACE)[^;]*\$[A-Za-z_]|(SELECT |INSERT INTO|UPDATE |DELETE FROM)[^"'"'"'`;]*["'"'"'`][[:space:]]*\+[[:space:]]*[A-Za-z_$]' 'SQL montado por concatenação/interpolação (use parametrizado)'
  scan_grep HIGH CMDI 'os\.system\(|subprocess\.[a-z]+\([^)]*shell=True|child_process|exec\([^)]*(req|\$_|params)|shell_exec\(' 'possível command injection (input em shell/exec)'
  scan_grep CRITICAL SSJI 'eval\(|new Function\(|setTimeout\(["'"'"']|setInterval\(["'"'"']|vm\.runIn' 'eval/Function/vm com string = injeção de código no servidor (SSJI/RCE)'
  deser_check

  # --- 9. path traversal: leitura/envio de arquivo com input do usuário ---
  scan_grep MEDIUM PATHTRAV '(readFile(Sync)?|createReadStream|sendFile|res\.download|open|fopen|file_get_contents)\([^)]*(req\.|request\.|params|query|\$_(GET|POST|REQUEST)|argv|\.body)' 'caminho de arquivo montado com input do usuário (path traversal) — normalizar e validar contra allowlist'

  # --- 19. SSRF: requisição de saída com URL vinda do usuário ---
  scan_grep MEDIUM SSRF '(fetch|axios(\.get|\.post)?|requests\.(get|post)|urllib\.request|http\.get|got|superagent)\([^)]*(req\.|request\.|params|query|\.body|\$_(GET|POST|REQUEST))' 'requisição de saída com URL controlada pelo usuário (SSRF) — validar host contra allowlist'

  # --- 6b. crypto fraco / uso incorreto ---
  scan_grep MEDIUM CRYPTO 'createCipheriv?\(|createHash\(["'"'"'](md5|sha1)|[^A-Za-z](MD5|SHA1)\(|des-ede3|des-cbc|RC4|Math\.random.*iv' 'crypto fraco/uso incorreto — algoritmo forte + IV/nonce aleatório por operação'

  # --- 21. open redirect ---
  scan_grep MEDIUM OPENREDIR 'res\.redirect\([^)]*(req\.|request\.|query|params)|redirect\((request|req)\.' 'possível open redirect (redirect com input do usuário) — usar allowlist'

  # --- 1c. segredo hardcoded em config (secret/senha = "literal") ---
  hardcoded_secret_check

  # --- 10. CORS (config de servidor = MEDIUM; header cru em edge/serverless = INFO) ---
  scan_grep MEDIUM CORS 'AllowOrigins: *["'"'"']\*|[^-]origin: *["'"'"']\*|allow_origins=\[ *["'"'"']\*|[^a-zA-Z]cors\(\)|cors\(\{ *\}\)' 'CORS liberado (aberto/*) — usar allowlist explícita em API autenticada'
  scan_grep INFO CORS 'Access-Control-Allow-Origin["'"'"': ,]+\*' 'CORS * em header (comum em edge/serverless) — restringir se o endpoint for autenticado'

  # --- 25. randomness fraco (só HIGH em contexto de segurança; senão INFO) ---
  random_check

  # --- 30. over-fetching ---
  scan_grep INFO OVERFETCH "\.select\(['\"]\\*|SELECT \\*" 'select(*) — confirmar que não vaza campo sensível na resposta'

  # --- 31. WebSocket ---
  scan_grep INFO WEBSOCKET 'new WebSocket|websocket\.|Upgrader|socket\.io' 'WebSocket — confirmar auth no handshake + checagem de Origin'

  # --- 32. PII -> LLM ---
  scan_grep INFO PII-LLM 'openai|anthropic|groq|chat\.completions|generateText' 'chamada a LLM — confirmar que não manda PII sem minimizar/consentir'

  # --- 16/18. JWT sem algorithms (por arquivo) ---
  grep -rlEn "${GREP_INCLUDE[@]}" -- 'jwt\.verify\(|ParseWithClaims|jwt\.decode\(' "$P" 2>/dev/null | grep -vE "$EXCLUDE" \
    | while IFS= read -r f; do
        if ! grep -qE 'algorithms|SigningMethodHMAC|verify=True' "$f"; then
          finding "MEDIUM" "JWT-ALG" "$f" "jwt.verify/decode sem travar algoritmo (alg confusion / none)"
        fi
      done

  # --- 13. supply chain ---
  if [ -f "$P/package.json" ] && ! ls "$P"/{package-lock.json,pnpm-lock.yaml,yarn.lock} >/dev/null 2>&1; then
    finding "LOW" "SUPPLYCHAIN" "$P/package.json" "sem lockfile (deps não fixadas)"
  fi
  scan_grep MEDIUM CICD 'uses: [^@]+@v?[0-9]+ *$|pull_request_target' 'GitHub Action não pinada por SHA ou gatilho perigoso'
  grep -rEn 'FROM [^@[:space:]]+:latest|FROM [^@:[:space:]]+ *$' "$P"/**/Dockerfile "$P"/Dockerfile 2>/dev/null \
    | while IFS= read -r hit; do finding "LOW" "DOCKER" "${hit%%:*}" "imagem Docker sem digest fixo (:latest)"; done
  # .env no .gitignore?
  if [ -f "$P/.gitignore" ] && ! grep -qE '^\.env' "$P/.gitignore"; then
    finding "MEDIUM" "GITIGNORE" "$P/.gitignore" ".env não está no .gitignore"
  fi
}

########################## BLACK-BOX ##########################
black_box() {
  local u="$1"; local host="${u#*://}"; host="${host%%/*}"
  echo "▸ Black-box: $u" >&2
  local H; H="$(curl -s -m 15 -D - -o /dev/null "$u" 2>/dev/null)"
  for hdr in "content-security-policy:CSP" "strict-transport-security:HSTS" "x-frame-options:X-Frame-Options" "x-content-type-options:nosniff" "referrer-policy:Referrer-Policy"; do
    local key="${hdr%%:*}" name="${hdr#*:}"
    echo "$H" | grep -qi "^$key" || finding "MEDIUM" "HEADERS" "$u" "header ausente: $name"
  done
  echo "$H" | grep -qiE '^access-control-allow-origin: *\*' && finding "LOW" "CORS" "$u" "Access-Control-Allow-Origin: * (confirmar se rota é autenticada)"
  # arquivos expostos
  for pth in ".git/config" ".env" ".git/HEAD" ".env.production"; do
    local code; code="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$u/$pth" 2>/dev/null)"
    [ "$code" = "200" ] && finding "CRITICAL" "EXPOSED" "$u/$pth" "arquivo sensível acessível publicamente (HTTP 200)"
  done
  # SPF / DMARC
  command -v dig >/dev/null 2>&1 && {
    dig +short TXT "$host" 2>/dev/null | grep -qi 'v=spf1' || finding "MEDIUM" "DNS-SPF" "$host" "sem registro SPF (spoofing de e-mail)"
    local dm; dm="$(dig +short TXT "_dmarc.$host" 2>/dev/null)"
    echo "$dm" | grep -qi 'v=DMARC1' || finding "MEDIUM" "DNS-DMARC" "$host" "sem registro DMARC"
    echo "$dm" | grep -qi 'p=none' && finding "LOW" "DNS-DMARC" "$host" "DMARC p=none (só monitora, não bloqueia)"
  }
  # Supabase anon key -> probe leve
  local html; html="$(curl -s -m 15 "$u" 2>/dev/null)"
  local sb; sb="$(echo "$html" | grep -oiE 'https://[a-z0-9]+\.supabase\.co' | head -1)"
  [ -n "$sb" ] && finding "INFO" "SUPABASE" "$u" "backend Supabase detectado ($sb) — rodar white-box das policies RLS"
}

[ -n "$TARGET_PATH" ] && white_box
[ -n "$URL" ] && black_box "$URL"

########################## RELATÓRIO ##########################
declare -A COUNT=( [CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0 )
while IFS=$'\t' read -r sev _ _ _; do [ -n "${sev:-}" ] && COUNT[$sev]=$(( ${COUNT[$sev]:-0} + 1 )); done < "$FINDINGS"

if [ "$JSON" = "1" ]; then
  printf '{"findings":['
  # ordena por severidade e emite num ÚNICO processo awk (contador de vírgula
  # precisa persistir entre linhas — subshell de pipe perderia o estado).
  for S in CRITICAL HIGH MEDIUM LOW INFO; do
    grep -P "^$S\t" "$FINDINGS" 2>/dev/null
  done | awk -F'\t' '
    NR>1 { printf "," }
    {
      for (i=1;i<=NF;i++) { gsub(/\\/,"\\\\",$i); gsub(/"/,"\\\"",$i) }
      printf "{\"severity\":\"%s\",\"vector\":\"%s\",\"location\":\"%s\",\"message\":\"%s\"}",$1,$2,$3,$4
    }'
  printf '],"summary":{"critical":%s,"high":%s,"medium":%s,"low":%s,"info":%s}}\n' \
    "${COUNT[CRITICAL]}" "${COUNT[HIGH]}" "${COUNT[MEDIUM]}" "${COUNT[LOW]}" "${COUNT[INFO]}"
else
  echo
  echo "════════════════ secure-code scan ════════════════"
  for S in CRITICAL HIGH MEDIUM LOW INFO; do
    local_lines="$(grep -P "^$S\t" "$FINDINGS" 2>/dev/null)"
    [ -z "$local_lines" ] && continue
    case $S in CRITICAL) i="🔴";; HIGH) i="🟠";; MEDIUM) i="🟡";; LOW) i="⚪";; INFO) i="ℹ️ ";; esac
    echo; echo "$i $S"
    echo "$local_lines" | while IFS=$'\t' read -r sev vec loc msg; do
      printf '  [%s] %s\n      %s\n' "$vec" "$loc" "$msg"
    done
  done
  echo
  echo "──────────────────────────────────────────────────"
  echo "🔴 ${COUNT[CRITICAL]} crítico · 🟠 ${COUNT[HIGH]} alto · 🟡 ${COUNT[MEDIUM]} médio · ⚪ ${COUNT[LOW]} baixo · ℹ️  ${COUNT[INFO]} info"
  echo "Cada achado é ponto de partida — confirme lendo o código/alvo (verify-before-flag)."
fi

# exit: 2 = erro de uso (path inválido); 1 = achou crítico/alto; 0 = limpo. (útil em CI)
[ "$PATH_ERR" = 1 ] && exit 2
[ "${COUNT[CRITICAL]}" -gt 0 ] || [ "${COUNT[HIGH]}" -gt 0 ] && exit 1 || exit 0
