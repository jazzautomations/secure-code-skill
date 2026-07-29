#!/usr/bin/env bash
# Suíte de testes do scanner: prova que os detectores DISPARAM no código vulnerável
# e NÃO dão falso-positivo (crítico/alto) no código limpo.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN="$DIR/../scan.sh"
pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then echo "  ✓ $1"; pass=$((pass+1)); else echo "  ✗ $1"; fail=$((fail+1)); fi; }

echo "== VULNERÁVEL (cada detector deve disparar) =="
# Copia as fixtures pra um dir de trabalho e GERA os tokens fake em runtime.
# Motivo: tokens com cara de real não podem ser versionados (push protection do
# GitHub bloqueia). Montados por partes e com baixa entropia (AAAA…), casam o
# nosso regex mas não são segredo real nem literal no fonte da suíte.
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp -r "$DIR/fixtures/vulnerable/." "$WORK/"
{
  printf 'const gh = "gh%s_%s"\n'        "p"        "$(printf 'A%.0s' {1..36})"
  printf 'const slack = "xox%s-%s-%s"\n' "b"        "$(printf '0%.0s' {1..10})" "$(printf 'B%.0s' {1..18})"
  printf 'const gkey = "AIza%s"\n'                  "$(printf 'C%.0s' {1..35})"
  printf 'const gitlab = "glpat-%s"\n'              "$(printf 'D%.0s' {1..20})"
  printf 'const openai = "sk-proj-%s"\n'            "$(printf 'E%.0s' {1..40})"
  printf 'const npmt = "npm_%s"\n'                  "$(printf 'F%.0s' {1..36})"
} > "$WORK/tokens_gen.js"
OUT="$("$SCAN" --json "$WORK" 2>/dev/null)"
for vec in SECRETS JWT-SECRET SECRETS-PUBLIC RLS-SERVICEROLE RLS LOCALSTORAGE XSS SQLI CMDI CORS RANDOM JWT-ALG SSJI SECRETS-HARDCODED CRYPTO OPENREDIR IDOR DESERIAL PATHTRAV SSRF; do
  if echo "$OUT" | grep -q "\"vector\":\"$vec\""; then check "detecta $vec" 0; else check "detecta $vec" 1; fi
done

echo "== LIMPO (sem falso-positivo crítico/alto) =="
OUTC="$("$SCAN" --json "$DIR/fixtures/clean" 2>/dev/null)"
if echo "$OUTC" | grep -qE '"severity":"(CRITICAL|HIGH)"'; then
  check "código limpo não gera crítico/alto" 1
  echo "    (achados indevidos:)"; echo "$OUTC" | grep -oE '"vector":"[^"]+","location":"[^"]+"' | sed 's/^/      /'
else
  check "código limpo não gera crítico/alto" 0
fi

echo
echo "RESULTADO: $pass passou, $fail falhou"
[ "$fail" -eq 0 ] || exit 1
