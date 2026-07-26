#!/usr/bin/env bash
# Suíte de testes do scanner: prova que os detectores DISPARAM no código vulnerável
# e NÃO dão falso-positivo (crítico/alto) no código limpo.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN="$DIR/../scan.sh"
pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then echo "  ✓ $1"; pass=$((pass+1)); else echo "  ✗ $1"; fail=$((fail+1)); fi; }

echo "== VULNERÁVEL (cada detector deve disparar) =="
OUT="$("$SCAN" --json "$DIR/fixtures/vulnerable" 2>/dev/null)"
for vec in SECRETS JWT-SECRET SECRETS-PUBLIC RLS-SERVICEROLE RLS LOCALSTORAGE XSS SQLI CMDI CORS RANDOM JWT-ALG; do
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
