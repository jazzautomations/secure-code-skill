# Template de Relatório de Auditoria de Segurança

Use ao rodar o MODO 2. Um bloco por achado CONFIRMADO ou PLAUSÍVEL. Ordene por severidade
(CRÍTICO → BAIXO). Comece com o resumo executivo.

---

## Resumo executivo
- **Alvo:** <app / repo / domínio> · **Data:** <AAAA-MM-DD> · **Escopo:** <caixa-preta externa / caixa-branca código / ambos>
- **Contagem:** 🔴 X crítico · 🟠 Y alto · 🟡 Z médio · ⚪ W baixo
- **Top 3 pra agir hoje:** <linha, linha, linha>
- **Stack detectada:** <framework / banco / auth / deploy>

---

## Findings

### [🔴 CRÍTICO] Título curto e específico
- **Onde:** `arquivo:linha` ou `https://host/endpoint`
- **Vetor:** <nº e nome no guardrails, ex: "2 — RLS mal configurada">
- **Evidência:** <o que você observou/testou que PROVA a falha — comando + resposta, não "parece inseguro">
- **Impacto:** <o que um atacante consegue: vaza dado de todos os usuários / fraude / account takeover>
- **Correção:** <patch concreto; aponte o errado→certo do vetor>
- **Auto-fix?:** <✅ posso corrigir | ⛔ precisa humano (motivo: rotacionar key / RLS em prod / etc)>
- **Confiança:** <CONFIRMADO (testado) | PLAUSÍVEL (indício — teste manual que confirma: ...)>

### [🟠 ALTO] ...
### [🟡 MÉDIO] ...
### [⚪ BAIXO] ...

---

## Plano de correção (ordenado por impacto)
1. <ação> — <auto-fix / escalar> — <esforço estimado>
2. ...

## O que NÃO é problema (falso-positivos descartados)
Liste o que você checou e concluiu estar correto, pra dar confiança no relatório.
Ex: "anon key no front — OK, RLS confirmada ligada nas 12 tabelas."
