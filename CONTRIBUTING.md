# Contribuindo

Valeu por ajudar a deixar os apps do mundo mais seguros. 🙏

## Como contribuir

- **Achou um vetor comum que falta?** Abra uma issue descrevendo o erro típico da IA e o impacto.
- **Tem um exemplo `❌ errado → ✅ certo` melhor?** Manda PR editando `secure-code/references/vectors.md`.
- **Corrigir um falso-positivo?** Se a skill marca algo correto como bug, abra issue — a lista de
  falso-positivos em `secure-code/SKILL.md` é tão importante quanto a de vetores.

## Padrão de um vetor

Todo vetor deve ter:

1. **Como a IA erra** — o padrão inseguro que modelos geram na prática.
2. **A regra** — o comportamento seguro, imperativo.
3. **❌ errado → ✅ certo** — exemplo de código curto e concreto.
4. **Como detectar** — comando/teste que confirma a falha (para o MODO 2).

## Princípios

- **Verificável.** Prefira padrões atemporais (ex: "SQL parametrizado") a estatísticas que
  envelhecem. Se citar dado/CVE, linke a fonte.
- **Baixo falso-positivo.** Toda regra de detecção deve dizer como *confirmar* antes de acusar.
- **Acionável.** O agente tem que saber o que fazer, não só que "é inseguro".

## Fluxo

1. Fork → branch → edite → PR.
2. Descreva no PR o vetor e por que é comum em código de IA.
