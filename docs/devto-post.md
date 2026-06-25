---
title: "Le dije a un atacante de IA que gané. Perdió."
published: false
description: "Un gateway de seguridad que no bloquea ataques: los engaña. Misdirection-proxy v0.5.0 usa desinformación controlada para hacer que los atacantes automatizados colapsen."
tags: ai, security, python, devsecops
---

Cada vez que un LLM dice *"No puedo ayudarte con eso"*, le está regalando un gradiente de optimización al atacante.

No es intuición. Es matemática:

```
ASR = 1 - (1 - β_D · (1 - β_A))^N  →  1 cuando N → ∞
```

Cada refusal predecible es una pista. El atacante ajusta. Itera. Y eventualmente gana.

**¿Y si en vez de decir "no", el sistema dice "sí" — pero con trampa?**

## Presento misdirection-proxy v0.5.0

Un gateway de seguridad que reemplaza los bloqueos predecibles por **desinformación controlada**. Cuando detecta un ataque, no lo bloquea: lo engaña. Genera respuestas que parecen exitosas al juez automatizado del atacante pero que son operativamente nulas.

El atacante cree que va ganando. En realidad, su optimizador está colapsando.

## Cómo funciona

4 capas de defensa en una sola petición HTTP:

**1. Context Filter** — Analiza datos externos (RAG, herramientas, documentos) buscando inyecciones indirectas ocultas.

**2. Intention Detector** — Clasifica el prompt en 5 categorías: jailbreak, exfiltración, ejecución de código, prompt injection, ingeniería social.

**3. Adaptive Controller** — Si el atacante persiste (mismo X-Session-ID), escala la intensidad de la defensa logarítmicamente: γ_A(t) = min(0.71 + ln(1 + 0.3·ΣM_i), 0.99)

**4. CMPE Engine** — Genera la respuesta de engaño: preámbulo positivo + contenido reshuffleado + pregunta de seguimiento. Parece exitosa. Es inofensiva.

## El colapso del atacante

| Ciclo | γ_A | PPV del atacante | Estado |
|-------|-----|------------------|--------|
| 1 | 0.71 | 0.07 | Recibe basura, ajusta |
| 2 | 0.97 | 0.01 | Gradiente corrupto |
| 3+ | 0.99 | ~0.00 | **Colapso** |

Tras 3 ciclos, el atacante converge a una región muerta del espacio latente. No puede progresar. Cree que va ganando porque recibe respuestas "exitosas". Pero cada respuesta es un falso positivo inducido.

## Pruébalo ahora

```bash
git clone https://github.com/amurlaniakea/misdirection-proxy.git
cd misdirection-proxy
docker compose up -d
docker compose --profile bench run --rm bench
```

El benchmark ejecuta 30 ataques (directos, indirectos, RAG injection) y genera un reporte JSON con PPV, ASR, γ_A(t) y latencia.

## Stack

- **Motor CMPE** — 3 pasos de desinformación controlada
- **Detector** — 5 categorías de amenazas
- **Gateway HTTP** — FastAPI, compatible con OpenAI API
- **Controlador Adaptativo** — Escalado logarítmico de γ_A
- **Context Filter** — Inyecciones indirectas en RAG/tools
- **Benchmark** — Simulador adversarial dual-mode

**147 tests pasando.**

## Links

- **Repo:** https://github.com/amurlaniakea/misdirection-proxy
- **Paper:** https://arxiv.org/abs/2606.20470
- **Licencia:** AGPL-3.0

---

¿Defensa por engaño en producción? Leo opiniones.
