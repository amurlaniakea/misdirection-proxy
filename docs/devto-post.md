---
title: "Deception Gateway: Por qué el bloqueo pasivo de LLMs está matemáticamente roto (y cómo engañar a los atacantes con desinformación controlada)"
published: false
description: "Presentamos misdirection-proxy v0.5.0: un gateway de seguridad que reemplaza los bloqueos predecibles por desinformación controlada, degradando el optimizador del atacante hasta el colapso de Markov."
tags: ai, security, python, devsecops
---

## El problema: cada "no puedo ayudarte" es un regalo para el atacante

Imagina que eres un atacante automatizado usando [PAIR](https://arxiv.org/abs/2310.08419) o [GPTFuzz](https://arxiv.org/abs/2309.10253). Envías un prompt malicioso al LLM y recibes:

> *"I cannot help with that request. I'm sorry."*

¿Qué información te da eso? **Todo.** Te dice:
1. El prompt fue detectado como malicioso
2. El sistema tiene un filtro activo
3. Necesitas reformular el ataque

Cada refusal predecible es un **gradiente de optimización**. El atacante ajusta su siguiente prompt basándose en el feedback. Con suficientes iteraciones, el ASR (Attack Success Rate) converge a 1.0:

```
ASR_block = 1 - (1 - β_D · (1 - β_A))^N  →  1 as N → ∞
**

Esto no es intuición — es una demostración formal del paper de [Soosahabi & Namsani (2026)](https://arxiv.org/abs/2606.20470): **las defensas detect-and-block son fundamentalmente incompletas contra ataques automatizados.**

## La solución: engañar al atacante con desinformación controlada

¿Y si en vez de decir "no puedo ayudarte", el sistema responde con algo que **parece** satisfacer la solicitud del atacante pero que es semánticamente no-operacional?

Esto es exactamente lo que hace [misdirection-proxy](https://github.com/amurlaniakea/misdirection-proxy) v0.5.0: un gateway de seguridad que implementa **CMPE (Contextual Misdirection via Progressive Engagement)** — defensa activa por engaño.

## Arquitectura: 4 capas de defensa síncrona

Cuando una petición HTTP llega al proxy, pasa por 4 capas secuenciales:

```
┌─────────────────────────────────────────────────────────────────┐
│                     PETICIÓN HTTP ENTRANTE                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  CAPA 1: CONTEXT FILTER (Frente 2)                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ¿Hay datos externos sospechosos (RAG, tools, documentos)? │  │
│  │ → Detección de inyecciones indirectas pasivas             │  │
│  │ → Neutralización semántica (preserva partes benignas)     │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  CAPA 2: INTENTION DETECTOR                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ¿El prompt del usuario es malicioso?                       │  │
│  │ → 5 categorías: jailbreak, exfiltración, code exec,        │  │
│  │   prompt injection, ingeniería social                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  CAPA 3: ADAPTIVE CONTROLLER (Frente 1)                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ¿El atacante está persistiendo? (X-Session-ID header)      │  │
│  │ → Escala γ_A(t) = min(0.71 + ln(1 + 0.3·ΣM_i), 0.99)    │  │
│  │ → Más entropía en respuestas a medida que persiste         │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  CAPA 4: CMPE ENGINE                                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ¿Confirmado malicioso? Genera misdirection response:       │  │
│  │ 1. Preámbulo positivo ("I'd be happy to help...")          │  │
│  │ 2. Prompt reshuffling (mezcla + glue tokens)               │  │
│  │ 3. Follow-up question (ramifica conversación)              │  │
│  │ → Respuesta PARECE exitosa al juez del atacante            │  │
│  │ → Pero es operativamente nula                               │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│              RESPUESTA ENVIADA AL ATACANTE                      │
│  (Parece exitosa, pero el gradiente del optimizador se degrada)  │
└─────────────────────────────────────────────────────────────────┘
```

## Resultados: el atacante converge al estado absorbente de error

Cuando el atacante recibe respuestas que **parecen** exitosas pero son falsos positivos inducidos, su optimizador se degrada ciclo a ciclo:

| Ciclo | γ_A(t) | PPV del atacante | Estado del optimizador |
|-------|--------|------------------|----------------------|
| 1 | 0.71 | 0.07 | Recibe basura, ajusta |
| 2 | 0.97 | 0.01 | Gradiente corrupto |
| 3+ | 0.99 | ~0.00 | **Estado absorbente** |

Tras 3-4 ciclos, la probabilidad de que el atacante encuentre un verdadero jailbreak es prácticamente cero. El optimizador ha convergido a una región muerta del espacio latente.

## Reproducibilidad: clonar y ejecutar en 30 segundos

El stack completo (proxy + Ollama + benchmark) se despliega con Docker Compose:

```bash
# Clonar el repositorio
git clone https://github.com/amurlaniakea/misdirection-proxy.git
cd misdirection-proxy

# Levantar el gateway + Ollama (descarga qwen2:0.5b automáticamente)
docker compose up -d

# Ejecutar el benchmark adversarial completo
docker compose --profile bench run --rm bench

# Ver los reportes
ls reports/
cat reports/eval_report_ollama.json
```

El benchmark ejecuta 30 ataques (10 directos, 10 indirectos, 10 RAG injection) y genera un reporte JSON con PPV, ASR, γ_A(t) y latencia por ciclo.

Para usar un modelo más potente:

```bash
OLLAMA_MODEL=llama3:8b docker compose up -d
```

## Stack técnico

| Componente | Versión | Descripción |
|---|---|---|
| CMPE Engine | v0.1.0 | Motor de misdirection de 3 pasos |
| Intention Detector | v0.1.0 | 5 categorías de amenazas |
| HTTP Gateway | v0.2.0 | FastAPI, compatible con OpenAI API |
| Adaptive Controller | v0.3.0 | γ_A dinámico vía `X-Session-ID` |
| Context Filter | v0.4.0 | Inyecciones indirectas en RAG/tools |
| Adversarial Benchmark | v0.5.0 | Simulador dual-mode (deterministic + Ollama) |

**147 tests pasando** — cobertura completa de unitarios + integración.

## ¿Por qué importa?

Los agentes de IA modernos no solo procesan input del usuario. Ingieren datos de RAG, herramientas externas, documentos y memoria. Cada uno de esos canales es una superficie de ataque.

El paradigma clásico de "detectar y bloquear" no escala porque:
1. **Es predecible** — cada refusal da feedback al atacante
2. **Es estático** — un γ_A fijo permite mapear la defensa
3. **Es incompleto** — no cubre inyecciones indirectas en datos pasivos

La defensa activa por engaño resuelve los tres problemas simultáneamente.

## Enlaces

- **Repositorio:** [github.com/amurlaniakea/misdirection-proxy](https://github.com/amurlaniakea/misdirection-proxy)
- **Paper base:** [Soosahabi & Namsani (2026)](https://arxiv.org/abs/2606.20470)
- **Licencia:** AGPL-3.0-or-later

---

¿Qué opinas? ¿Crees que la defensa por engaño es viable en producción o sigue siendo demasiado teórica? Déjame tu opinión en los comentarios.
