

# autoflow

Optimiza de forma iterativa tu estado de flujo en Claude Code.

autoflow analiza tus patrones de permisos en Claude Code y recomienda reglas de autoaceptación para reducir las interrupciones. Mide la "puntuación de flujo" (flow score) — el porcentaje de llamadas a herramientas que no requieren un aviso de permiso — y te ayuda a mejorarla.

## Instalación

```bash
claude plugin install ~/git/autoflow
```

O ejecútalo con:

```bash
claude --plugin-dir ~/git/autoflow/
```

## Uso

### Hook al iniciar sesión

autoflow inyecta silenciosamente una recomendación principal al iniciar la sesión. Si no hay nada que sugerir, permanece completamente silencioso.

### Auditoría bajo demanda

```
/autoflow:audit
```

Esto ejecuta un análisis completo de las sesiones de los últimos 7 días y te guía interactivamente por las recomendaciones.

### CLI Directo

```bash
# Full JSON report
python3 scripts/analyze.py --mode full --days 7

# Single recommendation for hook
python3 scripts/analyze.py --mode quick --days 7

# Apply a rule to settings.json
python3 scripts/analyze.py --mode apply --pattern "Bash(git status *)"
```

## Cómo Funciona

autoflow lee las transcripciones de tus sesiones de Claude Code (`~/.claude/projects/*/*.jsonl`) y:

1. Analiza cada llamada a herramienta y su resultado
2. Clasifica cada una como aprobada o denegada
3. Extrae patrones de comandos multinivel (por ejemplo, `Bash(git *)` frente a `Bash(git status *)`)
4. Cruza referencias con tu lista de permitidos actual en `~/.claude/settings.json`
5. Marca los comandos destructivos que deben mantener el aviso de permiso
6. Recomienda el nivel de granularidad óptimo para cada grupo de comandos

### Análisis Multinivel

Para cada grupo de comandos, autoflow analiza en múltiples niveles de granularidad:

- **Nivel 0 (amplio):** `Bash(git *)` — cubre todos los comandos de git
- **Nivel 1 (subcomando):** `Bash(git status *)` — cubre un subcomando específico

Si todos los usos en el nivel 0 son seguros (sin denegaciones, sin subcomandos destructivos), recomienda el patrón amplio. De lo contrario, recomienda subcomandos seguros individuales.

### Niveles de Riesgo

- **bajo** — 0 denegaciones, 5+ aprobaciones, no destructivo
- **medio** — 0 denegaciones pero destructivo o < 5 aprobaciones
- **alto** — cualquier denegación

## Requisitos

- Python 3.6+ (solo biblioteca estándar, sin dependencias)
- Claude Code con transcripciones de sesiones

## Licencia

MIT
