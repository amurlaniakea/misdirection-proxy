# misdirection-proxy

**Language:** Python  
**Files:** 37  
**Lines:** 4,675  


## Structure

- `docs/`
- `reports/`
- `scripts/`
- `src/`
- `tests/`

## Subsystems

- **src/** — 7 files (no tests)
- **tests/** — 2 files (has tests)

## Testing

**Test command:** `python3 -m pytest --co -q 2>&1 | head -20`

**Test files:**
- `tests/integration/test_proxy.py`
- `tests/integration/test_gateway.py`
- `tests/unit/test_bench.py`
- `tests/unit/test_metrics.py`
- `tests/unit/test_context_filter.py`
- `tests/unit/test_detector.py`
- `tests/unit/test_cmpe.py`
- `tests/unit/test_adaptive.py`

## Dependencies

- fastapi>=0.110.0
- uvicorn>=0.29.0
- pydantic>=2.0.0
- httpx>=0.27.0
- python-dotenv>=1.0.0

## Conventions

- **test_framework:** pytest
- **build_system:** setuptools/poetry
