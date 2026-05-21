# Task API — Versión básica

API REST mínima de tareas (CRUD en memoria).

Esta es la **versión básica** del trabajo práctico.

---

## Instalacion y ejecución

### Opcion A — Docker 

#### Desde GitHub

```bash
cp .env.example .env       # opcional: completar SENTRY_DSN
docker compose up --build
```

#### Desde DockerHub
```bash
docker pull lautiar/task-api:latest
# Completar opcionalmente SENTRY_DSN en el archivo .env
docker run -p 5000:5000 lautiar/task-api:latest
```

### Opcion B — Python local

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

La API queda disponible en `http://localhost:5000`.

---

## Estructura

```
.
├── app.py                  # API principal
├── test.py             # Tests
├── pytest.ini
├── requirements.txt
├── Dockerfile              # Multi-stage, usuario no-root, healthcheck
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── .gitignore
└── .github/
    └── workflows/
        └── ci.yml          # GitHub Actions
```

---

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Índice de endpoints |
| `GET` | `/health` | Healthcheck para Docker y Render |
| `GET` | `/metrics` | Métricas (total, hechas, pendientes, %) |
| `GET` | `/tasks` | Listar tareas |
| `POST` | `/tasks` | Crear tarea |
| `GET` | `/tasks/<id>` | Ver una tarea |
| `PATCH` | `/tasks/<id>` | Actualizar tarea |
| `DELETE` | `/tasks/<id>` | Eliminar tarea |

---

### Ejemplos

```bash
# Crear una tarea
curl -X POST http://localhost:5000/tasks \
  -H "Content-Type: application/json" \
  -d '{"title": "Tarea 1"}'

# Listar
curl http://localhost:5000/tasks

# Marcar como hecha
curl -X PATCH http://localhost:5000/tasks/1 \
  -H "Content-Type: application/json" \
  -d '{"done": true}'

# Ver métricas
curl http://localhost:5000/metrics
```

--- 

## Tests

```bash
pip install -r requirements.txt
pytest -v
```

---

## CI/CD

El workflow `.github/workflows/ci.yml` corre en cada push a `basic` o `main`:

1. **test** — instala deps y corre `pytest`.
2. **docker** — buildea la imagen y la publica en Docker Hub.

Para que el push a Docker Hub funcione hay que configurar dos secrets del repo:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN` (Access Token de Docker Hub, no la contraseña)

---

## Monitoreo

Si se setea la variable `SENTRY_DSN`, los errores no controlados se reportan
automáticamente a Sentry. Si no, la app arranca igual sin monitoreo.

`/metrics` provee un dashboard rápido del estado del sistema sin necesidad
de servicio externo.

---
