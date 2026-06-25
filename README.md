# API Gestor de Contraseñas

API REST para guardar y gestionar credenciales de forma segura. Construida con Flask, SQLite y cifrado AES-128 (Fernet).

Esta es la **versión avanzada** del trabajo práctico integrador de DevOps. La versión básica (Task API en memoria) vive en la rama [`basic`](../../tree/basic).

---

## Tabla de contenidos

- [Seguridad](#seguridad)
- [Instalación y ejecución](#instalación-y-ejecución)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Endpoints](#endpoints)
  - [General](#general)
  - [Vaults](#vaults)
  - [Entradas](#entradas)
  - [Herramientas de contraseñas](#herramientas-de-contraseñas)
  - [Métricas](#métricas)
  - [Registro de auditoría](#registro-de-auditoría)
  - [Andon Cord](#andon-cord)
- [Errores](#errores)
- [Puntaje de seguridad](#puntaje-de-seguridad)
- [Tests](#tests)
- [CI/CD](#cicd)

---

## Seguridad

- Las **contraseñas maestras** de cada vault se guardan con hash bcrypt, nunca en texto plano.
- Las **contraseñas almacenadas** dentro de cada vault se cifran con AES-128 (Fernet con HMAC-SHA256). Solo se descifran si se piden explícitamente con `?reveal=true`.
- **Toda acción sensible** queda registrada en el log de auditoría.
- La **contraseña maestra** se envía en cada petición como header `X-Master-Password`, nunca se guarda en sesión.
- La clave de cifrado (`FERNET_KEY`) se inyecta como variable de entorno en runtime; no se commitea al repositorio.

---

## Instalación y ejecución

### Opción A — Docker

#### Desde GitHub

```bash
cp .env.example .env
# Completar FERNET_KEY y opcionalmente SENTRY_DSN en el archivo .env
docker compose up

# Para detener y borrar el volumen de datos:
docker compose down -v
```

> El `docker compose up` pullea la imagen `lautiar/passmanager:latest` desde Docker Hub (no buildea local). Para correr cambios locales del código, usá la Opción B o buildeá manualmente con `docker build -t passmanager:dev .`

#### Desde Docker Hub

```bash
docker pull lautiar/passmanager:latest
docker run -p 5000:5000 \
  -e FERNET_KEY="..." \
  -e SENTRY_DSN="..." \
  lautiar/passmanager:latest
```

### Opción B — Python local

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # completar FERNET_KEY
python app.py
```

La API queda disponible en `http://localhost:5000`.

### Generar una FERNET_KEY

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Pegar el resultado en el archivo `.env`.

### Variables de entorno

| Variable | Requerida | Por defecto | Descripción |
|---|---|---|---|
| `FERNET_KEY` | Recomendada | Genera una nueva en cada arranque (los datos viejos quedan inaccesibles) | Clave de cifrado simétrico para las contraseñas almacenadas |
| `SENTRY_DSN` | No | (vacío) | URL de conexión a Sentry. Sin esta variable, el monitoreo se desactiva |
| `DATABASE_URL` | No | `sqlite:////tmp/passmanager.db` | URL de la base de datos. Permite migrar a Postgres cambiando solo esta variable |
| `PORT` | No | `5000` | Puerto en el que escucha la app. Render lo setea automáticamente |

---

## Estructura del proyecto

```
passmanager/
├── app.py                         # Aplicación principal
├── test.py                        # 49 tests (44 pasan + 5 fallan intencionalmente)
├── pytest.ini                     # Configuración de pytest
├── Dockerfile                     # Multi-stage build, usuario no-root, healthcheck
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
├── .env.example                   # Plantilla de variables de entorno
├── .gitignore
└── .github/
    └── workflows/
        └── ci.yml                 # Pipeline de GitHub Actions
```

---

## Endpoints

Todos los requests y responses usan `application/json`. Los endpoints que acceden a una bóveda requieren el header `X-Master-Password`.

### Header de autenticación

```
X-Master-Password: <contraseña-maestra-de-la-vault>
```

---

### General

#### `GET /`

Devuelve un índice con todos los endpoints disponibles.

**No requiere autenticación.**

**Respuesta `200`**

```
{
  "api": "Gestor de Contraseñas",
  "endpoints": {
    "DELETE /vaults/<id>": "Eliminar vault",
    "DELETE /vaults/<id>/entries/<eid>": "Eliminar entrada",
    "GET  /andon/events": "Historial de eventos Andon",
    "GET  /audit": "Log completo de auditoría",
    "GET  /metrics": "Lean / Agile / Security",
    "GET  /vaults/<id>": "Obtener vault (requiere header con la contraseña maestra)",
    "GET  /vaults/<id>/entries": "Listar entradas",
    "GET  /vaults/<id>/entries/<eid>": "Obtener entrada (opcionalmente revelar contraseña)",
    "PATCH /vaults/<id>/entries/<eid>": "Actualizar entrada",
    "POST /andon/pull": "Activar el Andon Cord",
    "POST /andon/resolve/<id>": "Resolver alerta",
    "POST /check-strength": "Verificar la fortaleza de una contraseña",
    "POST /generate": "Generar una contraseña segura",
    "POST /vaults": "Crear vault",
    "POST /vaults/<id>/entries": "Guardar una nueva credencial"
  },
  "version": "1.0"
}
```

---

### Vaults

Una vault es un contenedor de credenciales protegido por una contraseña maestra. Al eliminar una vault se eliminan todas sus entradas en cascada.

#### `POST /vaults` — Crear una vault

**No requiere autenticación.**

**Body**

```json
{
  "name": "Personal",
  "owner": "lautaro",
  "master_password": "MiClav3Maestra!2025"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `name` | string | sí | Nombre de la vault |
| `owner` | string | sí | Identificador del dueño |
| `master_password` | string | sí | Contraseña maestra (se hashea con bcrypt) |

**Respuesta `201`**

```json
{
  "id": 1,
  "name": "Personal",
  "owner": "lautaro",
  "created_at": "2026-05-19T10:00:00.000000+00:00",
  "entry_count": 0
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/vaults \
  -H "Content-Type: application/json" \
  -d '{"name": "Personal", "owner": "lautaro", "master_password": "MiClav3Maestra!2025"}'
```

---

#### `GET /vaults/<id>` — Ver una vault

Devuelve la vault con todas sus entradas (las contraseñas no se incluyen descifradas en este endpoint).

**Requiere `X-Master-Password`.**

**Respuesta `200`**

```json
{
  "id": 1,
  "name": "Personal",
  "owner": "lautaro",
  "created_at": "2026-05-19T10:00:00.000000+00:00",
  "entry_count": 2,
  "entradas": [ ... ]
}
```

**Curl**

```bash
curl http://localhost:5000/vaults/1 \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

---

#### `DELETE /vaults/<id>` — Eliminar una vault

Elimina la vault y todas sus entradas de forma permanente.

**Requiere `X-Master-Password`.**

**Respuesta `200`**

```json
{
  "mensaje": "Bóveda 1 eliminada"
}
```

**Curl**

```bash
curl -X DELETE http://localhost:5000/vaults/1 \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

---

### Entradas

Una entrada guarda una credencial (servicio, usuario, contraseña cifrada) dentro de una vault.

#### `GET /vaults/<vault_id>/entries` — Listar entradas

Lista todas las entradas de una vault. Las contraseñas nunca se incluyen en este listado, solo metadatos.

**Requiere `X-Master-Password`.**

**Respuesta `200`**

```json
[
  {
    "id": 1,
    "vault_id": 1,
    "service": "github.com",
    "username": "lautiar",
    "strength_score": 5,
    "strength_label": "muy_fuerte",
    "notes": "",
    "created_at": "2026-05-19T10:05:00.000000+00:00",
    "updated_at": "2026-05-19T10:05:00.000000+00:00"
  }
]
```

**Curl**

```bash
curl http://localhost:5000/vaults/1/entries \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

---

#### `POST /vaults/<vault_id>/entries` — Guardar una credencial

Almacena una nueva credencial. La contraseña se cifra con AES-128 (Fernet) antes de guardarse.

**Requiere `X-Master-Password`.**

**Body**

```json
{
  "service": "github.com",
  "username": "lautiar",
  "password": "G!tHub$ecure2025!!",
  "notes": "Cuenta de trabajo"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `service` | string | sí | Nombre del sitio o servicio |
| `username` | string | sí | Usuario o email |
| `password` | string | sí | Contraseña en texto plano (se cifra antes de guardar) |
| `notes` | string | no | Notas opcionales |

**Respuesta `201`**

```json
{
  "id": 1,
  "vault_id": 1,
  "service": "github.com",
  "username": "lautiar",
  "strength_score": 5,
  "strength_label": "muy_fuerte",
  "notes": "Cuenta de trabajo",
  "created_at": "2026-05-19T10:05:00.000000+00:00",
  "updated_at": "2026-05-19T10:05:00.000000+00:00",
  "verificacion_fortaleza": {
    "strong": true,
    "issues": []
  }
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/vaults/1/entries \
  -H "Content-Type: application/json" \
  -H "X-Master-Password: MiClav3Maestra!2025" \
  -d '{"service": "github.com", "username": "lautiar", "password": "G!tHub$ecure2025!!", "notes": "Cuenta de trabajo"}'
```

---

#### `GET /vaults/<vault_id>/entries/<entry_id>` — Ver una entrada

Devuelve una entrada. Por defecto la contraseña no se muestra. Agregar `?reveal=true` para descifrarla y devolverla en texto plano.

**Requiere `X-Master-Password`.**

| Parámetro | Valores | Por defecto | Descripción |
|---|---|---|---|
| `reveal` | `true` / `false` | `false` | Incluir la contraseña descifrada en la respuesta |

**Curl (sin contraseña)**

```bash
curl http://localhost:5000/vaults/1/entries/1 \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

**Curl (con contraseña descifrada)**

```bash
curl "http://localhost:5000/vaults/1/entries/1?reveal=true" \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

Cada acceso (con o sin `reveal`) queda registrado en el log de auditoría.

---

#### `PATCH /vaults/<vault_id>/entries/<entry_id>` — Actualizar una entrada

Actualiza uno o más campos de una entrada. Todos los campos son opcionales. Si se cambia la contraseña, se re-cifra y se recalcula el puntaje de fortaleza.

**Requiere `X-Master-Password`.**

**Body (todos los campos opcionales)**

```json
{
  "service": "github.com",
  "username": "lautiar@trabajo.com",
  "password": "NuevaP@ssw0rd2025!!",
  "notes": "Nota actualizada"
}
```

**Curl**

```bash
curl -X PATCH http://localhost:5000/vaults/1/entries/1 \
  -H "Content-Type: application/json" \
  -H "X-Master-Password: MiClav3Maestra!2025" \
  -d '{"notes": "Nota actualizada", "password": "NuevaP@ssw0rd2025!!"}'
```

---

#### `DELETE /vaults/<vault_id>/entries/<entry_id>` — Eliminar una entrada

**Requiere `X-Master-Password`.**

**Respuesta `200`**

```json
{
  "mensaje": "Entrada 1 eliminada"
}
```

**Curl**

```bash
curl -X DELETE http://localhost:5000/vaults/1/entries/1 \
  -H "X-Master-Password: MiClav3Maestra!2025"
```

---

### Herramientas de contraseñas

Estos endpoints no requieren vault ni autenticación.

#### `POST /generate` — Generar una contraseña

Genera una contraseña segura usando el módulo `secrets` de Python (CSPRNG).

**Body (todos los campos opcionales)**

```json
{
  "length": 24,
  "symbols": true
}
```

| Campo | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `length` | integer | `20` | Largo de la contraseña (mínimo 12, máximo 128) |
| `symbols` | boolean | `true` | Incluir caracteres especiales |

**Respuesta `200`**

```json
{
  "password": "X7$kP2@nQ9!mR4#vT8&jY3^L",
  "longitud": 24,
  "fortaleza": {
    "strong": true,
    "issues": []
  },
  "puntaje": 5
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/generate \
  -H "Content-Type: application/json" \
  -d '{"length": 24, "symbols": true}'
```

---

#### `POST /check-strength` — Verificar fortaleza de una contraseña

Evalúa qué tan segura es una contraseña sin necesidad de guardarla.

**Body**

```json
{
  "password": "micontraseña123"
}
```

**Respuesta `200`**

```json
{
  "strong": false,
  "issues": [
    "Se requiere al menos una letra mayúscula",
    "Se requiere al menos un carácter especial"
  ],
  "puntaje": 2,
  "etiqueta": "aceptable"
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/check-strength \
  -H "Content-Type: application/json" \
  -d '{"password": "micontraseña123"}'
```

---

### Métricas

#### `GET /metrics` — Ver métricas del sistema

Devuelve un resumen en tiempo real del estado del sistema: cantidad de bóvedas, entradas, distribución por fortaleza, contraseñas débiles ("desperdicio" en términos Lean), alertas Andon y actividad reciente.

**No requiere autenticación.**

**Respuesta `200`**

```json
{
  "vaults": 3,
  "entradas": {
    "total": 12,
    "por_fortaleza": {
      "muy_debil": 1,
      "debil": 2,
      "aceptable": 1,
      "buena": 3,
      "fuerte": 4,
      "muy_fuerte": 1
    }
  },
  "lean": {
    "entradas_debiles": 3,
    "desperdicio_pct": 25.0
  },
  "seguridad": {
    "eventos_auditoria": 47,
    "alertas_andon_abiertas": 0,
    "andon_activo": false
  },
  "actividad_reciente": [ ... ]
}
```

**Curl**

```bash
curl http://localhost:5000/metrics
```

---

### Registro de auditoría

#### `GET /audit` — Ver el log de auditoría

Devuelve los últimos 100 eventos registrados en orden cronológico inverso. Toda acción sensible queda registrada: creación y acceso a vaults, contraseñas reveladas, intentos fallidos de autenticación, modificaciones y eliminaciones.

**No requiere autenticación.**

**Respuesta `200`**

```json
{
  "total": 47,
  "logs": [
    {
      "id": 47,
      "action": "entry_accessed",
      "vault_id": 1,
      "entry_id": 3,
      "detail": "reveal=true",
      "ip": "190.51.234.12",
      "created_at": "2026-05-19T10:05:00.000000+00:00"
    }
  ]
}
```

**Acciones registradas**

| Acción | Cuándo ocurre |
|---|---|
| `vault_created` | Al crear una vault |
| `vault_accessed` | Al acceder con contraseña maestra correcta |
| `vault_access_denied` | Al acceder con contraseña incorrecta |
| `vault_deleted` | Al eliminar una vault |
| `entry_created` | Al guardar una credencial |
| `entry_accessed` | Al consultar una entrada (con o sin reveal) |
| `entry_updated` | Al actualizar una entrada |
| `entry_deleted` | Al eliminar una entrada |

**Curl**

```bash
curl http://localhost:5000/audit
```

---

### Andon Cord

#### `POST /andon/pull` — Activar el cord

Levanta una alerta y detiene todas las escrituras. Si Sentry está configurado, también se envía el evento allí.

**No requiere autenticación.**

**Body**

```json
{
  "message": "Posible compromiso de la clave de cifrado",
  "severity": "high"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `message` | string | sí | Descripción del problema |
| `severity` | string | no | `low`, `medium` o `high` (por defecto: `high`) |

**Respuesta `201`**

```json
{
  "alerta": {
    "id": 1,
    "severity": "high",
    "message": "Posible compromiso de la clave de cifrado",
    "resolved": false,
    "raised_at": "2026-05-19T10:30:00.000000+00:00",
    "resolved_at": null
  },
  "sistema_detenido": true
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/andon/pull \
  -H "Content-Type: application/json" \
  -d '{"message": "Posible compromiso de la clave de cifrado", "severity": "high"}'
```

**Mientras el cord esté activo**, cualquier intento de escritura devuelve:

```json
{
  "error": "Andon Cord activo: escrituras detenidas"
}
```

---

#### `POST /andon/resolve/<event_id>` — Resolver una alerta

Marca una alerta como resuelta. Si era la última alerta abierta, las escrituras se reanudan automáticamente.

**No requiere autenticación.**

**Respuesta `200`**

```json
{
  "alerta": {
    "id": 1,
    "resolved": true,
    "resolved_at": "2026-05-19T10:35:00.000000+00:00"
  },
  "sistema_detenido": false
}
```

**Curl**

```bash
curl -X POST http://localhost:5000/andon/resolve/1
```

---

#### `GET /andon/events` — Ver historial de alertas

Lista todos los eventos Andon (activos y resueltos), del más reciente al más antiguo.

**No requiere autenticación.**

**Curl**

```bash
curl http://localhost:5000/andon/events
```

---

## Errores

Todos los errores devuelven JSON con la misma estructura.

| Código | Significado |
|---|---|
| `400` | Faltan campos o el body es inválido |
| `401` | Contraseña maestra incorrecta o ausente |
| `404` | El recurso no existe |
| `405` | Método HTTP no permitido en esa ruta |
| `409` | El recurso ya está en el estado solicitado (ej: alerta ya resuelta) |
| `503` | Andon Cord activo — escrituras detenidas |

**Ejemplo**

```json
{
  "error": "Contraseña maestra inválida"
}
```

---

## Puntaje de seguridad

Las contraseñas se puntúan de 0 a 5. Cada criterio suma 1 punto:

| Criterio | Puntos |
|---|---|
| Al menos 12 caracteres | +1 |
| Al menos 20 caracteres | +1 |
| Contiene mayúscula | +1 |
| Contiene número | +1 |
| Contiene carácter especial | +1 |

| Puntaje | Etiqueta |
|---|---|
| 0 | `muy_debil` |
| 1 | `debil` |
| 2 | `aceptable` |
| 3 | `buena` |
| 4 | `fuerte` |
| 5 | `muy_fuerte` |

Las entradas con puntaje menor a 3 se reportan en `/metrics` como `entradas_debiles` y suman al `desperdicio_pct` (terminología Lean).

---

## Tests

```bash
# Instalar dependencias
pip install -r requirements.txt

# Correr todos los tests
pytest test.py -v

# Solo los tests que pasan (igual que en CI)
pytest test.py -m "not failing" -v

# Solo los tests que fallan intencionalmente (para demo de Sentry)
pytest test.py -m failing -v
```

La suite tiene **49 tests** divididos en dos grupos:

- **44 tests que pasan** — cubren los flujos normales: CRUD de vaults y entradas, casos de error, cifrado y descifrado, autenticación, cordón Andon, métricas y auditoría.
- **5 fallos intencionales** (`TestIntentionalFailures`) — simulan bugs reales de producción (aceptar contraseñas débiles, entradas duplicadas, etc) para poblar el dashboard de Sentry durante la presentación.

Los fallos intencionales están excluidos del CI con el filtro `-m "not failing"` y deben correrse manualmente.

---

## CI/CD

El pipeline de GitHub Actions en `.github/workflows/ci.yml` se ejecuta en cada push a `main` y en cada pull request hacia `main`.

Corre **tres jobs** en secuencia:

1. **test** — instala dependencias y corre `pytest test.py -m "not failing" -v`. Si falla, frena todo.
2. **docker** — buildea la imagen Docker multi-stage, genera los tags (`latest`, `main`, `sha-<largo>`) usando `docker/metadata-action`, y la publica en Docker Hub.
3. **deploy** — dispara el Deploy Hook de Render pasándole la imagen por SHA específico (`imgURL=...passmanager:sha-<commit>`), de modo que Render despliega exactamente la versión que se testeó y buildeó, no el tag móvil `latest`.

### Estrategia de tags

Cada build genera varios tags simultáneos apuntando al mismo digest:

- `latest` — solo en push a `main`
- `main` — nombre de la rama
- `sha-<largo>` — SHA completo del commit, usado para el deploy versionado y para rollback

### Secrets requeridos

| Secret | Uso |
|---|---|
| `DOCKERHUB_USERNAME` | Login en Docker Hub |
| `DOCKERHUB_TOKEN` | Personal Access Token de Docker Hub |
| `RENDER_DEPLOY_HOOK_URL` | URL del Deploy Hook del servicio en Render |
