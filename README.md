# API Gestor de Contraseñas

Una API REST para guardar y gestionar credenciales de forma segura, construida con Flask y SQLite.

---

## Tabla de contenidos

- [Seguridad](#seguridad)
- [Instalación y ejecución](#instalación-y-ejecución)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Endpoints](#endpoints)
  - [General](#general)
  - [Vaults (bóvedas)](#vaults-bóvedas)
  - [Entradas](#entradas)
  - [Herramientas de contraseñas](#herramientas-de-contraseñas)
  - [Métricas](#métricas)
  - [Registro de auditoría](#registro-de-auditoría)
  - [Cordón Andon](#cordón-andon)
- [Errores](#errores)
- [Puntaje de seguridad](#puntaje-de-seguridad)
- [Tests](#tests)
- [CI/CD](#cicd)

---

## Seguridad

- Las **contraseñas maestras** se guardan con hash bcrypt, nunca en texto plano.
- Las **contraseñas almacenadas** se cifran con AES-256. Solo se descifran si se pide explícitamente con `?reveal=true`.
- **Toda acción sensible** queda registrada en un log de auditoría.
- La **contraseña maestra** se envía en cada petición como header `X-Master-Password`, nunca se guarda en sesión.

---

## Instalación y ejecución

### Opción A — Docker

```bash
cp .env.example .env
# Completar FERNET_KEY y opcionalmente SENTRY_DSN en el archivo .env
docker compose up --build
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

---

## Estructura del proyecto

```
passmanager/
├── app.py                         # Aplicación principal
├── test_app.py                    # 50 tests (45 pasan + 5 fallan intencionalmente)
├── pytest.ini                     # Configuración de pytest
├── Dockerfile
├── docker-compose.yml
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
X-Master-Password: <contraseña-maestra>
```

---

### General

#### `GET /`

Devuelve un índice con todos los endpoints disponibles.

**No requiere autenticación.**

**Respuesta `200`**
```json
{
  "api": "Password Manager",
  "version": "1.0",
  "endpoints": { ... }
}
```

---

### Vaults

Una vault es un contenedor de credenciales protegido por una contraseña maestra. Al eliminar una vault se eliminan todas sus entradas.

#### `POST /vaults` — Crear una vault

**No requiere autenticación.**

**Body**
```json
{
  "name": "Personal",
  "owner": "usuario",
  "master_password": "contraseña"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `name` | string | sí | Nombre de la vault |
| `owner` | string | sí | Identificador del dueño |
| `master_password` | string | sí | Contraseña maestra (se guarda con bcrypt) |

**Respuesta `201`**
```json
{
  "id": 1,
  "name": "Personal",
  "owner": "usuario",
  "created_at": "2026-04-10T22:00:00.000000",
  "entry_count": 0
}
```

**Curl**
```bash
curl -X POST http://localhost:5000/vaults -H "Content-Type: application/json" -d '{"name": "Personal", "owner": "usuario", "master_password": "contraseña"}'
```

---

#### `GET /vaults/<id>` — Ver una vault

Devuelve la vault con todas sus entradas.

**Requiere `X-Master-Password`.**

**Respuesta `200`**
```json
{
  "id": 1,
  "name": "Personal",
  "owner": "usuario",
  "created_at": "2026-04-10T22:00:00.000000",
  "entry_count": 2,
  "entries": [ ... ]
}
```

**Curl**
```bash
curl http://localhost:5000/vaults/1 -H "X-Master-Password: contraseña"
```

---

#### `DELETE /vaults/<id>` — Eliminar una vault

Elimina la vault y todas sus entradas de forma permanente.

**Requiere `X-Master-Password`.**

**Respuesta `200`**
```json
{
  "message": "Vault 1 deleted"
}
```

**Curl**
```bash
curl -X DELETE http://localhost:5000/vaults/1 -H "X-Master-Password: contraseña"
```

---

### Entradas

Una entrada guarda una credencial (servicio, usuario, contraseña cifrada) dentro de una vault.

#### `GET /vaults/<vault_id>/entries` — Listar entradas

Lista todas las entradas de una vault. Las contraseñas nunca se incluyen en este listado.

**Requiere `X-Master-Password`.**

**Respuesta `200`**
```json
[
  {
    "id": 1,
    "vault_id": 1,
    "service": "github.com",
    "username": "usuario",
    "strength_score": 4,
    "strength_label": "strong",
    "notes": "",
    "created_at": "2026-04-10T22:00:00.000000",
    "updated_at": "2026-04-10T22:00:00.000000"
  }
]
```

**Curl**
```bash
curl http://localhost:5000/vaults/1/entries -H "X-Master-Password: contraseña"
```

---

#### `POST /vaults/<vault_id>/entries` — Guardar una credencial

Almacena una nueva credencial. La contraseña se cifra con AES-256 antes de guardarse.

**Requiere `X-Master-Password`.**

**Body**
```json
{
  "service": "github.com",
  "username": "usuario",
  "password": "contraseña",
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
  "username": "usuario",
  "strength_score": 4,
  "strength_label": "strong",
  "notes": "Cuenta de trabajo",
  "created_at": "2026-04-10T22:00:00.000000",
  "updated_at": "2026-04-10T22:00:00.000000",
  "strength_check": {
    "strong": true,
    "issues": []
  }
}
```

**Curl**
```bash
curl -X POST http://localhost:5000/vaults/1/entries -H "Content-Type: application/json" -H "X-Master-Password: contraseña_nueva" -d '{"service": "github.com", "username": "usuario", "password": "contraseña", "notes": "Cuenta de trabajo"}'
```

---

#### `GET /vaults/<vault_id>/entries/<entry_id>` — Ver una entrada

Devuelve una entrada. Por defecto la contraseña no se muestra. Agregar `?reveal=true` para descifrarla y devolverla.

**Requiere `X-Master-Password`.**

| Parámetro | Valores | Por defecto | Descripción |
|---|---|---|---|
| `reveal` | `true` / `false` | `false` | Incluir la contraseña descifrada en la respuesta |

**Curl (sin contraseña)**
```bash
curl http://localhost:5000/vaults/1/entries/1 -H "X-Master-Password: contraseña"
```

**Curl (con contraseña descifrada)**
```bash
curl "http://localhost:5000/vaults/1/entries/1?reveal=true" -H "X-Master-Password: contraseña"
```

---

#### `PATCH /vaults/<vault_id>/entries/<entry_id>` — Actualizar una entrada

Actualiza uno o más campos de una entrada. Todos los campos son opcionales. Si se cambia la contraseña, se re-cifra y se recalcula el puntaje de seguridad.

**Requiere `X-Master-Password`.**

**Body (todos los campos opcionales)**
```json
{
  "service": "github.com",
  "username": "usuario@trabajo.com",
  "password": "contraseña_nueva",
  "notes": "Nota actualizada"
}
```

**Curl**
```bash
curl -X PATCH http://localhost:5000/vaults/1/entries/1 -H "Content-Type: application/json" -H "X-Master-Password: contraseña" -d '{"notes": "Nota actualizada", "password": "contraseña_nueva"}'
```

---

#### `DELETE /vaults/<vault_id>/entries/<entry_id>` — Eliminar una entrada

**Requiere `X-Master-Password`.**

**Respuesta `200`**
```json
{
  "message": "Entry 1 deleted"
}
```

**Curl**
```bash
curl -X DELETE http://localhost:5000/vaults/1/entries/1 -H "X-Master-Password: contraseña"
```

---

### Herramientas de contraseñas

Estos endpoints no requieren vault ni autenticación.

#### `POST /generate` — Generar una contraseña

Genera una contraseña segura usando el módulo `secrets` de Python.

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
  "password": "aB3$kLm!nP9@qRsT",
  "length": 20,
  "score": 5,
  "strength": {
    "strong": true,
    "issues": []
  }
}
```

**Curl**
```bash
curl -X POST http://localhost:5000/generate -H "Content-Type: application/json" -d '{"length": 24, "symbols": true}'
```

---

#### `POST /check-strength` — Verificar seguridad de una contraseña

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
  "score": 2,
  "label": "fair",
  "issues": [
    "At least one uppercase letter required",
    "At least one special character required"
  ]
}
```

**Curl**
```bash
curl -X POST http://localhost:5000/check-strength -H "Content-Type: application/json" -d '{"password": "micontraseña123"}'
```

---

### Métricas

#### `GET /metrics` — Ver métricas del sistema

Devuelve un resumen en tiempo real del estado de seguridad del sistema: cantidad de contraseñas débiles, alertas abiertas, actividad reciente, entre otros.

**No requiere autenticación.**

**Respuesta `200`**
```json
{
  "vaults": 3,
  "entries": {
    "total": 12,
    "by_strength": {
      "very_weak": 1,
      "weak": 2,
      "fair": 1,
      "good": 3,
      "strong": 4,
      "very_strong": 1
    }
  },
  "lean": {
    "weak_entries": 3,
    "waste_pct": 25.0
  },
  "security": {
    "audit_events": 47,
    "open_andon_alerts": 0,
    "andon_active": false
  },
  "recent_activity": [ ... ]
}
```

**Curl**
```bash
curl http://localhost:5000/metrics
```

---

### Registro de auditoría

#### `GET /audit` — Ver el log de auditoría

Devuelve los últimos 100 eventos registrados en orden cronológico inverso. Toda acción sensible queda registrada aquí: creación de vaults, accesos, contraseñas reveladas, intentos fallidos de autenticación.

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
      "ip": "127.0.0.1",
      "created_at": "2026-04-10T22:05:00.000000"
    }
  ]
}
```

**Acciones registradas**

| Acción | Cuándo ocurre |
|---|---|
| `vault_created` | Al crear una vault |
| `vault_accessed` | Al acceder con contraseña correcta |
| `vault_access_denied` | Al acceder con contraseña incorrecta |
| `vault_deleted` | Al eliminar una vault |
| `entry_created` | Al guardar una credencial |
| `entry_accessed` | Al consultar una entrada |
| `entry_updated` | Al actualizar una entrada |
| `entry_deleted` | Al eliminar una entrada |

**Curl**
```bash
curl http://localhost:5000/audit
```

---

### Cordón Andon

El Cordón Andon es un concepto de manufactura lean: cualquier persona del equipo puede "tirar del cordón" para detener la línea de producción cuando detecta un problema de calidad. Mientras esté activo, todas las operaciones de escritura (`POST`, `PATCH`, `DELETE`) devuelven `503`. Las operaciones de lectura (`GET`) siguen funcionando. El sistema se reanuda recién cuando todos los alertas estén resueltos.

#### `POST /andon/pull` — Activar el cordón

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
  "system_halted": true,
  "alert": {
    "id": 1,
    "severity": "high",
    "message": "Posible compromiso de la clave de cifrado",
    "resolved": false,
    "raised_at": "2026-04-10T22:10:00.000000",
    "resolved_at": null
  }
}
```

**Curl**
```bash
curl -X POST http://localhost:5000/andon/pull -H "Content-Type: application/json" -d '{"message": "Posible compromiso de la clave de cifrado", "severity": "high"}'
```

---

#### `POST /andon/resolve/<event_id>` — Resolver una alerta

Marca una alerta como resuelta. Si era la última alerta abierta, las escrituras se reanudan automáticamente.

**No requiere autenticación.**

**Body (opcional)**
```json
{
  "root_cause": "Se rotó la clave de cifrado, no hubo brecha"
}
```

**Respuesta `200`**
```json
{
  "system_halted": false,
  "alert": {
    "id": 1,
    "resolved": true,
    "resolved_at": "2026-04-10T22:30:00.000000"
  }
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
| `409` | El recurso ya está en el estado solicitado |
| `422` | Regla de negocio violada |
| `503` | Cordón Andon activo — escrituras detenidas |

**Ejemplo**
```json
{
  "error": "Invalid master password"
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
| 0 | `very_weak` |
| 1 | `weak` |
| 2 | `fair` |
| 3 | `good` |
| 4 | `strong` |
| 5 | `very_strong` |

Las entradas con puntaje menor a 3 se reportan en `/metrics`.

---

## Tests

```bash
# Instalar dependencias
pip install -r requirements.txt

# Correr todos los tests
pytest test_app.py -v

# Solo los tests que pasan (igual que en CI)
pytest test_app.py -m "not failing" -v

# Solo los tests que fallan intencionalmente (para demo de Sentry)
pytest test_app.py -m failing -v
```

La suite tiene 50 tests divididos en dos grupos:

**45 tests que pasan** — cubren todos los flujos normales, casos de error, cifrado/descifrado, autenticación, cordón Andon, métricas y auditoría.

**5 fallos intencionales** (`TestIntentionalFailures`) — simulan bugs reales de producción (aceptar contraseñas débiles, entradas duplicadas, auditoría GDPR) para poblar el dashboard de Sentry durante la presentación.

---

## CI/CD

El pipeline de GitHub Actions en `.github/workflows/ci.yml` se ejecuta en cada push a `main` o `develop` y en cada pull request a `main`.

Corre dos jobs en secuencia:

1. **test** — instala dependencias y corre `pytest -m "not failing"` (siempre verde)
2. **docker** — construye la imagen Docker para validar el Dockerfile

Los fallos intencionales están excluidos del CI con el filtro `-m "not failing"` y deben correrse manualmente.Flai
