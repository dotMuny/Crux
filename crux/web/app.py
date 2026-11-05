"""API local de Crux. Escucha solo en 127.0.0.1 y no tiene autenticación.

Decisión consciente: Crux es mono-usuario y se instala en el Kali de cada
analista. Añadir login sin necesidad invita a exponer el puerto "ya que hay
usuarios", que es justo lo que no queremos. El día que haga falta compartir una
instancia, la autenticación entra como dependencia de FastAPI en un único punto
—`requiere_sesion`— y no hay que reescribir las rutas.

La SPA compilada se sirve desde `web/dist`. La política de contenido prohíbe
cualquier origen externo: si alguien introduce una dependencia que tire de un
CDN, la página se romperá en desarrollo en vez de filtrar tráfico en producción.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..core import paths
from ..core.queue import ColaDeTrabajos
from ..core.store import init_db
from .routes import api

DIST = Path(__file__).parent / "dist"

# Ni CDNs, ni fuentes remotas, ni imágenes de fuera. `connect-src 'self'` cubre
# también las peticiones y la transmisión de eventos.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)


def fichero_servible(ruta: str) -> Path | None:
    """El fichero de `dist` que corresponde a esta ruta, o None si no lo hay.

    Comprobar la contención no es opcional: `DIST / ruta` con una ruta como
    `../../../etc/passwd` apunta fuera del directorio, y `is_file()` responde
    que sí tan contento. Así se servía /etc/passwd desde la propia interfaz.

    Se resuelve antes de comparar, y se compara contra el `dist` también
    resuelto, para que un enlace simbólico dentro de dist que apunte fuera
    tampoco valga. La ruta llega ya descodificada por Starlette, de modo que
    `%2e%2e%2f` y `....//` acaban en la misma comprobación: no hay que filtrar
    patrones, que es la defensa que siempre se queda corta.
    """
    if not ruta:
        return None
    raiz = DIST.resolve()
    try:
        candidato = (raiz / ruta).resolve()
    except (OSError, ValueError, RuntimeError):
        # ruta inválida, byte nulo o bucle de enlaces simbólicos
        return None
    if not candidato.is_relative_to(raiz) or not candidato.is_file():
        return None
    return candidato


@asynccontextmanager
async def ciclo(app: FastAPI):
    init_db()
    paths.ensure_dirs()
    app.state.cola = ColaDeTrabajos()
    yield
    for trabajo in app.state.cola.activos:
        await app.state.cola.cancelar(trabajo.id)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Crux",
        version="0.1.0",
        lifespan=ciclo,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.include_router(api.router, prefix="/api")

    @app.middleware("http")
    async def cabeceras(request: Request, call_next):
        """Crux predica cabeceras de seguridad; lo mínimo es aplicárselas."""
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), interest-cohort=()"
        )
        return response

    if DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

        @app.get("/{ruta:path}", include_in_schema=False)
        async def spa(ruta: str):
            """Todo lo que no sea /api devuelve el index: el enrutado es del cliente."""
            candidato = fichero_servible(ruta)
            if candidato is not None:
                return FileResponse(candidato)
            return FileResponse(DIST / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        async def sin_compilar():
            return JSONResponse(
                {
                    "error": "la interfaz no está compilada",
                    "solucion": "cd frontend && pnpm install && pnpm build",
                    "api": "/api/docs",
                },
                status_code=503,
            )

    return app


app = create_app()
