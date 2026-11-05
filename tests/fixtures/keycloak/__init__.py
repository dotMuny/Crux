"""Un Keycloak de pruebas y dos aplicaciones que se autentican contra él.

No es Keycloak: reproduce lo que Crux tiene que atravesar para entrar en una
aplicación que delega el acceso en Keycloak, con el mismo marcado y el mismo
orden de redirecciones. Existe para que las pruebas de autenticación corran sin
red y sin descargar nada.

Lo que imita del Keycloak real, porque cada cosa rompió o podía romper el login:

- El formulario vive en OTRO host que la aplicación. Las cookies de uno no
  viajan al otro.
- Al pedir el formulario reparte `AUTH_SESSION_ID`, y si no vuelve con el envío
  responde con «Cookie not found» en lugar de aceptar la clave.
- Los identificadores del tema `keycloak.v2`: `#kc-form-login`, `#username`,
  `#password`, `#kc-login`, el error en `#input-error-username`.
- Tras entrar deja `KEYCLOAK_IDENTITY`: una segunda visita entra SIN enseñar el
  formulario. Es lo que hacía que, con un solo navegador para todos los roles,
  el segundo rol entrase como el primero.
- Usuarios que piden segundo factor y usuarios con una acción obligatoria
  pendiente (cambiar la clave), que son los dos bloqueos habituales en
  producción.
- Un reino «dospasos» que pide el usuario y la clave en pantallas distintas.

Las dos aplicaciones cubren los dos sitios donde acaba la sesión:

- `app`: aplicación de servidor, como una detrás de oauth2-proxy o un Spring
  con OIDC. Canjea el código desde el servidor y deja una cookie de sesión.
- `spa`: aplicación de página única, como una con keycloak-js. Canjea el código
  desde el navegador, guarda el token en `sessionStorage` y lo manda en
  `Authorization: Bearer`. No hay cookie que capturar.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
from flask import Flask, Response, redirect, request
from werkzeug.serving import make_server

SECRETO = secrets.token_bytes(32)

USUARIOS = {
    "ana": {"clave": "ana-clave", "roles": ["usuario"]},
    "admin": {"clave": "admin-clave", "roles": ["usuario", "admin"]},
    # Bloqueos habituales: no hay forma de completarlos sin una persona.
    "otp": {"clave": "otp-clave", "roles": ["usuario"], "otp": True},
    "cambio": {"clave": "cambio-clave", "roles": ["usuario"], "accion": "UPDATE_PASSWORD"},
}


def _b64(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def emitir_jwt(usuario: str, roles: list[str], segundos: int) -> str:
    """Un JWT con la forma de los de Keycloak, firmado con un secreto largo."""
    ahora = int(time.time())
    cabecera = {"alg": "HS256", "typ": "JWT", "kid": "crux-pruebas"}
    cuerpo = {
        "exp": ahora + segundos, "iat": ahora, "iss": "crux-pruebas",
        "sub": hashlib.sha256(usuario.encode()).hexdigest()[:16],
        "preferred_username": usuario, "realm_access": {"roles": roles},
    }
    firmado = f"{_b64(json.dumps(cabecera).encode())}.{_b64(json.dumps(cuerpo).encode())}"
    firma = hmac.new(SECRETO, firmado.encode(), hashlib.sha256).digest()
    return f"{firmado}.{_b64(firma)}"


def validar_jwt(token: str) -> dict | None:
    try:
        cabecera, cuerpo, firma = token.split(".")
    except ValueError:
        return None
    esperada = _b64(hmac.new(SECRETO, f"{cabecera}.{cuerpo}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(esperada, firma):
        return None
    datos = json.loads(base64.urlsafe_b64decode(cuerpo + "=" * (-len(cuerpo) % 4)))
    return datos if datos["exp"] > time.time() else None


# ── Proveedor de identidad ──────────────────────────────────────────────────
@dataclass
class EstadoIdP:
    caducidad_token: int = 300
    # sesión de autenticación en curso → datos del intento
    en_curso: dict[str, dict] = field(default_factory=dict)
    # código de autorización → usuario
    codigos: dict[str, str] = field(default_factory=dict)
    # KEYCLOAK_IDENTITY → usuario (la sesión SSO)
    sso: dict[str, str] = field(default_factory=dict)
    entradas: list[str] = field(default_factory=list)


PLANTILLA = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Sign in to {reino}</title></head>
<body class="pf-v5-c-login"><div class="pf-v5-c-login__main">
<h1 id="kc-page-title">{titulo}</h1>
{cuerpo}
</div></body></html>"""


def crear_idp(estado: EstadoIdP) -> Flask:
    app = Flask("keycloak-de-pruebas")

    def _pagina(reino: str, titulo: str, cuerpo: str) -> str:
        return PLANTILLA.format(reino=html.escape(reino), titulo=titulo, cuerpo=cuerpo)

    def _formulario(reino: str, codigo: str, *, error: str = "", usuario: str = "",
                    paso: str = "ambos") -> str:
        accion = (f"/realms/{reino}/login-actions/authenticate?"
                  + urlencode({"session_code": codigo, "execution": "e1",
                               "client_id": "app", "tab_id": "t1"}))
        aviso = (f'<div class="pf-v5-c-helper-text" aria-live="polite">'
                 f'<div class="pf-v5-c-helper-text__item pf-m-error">'
                 f'<span class="pf-v5-c-helper-text__item-text" id="input-error-username">'
                 f'{html.escape(error)}</span></div></div>') if error else ""
        campo_usuario = (f'<label for="username">Username or email</label>'
                         f'<input id="username" name="username" type="text" '
                         f'autocomplete="username" value="{html.escape(usuario)}">')
        campo_clave = ('<label for="password">Password</label>'
                       '<input id="password" name="password" type="password" '
                       'autocomplete="current-password">')
        campos = {"usuario": campo_usuario, "clave": campo_clave,
                  "ambos": campo_usuario + campo_clave}[paso]
        return _pagina(reino, "Sign in to your account", f"""
<form id="kc-form-login" class="pf-v5-c-form" onsubmit="login.disabled = true; return true;"
      action="{html.escape(accion)}" method="post" novalidate="novalidate">
{campos}{aviso}
<input type="hidden" id="id-hidden-input" name="credentialId">
<button class="pf-v5-c-button pf-m-primary pf-m-block" name="login" id="kc-login"
        type="submit">Sign In</button>
</form>""")

    def _volver(intento: dict, usuario: str) -> Response:
        codigo = secrets.token_urlsafe(16)
        estado.codigos[codigo] = usuario
        estado.entradas.append(usuario)
        destino = intento["redirect_uri"] + ("&" if "?" in intento["redirect_uri"] else "?") \
            + urlencode({"state": intento["state"], "session_state": "s", "code": codigo})
        respuesta = redirect(destino, code=302)
        identidad = secrets.token_urlsafe(16)
        estado.sso[identidad] = usuario
        respuesta.set_cookie("KEYCLOAK_IDENTITY", identidad, httponly=True,
                             path=f"/realms/{intento['reino']}/")
        respuesta.set_cookie("KEYCLOAK_SESSION", "s", path=f"/realms/{intento['reino']}/")
        return respuesta

    @app.get("/realms/<reino>/protocol/openid-connect/auth")
    def autorizar(reino):
        intento = {"reino": reino, "redirect_uri": request.args.get("redirect_uri", ""),
                   "state": request.args.get("state", ""), "paso": "inicio"}
        # Sesión SSO viva: se entra sin formulario. Es el comportamiento real y
        # la razón de no compartir navegador entre roles.
        identidad = request.cookies.get("KEYCLOAK_IDENTITY")
        if identidad in estado.sso:
            return _volver(intento, estado.sso[identidad])
        codigo = secrets.token_urlsafe(12)
        estado.en_curso[codigo] = intento
        paso = "usuario" if reino == "dospasos" else "ambos"
        respuesta = Response(_formulario(reino, codigo, paso=paso))
        respuesta.set_cookie("AUTH_SESSION_ID", codigo, httponly=True,
                             path=f"/realms/{reino}/")
        respuesta.set_cookie("KC_RESTART", "r", httponly=True, path=f"/realms/{reino}/")
        return respuesta

    @app.post("/realms/<reino>/login-actions/authenticate")
    def autenticar(reino):
        codigo = request.args.get("session_code", "")
        if request.cookies.get("AUTH_SESSION_ID") != codigo or codigo not in estado.en_curso:
            return _pagina(reino, "We are sorry...",
                           '<p id="instruction1" class="instruction">Cookie not found. '
                           'Please make sure cookies are enabled in your browser.</p>'), 400
        intento = estado.en_curso[codigo]

        if intento["paso"] == "otp":
            usuario = intento["usuario"]
            if request.form.get("otp") == "123456":
                return _volver(intento, usuario)
            return _pagina(reino, "Sign in", '<span id="input-error-otp-code">'
                           'Invalid authenticator code.</span>')

        if reino == "dospasos" and intento["paso"] == "inicio":
            intento["usuario"] = request.form.get("username", "")
            intento["paso"] = "clave"
            return _formulario(reino, codigo, usuario=intento["usuario"], paso="clave")

        usuario = intento.get("usuario") or request.form.get("username", "")
        datos = USUARIOS.get(usuario)
        if not datos or request.form.get("password") != datos["clave"]:
            return _formulario(reino, codigo, error="Invalid username or password.",
                               usuario=usuario, paso="ambos" if reino != "dospasos" else "clave")
        if datos.get("otp"):
            intento.update(paso="otp", usuario=usuario)
            return _pagina(reino, "Sign in", f"""
<form id="kc-otp-login-form" action="/realms/{reino}/login-actions/authenticate?session_code={codigo}" method="post">
<label for="otp">One-time code</label>
<input id="otp" name="otp" autocomplete="one-time-code" type="text" autofocus>
<button id="kc-login" name="login" type="submit">Sign In</button></form>""")
        if datos.get("accion") == "UPDATE_PASSWORD":
            return _pagina(reino, "Update password", """
<form id="kc-passwd-update-form" method="post">
<input type="password" id="password-new" name="password-new" autocomplete="new-password">
<input type="password" id="password-confirm" name="password-confirm">
<button type="submit">Submit</button></form>""")
        return _volver(intento, usuario)

    @app.post("/realms/<reino>/protocol/openid-connect/token")
    def token(reino):
        usuario = estado.codigos.pop(request.form.get("code", ""), None)
        if usuario is None:
            return {"error": "invalid_grant"}, 400
        cuerpo = {"access_token": emitir_jwt(usuario, USUARIOS[usuario]["roles"],
                                             estado.caducidad_token),
                  "expires_in": estado.caducidad_token, "token_type": "Bearer"}
        respuesta = app.response_class(json.dumps(cuerpo), mimetype="application/json")
        # La SPA lo pide desde el navegador, con otro origen.
        respuesta.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        return respuesta

    return app


# ── Aplicación de servidor (cookie de sesión) ──────────────────────────────
def crear_app(idp: str, *, caducidad_sesion: float | None = None) -> Flask:
    app = Flask("app-con-keycloak")
    sesiones: dict[str, tuple[str, float]] = {}

    def usuario_actual() -> str | None:
        datos = sesiones.get(request.cookies.get("APPSESSION", ""))
        if datos is None:
            return None
        usuario, desde = datos
        if caducidad_sesion is not None and time.time() - desde > caducidad_sesion:
            return None
        return usuario

    def a_keycloak():
        return redirect(f"{idp}/realms/crux/protocol/openid-connect/auth?" + urlencode({
            "client_id": "app", "response_type": "code", "scope": "openid",
            "redirect_uri": f"{request.host_url}callback", "state": secrets.token_hex(4)}))

    @app.get("/callback")
    def callback():
        # El canje del código lo hace el servidor, como oauth2-proxy.
        r = httpx.post(f"{idp}/realms/crux/protocol/openid-connect/token",
                       data={"code": request.args.get("code", ""),
                             "grant_type": "authorization_code"}, timeout=5)
        if r.status_code != 200:
            return "fallo al canjear el código", 400
        datos = validar_jwt(r.json()["access_token"])
        sid = secrets.token_urlsafe(16)
        sesiones[sid] = (datos["preferred_username"], time.time())
        respuesta = redirect("/")
        respuesta.set_cookie("APPSESSION", sid, httponly=True, samesite="Lax")
        return respuesta

    @app.get("/")
    def portada():
        usuario = usuario_actual()
        if usuario is None:
            return a_keycloak()
        respuesta = Response(f"""<!doctype html><html><head><title>Panel</title></head><body>
<h1 id="hola">Panel de {html.escape(usuario)}</h1>
<a href="/perfil">Perfil</a> <a href="/buscar?q=facturas">Buscar</a>
<a href="/admin">Administración</a> <a href="/logout">Salir</a></body></html>""")
        # Solo existe con sesión: si aparece en el informe, se escaneó dentro.
        respuesta.set_cookie("preferencias", "tema-oscuro")
        return respuesta

    @app.get("/perfil")
    def perfil():
        usuario = usuario_actual()
        return a_keycloak() if usuario is None else f"<h1>Perfil de {usuario}</h1>"

    @app.get("/buscar")
    def buscar():
        if usuario_actual() is None:
            return a_keycloak()
        # Reflejo sin escapar, solo visible con sesión.
        return f"<h1>Resultados para {request.args.get('q', '')}</h1>"

    @app.get("/admin")
    def admin():
        usuario = usuario_actual()
        if usuario is None:
            return a_keycloak()
        if "admin" not in USUARIOS[usuario]["roles"]:
            return "prohibido", 403
        return "<h1>Administración</h1><p>usuarios: ana, admin</p>"

    @app.get("/logout")
    def logout():
        sesiones.pop(request.cookies.get("APPSESSION", ""), None)
        return redirect("/")

    return app


# ── Aplicación de página única (token en cabecera) ─────────────────────────
def crear_spa(idp: str) -> Flask:
    app = Flask("spa-con-keycloak")

    @app.get("/")
    def portada():
        return f"""<!doctype html><html><head><title>SPA</title></head><body>
<h1 id="hola">Cargando…</h1>
<script>
const KC = "{idp}/realms/crux/protocol/openid-connect";
async function main() {{
  const q = new URLSearchParams(location.search);
  let token = sessionStorage.getItem("t");
  if (!token && q.get("code")) {{
    const r = await fetch(KC + "/token", {{method: "POST",
      body: new URLSearchParams({{grant_type: "authorization_code", code: q.get("code"),
                                 client_id: "spa", redirect_uri: location.origin + "/"}})}});
    token = (await r.json()).access_token;
    sessionStorage.setItem("t", token);
    history.replaceState({{}}, "", "/");
  }}
  if (!token) {{
    location = KC + "/auth?client_id=spa&response_type=code&state=x&redirect_uri="
      + encodeURIComponent(location.origin + "/");
    return;
  }}
  const yo = await (await fetch("/api/yo", {{headers: {{Authorization: "Bearer " + token}}}})).json();
  document.getElementById("hola").textContent = "Hola, " + yo.usuario;
}}
main();
</script></body></html>"""

    def con_token():
        cabecera = request.headers.get("Authorization", "")
        return validar_jwt(cabecera[7:]) if cabecera.startswith("Bearer ") else None

    @app.get("/api/yo")
    def yo():
        datos = con_token()
        if datos is None:
            return {"error": "no autenticado"}, 401
        return {"usuario": datos["preferred_username"]}

    @app.get("/api/notas")
    def notas():
        if con_token() is None:
            return {"error": "no autenticado"}, 401
        return {"q": request.args.get("q", ""), "notas": []}

    return app


# ── Arranque en hilos, para las pruebas ────────────────────────────────────
@dataclass
class Laboratorio:
    idp: str
    app: str
    spa: str
    estado: EstadoIdP
    _servidores: list = field(default_factory=list)

    def parar(self) -> None:
        for s in self._servidores:
            s.shutdown()


def _servir(aplicacion: Flask, host: str):
    servidor = make_server(host, 0, aplicacion, threaded=True)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    return servidor, f"http://{host}:{servidor.server_port}"


def levantar(*, caducidad_sesion: float | None = None,
             caducidad_token: int = 300) -> Laboratorio:
    """El proveedor en 127.0.0.2 y las aplicaciones en 127.0.0.1.

    Dos direcciones distintas, no dos puertos: las cookies no se separan por
    puerto, y con el mismo host las del proveedor llegarían a la aplicación,
    que es justo lo que no pasa con un Keycloak de verdad.
    """
    estado = EstadoIdP(caducidad_token=caducidad_token)
    s_idp, idp = _servir(crear_idp(estado), "127.0.0.2")
    s_app, app = _servir(crear_app(idp, caducidad_sesion=caducidad_sesion), "127.0.0.1")
    s_spa, spa = _servir(crear_spa(idp), "127.0.0.1")
    return Laboratorio(idp=idp, app=app, spa=spa, estado=estado,
                       _servidores=[s_idp, s_app, s_spa])


if __name__ == "__main__":
    lab = levantar()
    print(f"proveedor  {lab.idp}\napp        {lab.app}\nspa        {lab.spa}")
    print("usuarios: ana/ana-clave, admin/admin-clave, otp/otp-clave, cambio/cambio-clave")
    threading.Event().wait()
