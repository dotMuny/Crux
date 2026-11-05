"""App Flask con fallos plantados. Solo 127.0.0.1. Fixture de test, nada más.

Cada ruta lleva el identificador de la clase de hallazgo que debe disparar, para
que `EXPECTED_FINDINGS` y los tests no se desincronicen del código.
"""

from __future__ import annotations

import base64
import hmac
import json
import sqlite3
from hashlib import sha256

from flask import Flask, Response, jsonify, make_response, request

# Clases de hallazgo que un escaneo completo debería encontrar aquí. Los tests
# comprueban esta lista contra lo detectado; si se añade una vulnerabilidad,
# se añade su clave aquí.
EXPECTED_FINDINGS: dict[str, str] = {
    "missing-security-headers": "Ninguna respuesta lleva CSP, HSTS, X-Frame-Options ni nosniff",
    "cookie-insecure-flags": "La cookie de sesión no tiene Secure, HttpOnly ni SameSite",
    "cors-permissive-credentials": "ACAO refleja el Origin y permite credenciales",
    "verbose-server-header": "Server y X-Powered-By revelan producto y versión",
    "jwt-alg-none-accepted": "/api/me acepta un JWT con alg:none sin verificar firma",
    "sql-injection": "/search concatena el parámetro q en la consulta SQL",
    "reflected-xss": "/greet devuelve el parámetro name sin escapar",
    "idor-invoice": "/invoice/<id> no comprueba la propiedad del recurso",
    "directory-listing": "/files/ lista el contenido del directorio",
    "exposed-debug-endpoint": "/debug/env expone configuración y variables",
    "exposed-git-config": "/.git/config es accesible",
    "open-redirect": "/go?next= redirige a cualquier destino",
    "session-fixation": "El identificador de sesión no se renueva al iniciar sesión",
    "privilege-in-cookie": "El rol viaja en la cookie y el servidor se fía de él",
    "jwt-secreto-debil": "El JWT se firma con el secreto «secret»",
    "jwt-sin-caducidad": "El JWT emitido no incluye exp",
    "jwt-claims-sensibles": "El JWT lleva la contraseña en el payload",
}

# Credenciales de juguete. El fixture necesita dos roles para poder comprobar
# el control de acceso: sin dos sesiones no hay nada que comparar.
USUARIOS: dict[str, tuple[str, str, int]] = {
    #  usuario : (contraseña, rol, id)
    "ana": ("Primavera2026", "admin", 1),
    "luis": ("luis123", "user", 2),
}

# Secreto débil a propósito, y el MISMO con el que se firma: antes se
# firmaba con uno y se verificaba con otro, así que ni los tokens
# legítimos pasaban. Un fallo plantado tiene que ser realista.
_SECRET = b"secret"


def _db() -> sqlite3.Connection:
    """Base en memoria por petición. Datos de juguete."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);
        INSERT INTO users VALUES (1,'ana','ana@intra.corp','admin'),
                                 (2,'luis','luis@intra.corp','user'),
                                 (3,'marta','marta@intra.corp','user');
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER, total TEXT);
        INSERT INTO invoices VALUES (1001,1,'1.240,00'),(1002,2,'310,50'),(1003,3,'99,90');
        """
    )
    return connection


def create_app() -> Flask:
    app = Flask(__name__)

    @app.after_request
    def _leak_headers(response: Response) -> Response:
        # missing-security-headers + verbose-server-header: se declara producto y
        # versión, y no se añade ninguna cabecera de seguridad.
        response.headers["Server"] = "Apache/2.4.49 (Unix) OpenSSL/1.0.2k-fips"
        response.headers["X-Powered-By"] = "PHP/5.6.40"
        # cors-permissive-credentials: refleja el Origin y admite credenciales,
        # que es la combinación que de verdad permite leer respuestas autenticadas.
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    @app.route("/")
    def index() -> Response:
        response = make_response(
            """<!doctype html><html><head><title>Portal Interno de Facturación</title>
            <meta name="generator" content="IntraPortal 3.2"></head>
            <body><h1>Portal Interno</h1>
            <form action="/search" method="get"><input name="q"><button>Buscar</button></form>
            <ul><li><a href="/greet?name=equipo">Saludo</a></li>
            <li><a href="/invoice/1001">Factura 1001</a></li>
            <li><a href="/files/">Documentos</a></li>
            <li><a href="/api/me">Mi perfil</a></li></ul>
            <script src="/static/app.js"></script></body></html>"""
        )
        # cookie-insecure-flags: sin Secure, sin HttpOnly, sin SameSite.
        # Solo se siembra si no hay sesión: reescribirla en cada visita, como
        # hacía antes, destruía la sesión recién iniciada y hacía que el
        # escaneo recorriera la aplicación como anónimo creyendo ir dentro.
        if "SESSIONID" not in request.cookies:
            response.set_cookie("SESSIONID", "s3ss10n-de-pruebas",
                                httponly=False, secure=False)
        # session-fixation: identificador que se reparte a cualquier visitante
        # y que el inicio de sesión NO renueva. Quien lo fije en el navegador
        # de la víctima queda dentro de su cuenta en cuanto ella entre.
        if "sid" not in request.cookies:
            response.set_cookie("sid", "fijo-para-todos", httponly=False, secure=False)
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response:
        if request.method == "GET":
            return make_response(
                """<!doctype html><html><head><title>Acceso · Portal Interno</title></head>
                <body><h1>Acceso</h1>
                <form method="post" action="/login">
                  <label>Usuario <input name="username" type="text"></label>
                  <label>Contraseña <input name="password" type="password"></label>
                  <button type="submit">Entrar</button>
                </form>
                <p><a href="/go?next=/mis-facturas">Volver a donde estaba</a></p>
                </body></html>"""
            )

        usuario = request.form.get("username", "")
        clave = request.form.get("password", "")
        registro = USUARIOS.get(usuario)
        if registro is None or registro[0] != clave:
            return make_response(
                "<html><title>Acceso</title><p>Credenciales incorrectas</p></html>", 401
            )

        _, rol, uid = registro
        response = make_response("", 302, {"Location": "/"})
        # La aplicación emite también un JWT para su API. Firmado con un
        # secreto de tutorial y sin caducidad: dos fallos plantados a la vez.
        cabecera = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64e(json.dumps(
            {"sub": usuario, "rol": rol, "uid": uid, "password": clave}
        ).encode())
        firma = _b64e(hmac.new(b"secret", f"{cabecera}.{payload}".encode(), sha256).digest())
        response.set_cookie("api_token", f"{cabecera}.{payload}.{firma}",
                            httponly=False, secure=False)
        # session-fixation: el identificador no se renueva al autenticarse, así
        # que vale el que ya tuviera el navegador antes de entrar.
        # privilege-in-cookie: el rol y el identificador de usuario viajan en la
        # propia cookie, sin firmar: el cliente puede reescribirlos.
        response.set_cookie("SESSIONID", f"{usuario}:{rol}:{uid}",
                            httponly=False, secure=False)
        # El identificador de seguimiento se conserva tal cual: ésa es la
        # fijación de sesión.
        return response

    @app.route("/logout")
    def logout() -> Response:
        response = make_response("", 302, {"Location": "/"})
        response.set_cookie("SESSIONID", "", expires=0)
        return response

    def sesion() -> tuple[str, str, int] | None:
        """Lee la sesión de la cookie. Se fía de ella: ése es el fallo."""
        cookie = request.cookies.get("SESSIONID", "")
        partes = cookie.split(":")
        if len(partes) != 3 or not partes[2].isdigit():
            return None
        return partes[0], partes[1], int(partes[2])

    @app.route("/mis-facturas")
    def mis_facturas() -> Response:
        """Solo el listado propio. El detalle, en cambio, no comprueba nada."""
        actual = sesion()
        if actual is None:
            return make_response("", 302, {"Location": "/login"})
        connection = _db()
        filas = connection.execute(
            "SELECT id, total FROM invoices WHERE owner_id = ?", (actual[2],)
        ).fetchall()
        items = "".join(
            f'<li><a href="/invoice/{r[0]}">Factura {r[0]}</a> — {r[1]} €</li>' for r in filas
        )
        return make_response(
            f"<html><title>Mis facturas</title><p>Sesión: {actual[0]} ({actual[1]})</p>"
            f"<ul>{items}</ul></html>"
        )

    @app.route("/admin/export")
    def admin_export() -> Response:
        """Debería ser solo de administración; no lo comprueba."""
        actual = sesion()
        if actual is None:
            return make_response("", 302, {"Location": "/login"})
        connection = _db()
        filas = connection.execute("SELECT id, name, email, role FROM users").fetchall()
        csv = "id,name,email,role\n" + "\n".join(",".join(map(str, f)) for f in filas)
        return Response(csv, mimetype="text/csv")

    @app.route("/search")
    def search() -> Response:
        # sql-injection: concatenación directa del parámetro en el SQL.
        term = request.args.get("q", "")
        connection = _db()
        query = f"SELECT id, name, email FROM users WHERE name LIKE '%{term}%'"  # noqa: S608
        try:
            rows = connection.execute(query).fetchall()
        except sqlite3.Error as exc:
            # El error se devuelve al cliente tal y como lo haría una aplicación
            # con el modo de depuración puesto: con el nombre de la excepción de
            # Python incluido. El formato importa — es por lo que los escáneres
            # reconocen el motor, y un mensaje inventado no prueba nada.
            return make_response(
                f"<pre>{type(exc).__module__}.{type(exc).__name__}: {exc}\n"
                f"query: {query}</pre>", 500
            )
        items = "".join(f"<li>{r[1]} &lt;{r[2]}&gt;</li>" for r in rows)
        return make_response(f"<html><title>Resultados</title><ul>{items}</ul></html>")

    @app.route("/greet")
    def greet() -> Response:
        # reflected-xss: el parámetro se interpola en el HTML sin escapar.
        name = request.args.get("name", "invitado")
        return make_response(f"<html><title>Saludo</title><h1>Hola, {name}</h1></html>")

    @app.route("/invoice/<int:invoice_id>")
    def invoice(invoice_id: int) -> Response:
        # idor-invoice: se sirve la factura sin comprobar de quién es.
        connection = _db()
        row = connection.execute(
            "SELECT id, owner_id, total FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
        if row is None:
            return make_response(jsonify({"error": "no existe"}), 404)
        return make_response(jsonify({"id": row[0], "owner_id": row[1], "total": row[2]}))

    @app.route("/api/me")
    def api_me() -> Response:
        # jwt-alg-none-accepted: si el header dice alg:none, se acepta el payload
        # sin verificar nada.
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return make_response(jsonify({"error": "falta el token"}), 401)
        token = auth.removeprefix("Bearer ").strip()
        try:
            header_b64, payload_b64, signature = token.split(".")
            header = json.loads(_b64d(header_b64))
            payload = json.loads(_b64d(payload_b64))
        except Exception:
            return make_response(jsonify({"error": "token ilegible"}), 400)

        if header.get("alg", "").lower() == "none":
            return make_response(jsonify({"user": payload, "verified": False}))
        expected = hmac.new(
            _SECRET, f"{header_b64}.{payload_b64}".encode(), sha256
        ).digest()
        if not hmac.compare_digest(_b64e(expected), signature):
            return make_response(jsonify({"error": "firma inválida"}), 401)
        return make_response(jsonify({"user": payload, "verified": True}))

    @app.route("/files/")
    def files() -> Response:
        # directory-listing: índice navegable del directorio.
        entries = ["nominas-2026.xlsx", "contrato-proveedor.pdf", "backup.sql", "notas.txt"]
        items = "".join(f'<li><a href="/files/{e}">{e}</a></li>' for e in entries)
        return make_response(
            f"<html><title>Index of /files/</title><h1>Index of /files/</h1>"
            f"<ul>{items}</ul></html>"
        )

    @app.route("/debug/env")
    def debug_env() -> Response:
        # exposed-debug-endpoint: configuración y secretos a la vista.
        return make_response(
            jsonify(
                {
                    "DEBUG": True,
                    "DB_DSN": "postgresql://intra:Verano2026@db.intra.corp:5432/billing",
                    "SECRET_KEY": "clave-de-pruebas-no-usar",
                    "SMTP_PASSWORD": "Correo.2026",
                }
            )
        )

    @app.route("/.git/config")
    def git_config() -> Response:
        # exposed-git-config: metadatos del repositorio accesibles.
        return Response(
            "[core]\n\trepositoryformatversion = 0\n"
            '[remote "origin"]\n\turl = https://git.intra.corp/billing/portal.git\n',
            mimetype="text/plain",
        )

    @app.route("/go")
    def go() -> Response:
        # open-redirect: destino sin validar.
        destination = request.args.get("next", "/")
        return make_response("", 302, {"Location": destination})

    @app.route("/static/app.js")
    def app_js() -> Response:
        # Endpoints y una clave en el bundle: material para el crawler.
        return Response(
            "const API='/api/v2';\n"
            "fetch(API+'/users');fetch(API+'/invoices?owner=me');\n"
            "fetch('/admin/export?format=csv');\n"
            "const ANALYTICS_KEY='ak_live_9f2b7c1d4e8a';\n",
            mimetype="application/javascript",
        )

    @app.route("/robots.txt")
    def robots() -> Response:
        return Response("User-agent: *\nDisallow: /admin/\nDisallow: /debug/\n",
                        mimetype="text/plain")

    return app


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


if __name__ == "__main__":
    # Solo loopback, siempre. Este fixture no debe ser alcanzable desde la red.
    create_app().run(host="127.0.0.1", port=8999, debug=False)
