"""Servicio de facturación. Código con fallos plantados para pruebas."""
import os
import sqlite3
import subprocess
import hashlib
from flask import Flask, request

app = Flask(__name__)

# hardcoded-secret: credencial en el código fuente.
DB_PASSWORD = "Verano2026!"
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


@app.route("/buscar")
def buscar():
    # sql-injection: el parámetro se concatena en la consulta.
    termino = request.args.get("q", "")
    conexion = sqlite3.connect("facturas.db")
    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM clientes WHERE nombre = '" + termino + "'")
    return str(cursor.fetchall())


@app.route("/exportar")
def exportar():
    # command-injection: entrada del usuario a un shell.
    formato = request.args.get("formato", "csv")
    salida = subprocess.check_output(f"/usr/bin/exportar --formato {formato}", shell=True)
    return salida


def hash_contrasena(clave: str) -> str:
    # weak-hash: MD5 para contraseñas.
    return hashlib.md5(clave.encode()).hexdigest()


@app.route("/plantilla")
def plantilla():
    # code-injection: evaluación de entrada del usuario.
    expresion = request.args.get("expr", "1+1")
    return str(eval(expresion))


if __name__ == "__main__":
    # debug-enabled: modo depuración en producción.
    app.run(host="0.0.0.0", debug=True)
