"""Repositorio de código deliberadamente vulnerable.

Existe para verificar que el pilar de análisis de código detecta lo que dice
detectar, en los cinco ecosistemas que la organización usa. Nada de esto se
despliega: es un fixture de test.
"""

# Clases que un escaneo de código debería encontrar aquí.
EXPECTED_FINDINGS: dict[str, str] = {
    "sql-injection": "Concatenación en consultas SQL en los cinco lenguajes",
    "command-injection": "Entrada del usuario a un shell en Python, JS, Java y PHP",
    "code-injection": "eval() sobre entrada del usuario en Python y JavaScript",
    "weak-hash": "MD5 para contraseñas en Python",
    "deserialization": "ObjectInputStream sobre datos no confiables en Java",
    "file-inclusion": "include() con entrada del usuario en PHP",
    "xss": "Salida sin escapar en JavaScript y PHP",
    "debug-enabled": "Flask con debug=True",
    "hardcoded-secret": "Credenciales en el código en los cinco lenguajes",
    "env-file-committed": ".env versionado con claves de AWS y Slack",
    "private-key": "Clave privada RSA en el repositorio",
    "vulnerable-dependency": "Dependencias con CVE en pip, npm, Maven, Composer y NuGet",
}
