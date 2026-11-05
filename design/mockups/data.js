/* Dataset compartido por las tres maquetas. Datos verosímiles de una auditoría
   interna: un portal de facturación, el intranet de RRHH y un Jenkins. */
window.CRUX_SCAN = {
  project: "Intranet · Q4 2026",
  scanId: "scan-0x1f4a",
  profile: "safe-active",
  started: "2026-10-27 18:42",
  duration: "14 min 08 s",
  targets: 4,
  requests: 18422,
  egress: "0 conexiones fuera del alcance",
  scope: ["10.20.4.0/24", "facturacion.intra.corp", "rrhh.intra.corp", "jenkins.intra.corp"],
  tasks: [
    { name: "probe", tool: "crux", status: "done", found: 14 },
    { name: "crawler", tool: "playwright", status: "done", found: 0 },
    { name: "nuclei", tool: "nuclei v3.11.1", status: "done", found: 9 },
    { name: "ffuf", tool: "ffuf 2.1.0", status: "done", found: 3 },
    { name: "sslscan", tool: "sslscan 2.1.5", status: "done", found: 2 },
    { name: "authz", tool: "crux", status: "running", found: 1 }
  ],
  trend: [
    { scan: "sem 38", critical: 1, high: 2, medium: 5, low: 7 },
    { scan: "sem 40", critical: 1, high: 3, medium: 6, low: 9 },
    { scan: "sem 42", critical: 2, high: 4, medium: 6, low: 8 },
    { scan: "sem 44", critical: 2, high: 3, medium: 4, low: 9 }
  ]
};

window.CRUX_FINDINGS = [
  {
    id: 1, sev: "critical", conf: "certain", state: "new", source: "nuclei",
    check: "springboot-actuator-env", cwe: "CWE-200", cvss: 9.8,
    title: "Spring Boot Actuator expone /env sin autenticación",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/actuator/env",
    firstSeen: "sem 42", desc:
      "El endpoint de gestión /actuator/env responde sin credenciales y devuelve toda la configuración del contexto de Spring, incluidas las propiedades del origen de datos y las variables de entorno del proceso.",
    fix: "Restringe management.endpoints.web.exposure.include a health e info, o mueve los actuators a un puerto de gestión no publicado y protégelo con Spring Security.",
    req: "GET /actuator/env HTTP/1.1\nHost: facturacion.intra.corp\nUser-Agent: crux/0.1 (authorized internal audit)\nAccept: */*\nConnection: close\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: application/vnd.spring-boot.actuator.v3+json\nContent-Length: 8841\n\n{\n  \"activeProfiles\": [\"prod\"],\n  \"propertySources\": [{\n    \"name\": \"systemEnvironment\",\n    \"properties\": {\n      \"SPRING_DATASOURCE_URL\": { \"value\": \"jdbc:postgresql://db.intra.corp:5432/billing\" },\n      \"SPRING_DATASOURCE_PASSWORD\": { \"value\": \"Verano2026!\" },\n      \"JWT_SIGNING_KEY\": { \"value\": \"kR8p2mQ...\" }\n    }\n  }]\n}",
    highlight: "SPRING_DATASOURCE_PASSWORD"
  },
  {
    id: 2, sev: "critical", conf: "certain", state: "confirmed", source: "crux",
    check: "sqli-error-based", cwe: "CWE-89", cvss: 9.1, param: "q",
    title: "Inyección SQL basada en error en el buscador de clientes",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/search?q=",
    firstSeen: "sem 44", desc:
      "El parámetro q se concatena directamente en la cláusula WHERE. Una comilla simple provoca un error de SQLite que se devuelve al cliente junto con la consulta completa, lo que permite reconstruir el esquema y extraer datos.",
    fix: "Usa consultas parametrizadas. Además, desactiva la traza de errores hacia el cliente en producción.",
    req: "GET /search?q=ana%27 HTTP/1.1\nHost: facturacion.intra.corp\nUser-Agent: crux/0.1 (authorized internal audit)\n\n",
    res: "HTTP/1.1 500 INTERNAL SERVER ERROR\nContent-Type: text/html; charset=utf-8\n\n<pre>SQL error: unrecognized token: \"'%ana'%'\"\nquery: SELECT id, name, email FROM users WHERE name LIKE '%ana'%'</pre>",
    highlight: "SQL error: unrecognized token"
  },
  {
    id: 3, sev: "high", conf: "certain", state: "new", source: "crux",
    check: "jwt-alg-none", cwe: "CWE-347", cvss: 8.1,
    title: "La API acepta un JWT con alg:none",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/api/me",
    firstSeen: "sem 44", desc:
      "Con la cabecera alg puesta a none, el servicio decodifica el payload y lo da por válido sin verificar firma. Permite suplantar a cualquier usuario, rol de administrador incluido.",
    fix: "Fija una lista de algoritmos permitidos en el verificador y rechaza none explícitamente. Verifica también iss, aud y exp.",
    req: "GET /api/me HTTP/1.1\nHost: facturacion.intra.corp\nAuthorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbmEiLCJyb2xlIjoiYWRtaW4ifQ.\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user\":{\"sub\":\"ana\",\"role\":\"admin\"},\"verified\":false}",
    highlight: "\"verified\":false"
  },
  {
    id: 4, sev: "high", conf: "certain", state: "new", source: "crux",
    check: "debug-endpoint-exposed", cwe: "CWE-215", cvss: 7.5,
    title: "Endpoint de depuración con credenciales en claro",
    host: "rrhh.intra.corp", ip: "10.20.4.31",
    target: "https://rrhh.intra.corp/debug/env",
    firstSeen: "sem 40", desc:
      "La ruta /debug/env devuelve el DSN de la base de datos, la clave de firma de sesión y la contraseña de SMTP. Accesible sin autenticar desde toda la red interna.",
    fix: "Elimina la ruta del build de producción. Rota las tres credenciales expuestas: hay que asumirlas comprometidas.",
    req: "GET /debug/env HTTP/1.1\nHost: rrhh.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"DEBUG\": true,\n  \"DB_DSN\": \"postgresql://intra:Verano2026@db.intra.corp:5432/rrhh\",\n  \"SECRET_KEY\": \"3f9a1c...\",\n  \"SMTP_PASSWORD\": \"Correo.2026\"\n}",
    highlight: "SMTP_PASSWORD"
  },
  {
    id: 5, sev: "high", conf: "firm", state: "new", source: "crux",
    check: "authz-idor", cwe: "CWE-639", cvss: 7.1,
    title: "Factura de otro usuario accesible cambiando el identificador",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/invoice/{id}",
    firstSeen: "sem 44", desc:
      "Con la sesión del rol usuario, la respuesta a /invoice/1001 (propiedad de otro usuario) es idéntica en estructura y código 200. Se comparó contra la sesión propietaria: no hay diferencia de control de acceso.",
    fix: "Comprueba la propiedad del recurso en el servidor antes de devolverlo. No basta con ocultar el enlace en la interfaz.",
    req: "GET /invoice/1001 HTTP/1.1\nHost: facturacion.intra.corp\nCookie: SESSIONID=rol-usuario-luis\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1001,\"owner_id\":1,\"total\":\"1.240,00\"}",
    diff: true, highlight: "\"owner_id\":1"
  },
  {
    id: 6, sev: "medium", conf: "certain", state: "new", source: "nuclei",
    check: "CVE-2021-41773", cwe: "CWE-22", cvss: 6.5,
    title: "Apache 2.4.49 con path traversal conocido",
    host: "rrhh.intra.corp", ip: "10.20.4.31",
    target: "https://rrhh.intra.corp/cgi-bin/",
    firstSeen: "sem 38", desc:
      "La cabecera Server declara Apache/2.4.49, afectada por CVE-2021-41773. La prueba de lectura fuera del raíz documental no tuvo éxito, así que la versión es el indicio, no la explotación.",
    fix: "Actualiza a 2.4.51 o posterior.",
    req: "GET /cgi-bin/.%2e/%2e%2e/etc/passwd HTTP/1.1\nHost: rrhh.intra.corp\n\n",
    res: "HTTP/1.1 403 Forbidden\nServer: Apache/2.4.49 (Unix) OpenSSL/1.0.2k-fips\n\n<html><head><title>403 Forbidden</title></head>",
    highlight: "Apache/2.4.49"
  },
  {
    id: 7, sev: "medium", conf: "certain", state: "new", source: "crux",
    check: "cors-reflect-credentials", cwe: "CWE-942", cvss: 6.1,
    title: "CORS refleja cualquier Origin y permite credenciales",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/api/v2/users",
    firstSeen: "sem 42", desc:
      "El servidor copia el Origin recibido a Access-Control-Allow-Origin y añade Allow-Credentials: true. Cualquier página que un empleado abra puede leer respuestas autenticadas de esta API.",
    fix: "Usa una lista blanca de orígenes. Allow-Credentials nunca debe combinarse con un origen reflejado.",
    req: "GET /api/v2/users HTTP/1.1\nHost: facturacion.intra.corp\nOrigin: https://atacante.example\n\n",
    res: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://atacante.example\nAccess-Control-Allow-Credentials: true\n\n[{\"id\":1,\"name\":\"ana\"}]",
    highlight: "Access-Control-Allow-Credentials: true"
  },
  {
    id: 8, sev: "medium", conf: "certain", state: "false_positive", source: "crux",
    check: "cookie-missing-flags", cwe: "CWE-614", cvss: 5.3,
    title: "Cookie de sesión sin Secure, HttpOnly ni SameSite",
    host: "wiki.intra.corp", ip: "10.20.4.44",
    target: "https://wiki.intra.corp/",
    firstSeen: "sem 38", desc:
      "SESSIONID se emite sin ninguno de los tres atributos. Marcada como falso positivo: el equipo de wiki confirma que es una cookie de preferencias de tema, no de sesión.",
    fix: "Si en algún momento pasa a identificar sesión, añade Secure, HttpOnly y SameSite=Lax.",
    req: "GET / HTTP/1.1\nHost: wiki.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\nSet-Cookie: SESSIONID=tema-oscuro; Path=/\n\n<!doctype html>",
    highlight: "Set-Cookie: SESSIONID=tema-oscuro; Path=/"
  },
  {
    id: 9, sev: "low", conf: "certain", state: "new", source: "nuclei",
    check: "directory-listing", cwe: "CWE-548", cvss: 3.7,
    title: "Listado de directorio habilitado en /files/",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/files/",
    firstSeen: "sem 40", desc:
      "El índice automático revela nombres de ficheros, entre ellos backup.sql y nominas-2026.xlsx.",
    fix: "Desactiva autoindex en la configuración del servidor y retira los ficheros que no deban publicarse.",
    req: "GET /files/ HTTP/1.1\nHost: facturacion.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\n\n<title>Index of /files/</title><ul>\n<li><a href=\"nominas-2026.xlsx\">nominas-2026.xlsx</a></li>\n<li><a href=\"backup.sql\">backup.sql</a></li></ul>",
    highlight: "backup.sql"
  },
  {
    id: 10, sev: "low", conf: "certain", state: "accepted_risk", source: "crux",
    check: "missing-security-headers", cwe: "CWE-693", cvss: 3.1,
    title: "Siete cabeceras de seguridad ausentes",
    host: "jenkins.intra.corp", ip: "10.20.4.7",
    target: "https://jenkins.intra.corp/",
    firstSeen: "sem 38", desc:
      "Faltan CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy y COOP. Aceptado como riesgo: el proxy inverso las añadirá en el cambio planificado de noviembre.",
    fix: "Añadir las cabeceras en el proxy inverso que publica Jenkins.",
    req: "GET / HTTP/1.1\nHost: jenkins.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Jenkins: 2.440.1\n\n<!doctype html>",
    highlight: "X-Jenkins: 2.440.1"
  },
  {
    id: 11, sev: "info", conf: "certain", state: "new", source: "nuclei",
    check: "git-config-exposure", cwe: "CWE-538", cvss: 0,
    title: "/.git/config accesible",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/.git/config",
    firstSeen: "sem 44", desc:
      "Revela la URL del repositorio de origen. El directorio .git completo no es descargable: no hay objetos accesibles.",
    fix: "Excluye los directorios con punto en la configuración del servidor.",
    req: "GET /.git/config HTTP/1.1\nHost: facturacion.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.intra.corp/billing/portal.git",
    highlight: "url = https://git.intra.corp/billing/portal.git"
  },
  {
    id: 12, sev: "info", conf: "firm", state: "new", source: "crux",
    check: "tech-fingerprint", cwe: "—", cvss: 0,
    title: "Pila tecnológica identificada",
    host: "facturacion.intra.corp", ip: "10.20.4.18",
    target: "https://facturacion.intra.corp/",
    firstSeen: "sem 38", desc:
      "Apache httpd 2.4.49 publicando Spring Boot con sesiones de servlet Java. Generator declara IntraPortal 3.2.",
    fix: "Retira las cabeceras que declaran producto y versión.",
    req: "GET / HTTP/1.1\nHost: facturacion.intra.corp\n\n",
    res: "HTTP/1.1 200 OK\nServer: Apache/2.4.49 (Unix)\nSet-Cookie: JSESSIONID=9F2B...; Path=/\n\n<meta name=\"generator\" content=\"IntraPortal 3.2\">",
    highlight: "JSESSIONID"
  }
];
