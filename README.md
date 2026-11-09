# Crux

Auditoría de aplicaciones web internas y de su código, desde el Kali de cada
analista. **En ejecución no habla con nadie que no sea el objetivo.**

No es un escáner nuevo: es el cerebro que orquesta las herramientas que ya
tienes —nuclei, wapiti, semgrep, gitleaks, trivy—, les quita las fugas de red
que traen de serie, añade los módulos que faltaban, y mete todo en un único
modelo de hallazgos con informe, interfaz y triaje compartidos.

```
crux doctor                      comprueba entorno, datos y política de egress
crux scan web https://app.intra  DAST, recon, crawler autenticado, roles, JWT
crux scan code /ruta/al/repo     SAST, secretos y dependencias vulnerables
crux diff 12 13                  qué cambió entre dos escaneos
crux web                         interfaz en 127.0.0.1:8777
```

---

## Instalación

### En un equipo con red

```bash
git clone https://github.com/dotMuny/Crux.git && cd Crux
bash install/bootstrap.sh
```

Descarga las plantillas de nuclei, las reglas de semgrep fijadas a un commit y
la base de vulnerabilidades de trivy. **Es el único momento en que se usa
internet.**

Al terminar deja la orden `crux` enlazada en `~/.local/bin`, así que se invoca
sin activar el entorno virtual. Si acabas de crear ese directorio, no estará en
tu `PATH` hasta que abras una sesión nueva; el instalador te avisa si es el
caso.

### En un equipo sin red

Desde el equipo de build, una vez:

```bash
bash install/bundle.sh          # → dist/crux-<version>.tar.gz (~180 MB)
```

Lleva el tarball al equipo de destino —repositorio interno, USB— y allí:

```bash
tar -xzf crux-<version>.tar.gz && cd crux-<version>
./instalar.sh
```

El instalador no abre un socket. Termina recalculando el SHA256 de cada pieza
contra el manifiesto: si algo se alteró entre la máquina de build y el equipo
del analista, te lo dice.

> El `dist/` de la interfaz web viaja ya compilado. **npm no toca el equipo de
> ningún analista**: solo la máquina de build tiene Node, y allí la instalación
> corre con los scripts de dependencias bloqueados y una espera de siete días
> antes de aceptar una versión recién publicada.

---

## Los dos pilares

### Aplicaciones web

```bash
crux scan web https://facturacion.intra.corp/ --project "Intranet"
```

Descubre, toma huella, recorre con navegador real, audita la API que hay por
debajo, lanza nuclei acotado a lo que la huella dice que hay delante, y aplica
las comprobaciones propias.

Con autenticación y comparación de roles:

```bash
crux scan web https://facturacion.intra.corp/ \
  --login-url https://facturacion.intra.corp/ \
  --user analista --password '…' \
  --role luis:user:luis:'…' \
  --role ana:admin:ana:'…' \
  --report informe.html
```

La URL de acceso es la de la aplicación **aunque el formulario esté en un
Keycloak o un ADFS**: Crux sigue la redirección con un navegador real, entra
donde le manden y vuelve. El proveedor se descubre solo y queda en el alcance
para entrar, no para auditarlo. Solo hace falta nombrarlo con `--idp` cuando la
aplicación salta a él con JavaScript, como las que usan keycloak-js; si no se
nombra, el login lo dice con el host exacto.

La sesión la usan **todas** las fases: sondas, comprobaciones propias, crawler,
nuclei y wapiti. Si no se consigue entrar, el escaneo **se para** y dice por
qué —credenciales rechazadas, segundo factor, una acción pendiente en el
proveedor, un host sin declarar—. No sigue como anónimo: el informe parecería
completo sin serlo.

Dos `--role` o más activan el análisis de control de acceso. Con uno solo no
hay nada que comparar y te lo advierte. Cada rol entra en un navegador limpio:
con un proveedor de SSO, compartirlo hacía que el segundo entrase como el
primero.

### La API que hay por debajo

Casi toda aplicación interna es una interfaz que habla con una API, y la API es
donde está la lógica. Crux la audita por dos vías, sin que haya que pedirlo:

- **Lo que hace la interfaz.** El navegador registra cada llamada con su
  **método y su cuerpo**: un `POST /api/buscar` con `{"q": "…"}` entra como
  endpoint con el parámetro `q`, y las fases activas pueden probarlo. Antes se
  apuntaba la URL y nada más, así que un parámetro que viaja en el cuerpo —en
  una API REST, casi todos— no tenía dónde probarse.
- **Lo que declara la especificación.** Si la aplicación publica un OpenAPI o
  un Swagger —`/openapi.json`, `/v3/api-docs`, `/swagger/v1/swagger.json` y una
  docena más—, se lee y se convierte en endpoints con sus parámetros y un cuerpo
  de ejemplo. Eso cubre lo que la interfaz no llega a pulsar. wapiti la recibe
  con `--swagger` y nuclei hace una segunda pasada en su modo OpenAPI.

Si la tienes a mano y la aplicación no la publica, pásala:

```bash
crux scan web https://facturacion.intra.corp/ --openapi ./openapi.yaml
```

Tres cosas que conviene saber:

- **La especificación es dato del objetivo, no configuración.** Declara sus
  propios servidores, y uno puede apuntar a otro host. De un servidor declarado
  se toma solo la ruta: el host es siempre el del alcance. Que declare un
  servidor de fuera se cuenta como hallazgo informativo, pero no se toca.
- **`PUT`, `PATCH` y `DELETE` no se tocan** salvo con el perfil agresivo, que
  es el que autoriza métodos destructivos. `DELETE /pedidos/{id}` está en toda
  especificación, y en la aplicación de un cliente borra un pedido de verdad.
- **De los cuerpos capturados se guardan los nombres, no los valores.** El
  cuerpo de la petición de acceso lleva la contraseña: los valores de los
  campos que lo parecen —`password`, `token`, `clave`, `cvv`…— se sustituyen
  por `***` antes de que nada toque el disco.

**Autorización, operación por operación.** Con dos `--role` o más, cada
operación de la API se repite con cada sesión y se comparan las respuestas. Se
afirma lo que se puede afirmar sin conocer la política de acceso:

- Una operación que devuelve lo mismo a un anónimo que a un usuario. En rutas
  con identificador de recurso —`/api/facturas/1001`— eso basta: una factura no
  es pública porque esté enlazada. En las demás hace falta otra señal, porque
  una API tiene operaciones públicas a propósito; la señal es que la operación
  conteste **cosas distintas a cada usuario**, porque entonces lo que recibió
  el anónimo es la vista de alguien.
- Una ruta que declara privilegio en su propio nombre —`/admin/…`, `/export/…`—
  y responde igual a los dos roles.
- Una ruta que se protege para leer y acepta escribir: si a esa sesión se le
  niega el `GET`, la aplicación sabe que no tiene por qué entrar, y que le
  acepte un `PUT` en la misma ruta es el control puesto en un sitio y olvidado
  en el otro.

Las operaciones de escritura solo se repiten con el perfil agresivo —un `POST`
crea algo de verdad, una vez por cada sesión— y `DELETE` no se repite con
ningún perfil. Lo que no se comparó, el informe lo dice.

**GraphQL.** Un endpoint y cien operaciones detrás: para wapiti y nuclei eso es
un POST con un campo de texto llamado `query`, y ahí se acaba el análisis. Crux
lo busca por lo que vio el navegador y por las rutas habituales, y entonces:

- pide el esquema, y si la introspección está abierta lo dice y además usa la
  lista de operaciones y argumentos que le acaban de dar;
- si está cerrada, prueba el atajo conocido: con las sugerencias de campo
  activadas, el error de un campo mal escrito dice cómo se llamaba de verdad;
- comprueba si responde sin sesión y si acepta lotes de consultas en una sola
  petición, que es como se saltan los límites de intentos;
- prueba los argumentos de texto de las **consultas** buscando el error del
  motor de base de datos. Las mutaciones no se tocan: cambian datos.

El fuzzing a fondo de cada argumento de GraphQL no lo hace ninguna herramienta
instalada, y aquí no se escribe un fuzzer propio. Lo que se hace en su lugar es
dejar el inventario completo en el informe —cada operación con sus argumentos—
para que el analista vaya a mano a lo que le interese.

Con `--sin-api` se apaga todo esto y el escaneo se queda en lo que vea el
navegador.

Para una API sin interfaz, con token en cabecera:

```bash
crux scan web https://api.intra.corp/ --header 'Authorization: Bearer …'
```

### Código

```bash
crux scan code /ruta/al/repo --project "Intranet" --report codigo.html
```

Cubre Python, JavaScript/TypeScript, Java, PHP y .NET. No usa la red en ningún
momento: la base de vulnerabilidades se consultó en local.

---

## Perfiles

| Perfil | Qué hace | Cuándo |
|---|---|---|
| `passive` | Solo observa. No envía una sola carga | Producción, primera pasada |
| `safe-active` | Detección activa sin fuerza bruta ni inyección profunda | El predeterminado |
| `aggressive` | Todo, incluido fuzzing DAST e inyección | Preproducción o ventana acordada |

El perfil decide también el ritmo (5, 20 u 80 peticiones por segundo) y la
profundidad del recorrido.

---

## Egress cero: qué se garantiza y cómo comprobarlo

Tres capas, de más débil a más fuerte.

**1. Alcance confinado.** Los objetivos se resuelven una vez al arrancar y se
congelan. Solo se admiten redes internas, y **solo las declaradas**: autorizar
`192.168.50.0/24` no autoriza `192.168.51.1`. Un objetivo que resuelva a IP
pública se rechaza salvo `--allow-public`, y queda en el registro de auditoría.

**2. Telemetría desactivada por obligación.** Cada herramienta declara los
flags que necesita y el ejecutor se niega a lanzarla si falta alguno. Esto
importa más de lo que parece: varias salen a internet **por defecto**.

| Herramienta | Qué hace sin que se lo pidas |
|---|---|
| `nuclei` | Usa el Interactsh **público** (`oast.pro`, `oast.live`) para OAST |
| `wapiti` | Envía un informe a sus autores cuando un módulo falla |
| `semgrep` | Manda métricas de uso, y `--config=auto` baja reglas del registry |
| `trivy` | Comprueba si hay base de datos nueva |

Además, el entorno de cada subproceso se construye desde cero por lista
blanca: ni variables de proxy ni credenciales (`AWS_*`, `GITHUB_TOKEN`,
`SSH_AUTH_SOCK`) llegan a la herramienta.

**3. Aislamiento real.**

```bash
crux scan web https://app.intra.corp/ --sandbox
```

El escaneo entero corre dentro de un namespace de red con un único cable hacia
el equipo y una regla que solo deja pasar hacia el alcance. Lo demás **no tiene
ruta**. El DNS congelado se escribe como `/etc/hosts` del namespace y no hay
servidor de nombres, así que el rebinding deja de ser posible.

Necesita privilegios. Sin ellos no se degrada en silencio: te lo dice y sale.

### Comprobarlo tú mismo

```bash
.venv/bin/python -m pytest tests/test_egress.py tests/test_sandbox.py -v
```

Esas pruebas ejecutan las herramientas dentro de un namespace sin ruta por
defecto. Si algo necesitase internet, fallan.

---

## Triaje

El juicio sobre un hallazgo se guarda por huella, no por fila, así que
**sobrevive a los reescaneos**: un falso positivo marcado hoy sigue marcado el
mes que viene, con su nota.

Un hallazgo solo se marca como **corregido** si la comprobación que lo produjo
se volvió a ejecutar. Si cambias de perfil o falta una herramienta, lo que deja
de aparecer se clasifica aparte:

```bash
crux diff 12 13
```

```
Ya no aparecen, pero NO se comprobaron · 1
█  alta   passive:cors-reflects-any-origin   https://app.intra.corp

  Esos hallazgos no se han corregido: el escaneo nuevo no llegó a buscarlos.
```

`crux diff` sale con código distinto de cero si hay regresiones, para
encadenarlo en un trabajo programado.

---

## Interfaz web

```bash
crux web
```

En `127.0.0.1:8777`. **Sin autenticación y solo en loopback, por decisión**:
añadir login sin necesidad invita a exponer el puerto. Si la expones, te avisa.

Cuatro vistas: panel de métricas, triaje de hallazgos (tabla virtualizada,
facetas, `j`/`k`, `⌘K`), grafo de superficie de ataque, y lista de escaneos
desde donde lanzar uno nuevo con progreso en vivo.

**El panel** responde a qué hacer a continuación, no a cuántos hallazgos hay:
cuántos quedan sin triar, qué cambió desde el escaneo anterior —nuevos,
corregidos, los que empeoran y los que **no se volvieron a comprobar**—, qué
comprobación se repite más (suele ser un arreglo que cierra varios), dónde se
concentran, qué herramienta los encontró, qué lleva más tiempo abierto y qué
tareas fallaron o se omitieron en el último escaneo.

**El triaje se deshace**: pulsar otra vez el estado que ya tiene un hallazgo lo
devuelve a «sin triar». Marcar algo por error es más fácil de hacer que de
detectar, y tiene que poder corregirse donde se hizo.

**El grafo de superficie** dibuja todo lo que el escaneo vio, no solo lo que
salió mal: las rutas sondeadas y los endpoints del recorrido salen aunque no
tengan ningún hallazgo —huecas, para distinguirlas—. Una ruta sin hallazgos es
igual de superficie de ataque, y a veces la más interesante. Pulsa un nodo y su
ficha enseña lo que se sabe de él: estado HTTP, título, servidor, tecnologías,
métodos, parámetros y quién lo descubrió; de un hallazgo, su descripción
completa y cómo se corrige. Hay filtro por texto, por severidad mínima, dos
disposiciones (radial y árbol) y la opción de esconder las rutas limpias.

**Los escaneos se pueden borrar** desde la lista, en lote. Se van con ellos sus
hallazgos, su evidencia y las salidas de las herramientas en disco; el triaje
del proyecto se conserva, porque vive por huella y no por escaneo.

**Desde la web se lanzan los dos pilares**: en la vista de escaneos eliges
«Aplicación web» o «Código» y el formulario cambia lo que pide —una URL o una
ruta—. El CLI queda para automatizar, no para el uso diario.

**La web hace ya todo lo que hace el CLI.** En un escaneo web el formulario
ofrece también:

- **Sesión**, en los tres modos: formulario (URL de acceso, usuario y
  contraseña; vale con Keycloak, ADFS y cualquier proveedor que acabe en un
  formulario), cabecera o JWT, y cookies pegadas a mano —la salida para el
  segundo factor y para Kerberos, que no se pueden automatizar—. Sin sesión solo
  se ve lo que la aplicación muestra sin autenticar, que en una aplicación
  interna es la menor parte.
- **Roles a comparar**, uno por fila. Con dos o más se activa el análisis de
  control de acceso; con uno la petición se acepta y te avisa de que no hay
  comparación posible.
- **Aislar la red**, equivalente a `--sandbox`. La casilla sale desactivada
  cuando el equipo no puede aislar, y dice qué falta.

Las credenciales viajan del navegador al servidor y se usan en memoria durante
el escaneo. **No se guardan en la base, no vuelven por la API y no aparecen en
el informe**: de la sesión queda registrado el modo —«formulario»,
«cabecera»—, el nombre de cada rol y de cada cookie, nunca un valor.

El panel dice con qué sesión se hizo cada escaneo y cómo se comprobó —qué
respondió la aplicación con ella y sin ella—, y si se perdió a mitad. Una
herramienta que corre con la sesión caducada recorre la aplicación como
anónima sin saberlo, así que se comprueba antes y después de cada una: si caducó
se vuelve a entrar, y si no se pudo, el informe lo dice.

Para nuclei y wapiti la sesión va en ficheros que solo lee tu usuario y que se
borran en cuanto la herramienta termina. La excepción es un token en cabecera
para wapiti, que solo lo admite en la línea de órdenes: mientras corre, otro
usuario del equipo podría verlo con `ps`.

### Aislar la red desde la web

El aislamiento mete el escaneo en un namespace de red que solo tiene ruta hacia
las direcciones del alcance, con el DNS congelado. Por línea de órdenes eso se
consigue relanzando el comando dentro del namespace; **el servidor web no puede
hacer eso**, porque dentro del namespace `127.0.0.1` es otro loopback y tu
navegador perdería la interfaz en el mismo instante en que empezara el escaneo.

Así que el escaneo aislado corre en un **proceso hijo** dentro del namespace,
que cuenta su avance por líneas JSON: ves el mismo progreso en vivo y el
servidor se queda fuera, alcanzable. El trabajo le llega por la entrada
estándar y no por argumentos, porque lleva contraseñas y `ps` enseña el argv de
cualquier proceso a cualquier usuario del equipo.

Si no se puede aislar, el escaneo **falla**. No se degrada a «igual pero sin
aislar»: quien marca esa casilla está diciendo que no quiere que el tráfico
pueda salir, y cumplirlo a medias en silencio sería peor que no cumplirlo.

---

### Lo que no se puede perder

Crux no reduce hallazgos en silencio. Colapsar dos avisos de la misma
comprobación es correcto; que la cuenta no cuadre, no. Cada escaneo guarda de
cuántos hallazgos partió y en qué se quedaron —cuántos se colapsaron por
huella, cuántos absorbió otro mejor explicado, cuántos se guardaron—, y el
panel lo enseña. Si la resta no cuadra, o si un hallazgo absorbido desaparece
sin que el que debía cubrirlo esté en el informe, el escaneo emite un hallazgo
propio de severidad alta diciendo que **el informe está incompleto**.

Lo mismo con las herramientas: si una corre y su salida no se puede leer —no
dejó el fichero, el JSON está truncado, cambió de formato entre versiones—,
eso es un hallazgo, no un cero. «No encontró nada» y «no se pudo leer lo que
encontró» no se parecen en nada cuando alguien firma el informe.

Y el grafo de superficie devuelve a la vez cuántos hallazgos tiene y cuántos
dibuja: si no coinciden, lo dice en rojo en la propia vista.

---

### Dónde se guarda todo

En disco, en el equipo del analista, siguiendo XDG. **No en el navegador**:
limpiar la sesión, cambiar de navegador o borrar cookies no borra ningún
escaneo.

| Qué | Dónde |
|---|---|
| Base de datos (escaneos, hallazgos, triaje) | `~/.local/share/crux/crux.db` |
| Salidas crudas de cada herramienta | `~/.local/share/crux/runs/` |
| Informes generados | `~/.local/share/crux/reports/` |

La propia interfaz lo dice, con el tamaño de cada pieza: está al final de la
vista de escaneos, en «Dónde se guardan».

El esquema se actualiza solo al arrancar, y únicamente añadiendo columnas: es
el único cambio que no puede perder datos de nadie. Un cambio que no quepa ahí
necesita decisión humana, no automatismo.

---

## Cuando algo no sale como esperas

**El escaneo tarda muchísimo.** Comprueba el perfil: `safe-active` va a 20
peticiones por segundo a propósito. Si acabas de ampliar el alcance, nuclei
lanza su catálogo acotado por la huella detectada; con varios hosts se
multiplica.

**`crux doctor` dice que faltan plantillas de nuclei.** Si las descargaste a
mano, revisa que **no** pasaras `-duc`: ese flag desactiva la comprobación de
actualizaciones del binario *y de las plantillas*, así que con él la descarga
no hace nada y el directorio queda vacío **sin dar error**. La orden correcta
está en `install/bootstrap.sh`.

**`crux scan code` no encuentra nada en un proyecto npm o PHP.** Mira si hay
`package-lock.json` o `composer.lock`. Sin fichero de bloqueo, el análisis de
dependencias no ve nada — y te lo dice con un hallazgo propio.

**El análisis de código ignora parte del repositorio.** semgrep omite por su
cuenta `tests`, `test`, `node_modules`, `vendor`, `build`, `dist` y `.venv`. Es
razonable para patrones de inyección, y el escaneo emite un aviso con lo que
quedó fuera. Si ahí hay código que sí se despliega, apunta directamente a él.
Los secretos sí se buscan en todo el árbol.

**El aislamiento se niega a escanear mi aplicación local.** Dentro de un
namespace de red, `127.0.0.1` es el loopback de ese namespace, no el del
equipo. Escanea sin aislar, o haz que la aplicación escuche en una dirección
encaminable. El escaneo se para antes de montar nada y te lo dice: un resultado
vacío se leería como que la aplicación no responde.

**La casilla de aislar la red sale desactivada.** El aislamiento necesita `ip`,
`nft` y privilegios. Si no eres root, hace falta `sudo` sin contraseña para
`ip` y `nft`; la propia casilla dice cuál de las tres cosas falta. Sin
aislamiento el escaneo funciona igual y el egress cero se sigue comprobando
herramienta por herramienta: lo que no se puede es imponerlo.

**El escaneo se para con «No se pudo entrar».** El mensaje dice por qué; los
casos habituales:

- *El acceso lleva a un host que no está en el alcance*: es tu proveedor de
  identidad y la aplicación salta a él con JavaScript. Decláralo en «Proveedor
  de identidad» (web) o con `--idp` (CLI).
- *El proveedor pide un segundo factor* o *exige cambiar la contraseña*: no se
  puede completar sin una persona. Entra tú una vez, o pide un usuario de
  auditoría sin segundo factor; si no es posible, autentícate en tu navegador y
  pega la sesión en el modo «Cookies».
- *No apareció ningún formulario de acceso*: los campos tienen nombres poco
  habituales. Pásalos en «El acceso no es el habitual» (web) o con
  `--selector-usuario` y `--selector-clave` (CLI).
- *La sesión no funciona fuera del navegador*: la aplicación guarda el token
  donde no se puede reutilizar. Cópialo de las herramientas de desarrollo de tu
  navegador y usa el modo «Cabecera».

---

## Por qué está hecho así

`docs/decisiones.md` recoge 51 decisiones que no se deducen leyendo el código,
cada una con su motivo y con la evidencia que la respalda. Están ahí para que
no se discutan desde cero, y para que quien no esté de acuerdo sepa
exactamente qué está cambiando.

Algunas que conviene leer antes de tocar nada:

- **§1** El alcance se confina a lo declarado, no a «cualquier red privada».
- **§15** No se marca como corregido lo que no se ha vuelto a comprobar.
- **§18** La rampa de severidad es indistinguible bajo protanopía, así que el
  color es refuerzo redundante y toda marca lleva su etiqueta.
- **§19** El control de acceso solo afirma tres cosas y calla en el resto.
- **§28** El sandbox envuelve el proceso entero, no cada herramienta.

---

## Desarrollo

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest tests/ -q          # 240 tests, ~5 min
```

La suite lanza escaneos reales contra una aplicación deliberadamente vulnerable
(`tests/fixtures/vulnapp`) y analiza un repositorio con fallos plantados
(`tests/fixtures/vulncode`). Para ejecutarla:

```bash
.venv/bin/python -m tests.fixtures.vulnapp    # en otra terminal
```

Los 81 tests que necesitan ese objetivo llevan la marca `necesita_objetivo` y
**fallan en rojo** si no responde, en lugar de pasar con cero hallazgos. Los
otros 179 no lo necesitan:

```bash
.venv/bin/python -m pytest -m 'not necesita_objetivo' -q
```

La interfaz solo se compila en la máquina de build:

```bash
cd frontend && corepack pnpm install && corepack pnpm build
```
