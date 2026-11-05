# Decisiones

Registro de las decisiones que no se deducen leyendo el código, con el motivo y
la evidencia que las respalda. Existe para que no se vuelvan a discutir desde
cero, y para que quien no esté de acuerdo sepa exactamente qué está cambiando.

---

## 1. El alcance se confina a lo declarado, no a "cualquier red privada"

**Decisión.** `Scope.allows_ip` solo admite las direcciones de los objetivos
declarados y las de `extra_hosts`. Ser una IP RFC1918 no basta.

**Motivo.** Autorizar una auditoría de `192.168.50.0/24` no autoriza a tocar
`192.168.51.1`, que puede ser la subred de otro equipo. La lectura permisiva
("mientras no salga a internet, vale") convierte una autorización acotada en una
barra libre dentro de la organización.

**Escape.** `allow_internal=True` recupera la lectura permisiva, de forma
explícita. `extra_hosts` cubre el caso legítimo: un IdP o un CDN internos de los
que la aplicación depende.

**Cómo se detectó.** Un test al escribirlo, antes de que llegara a producción.

---

## 2. Las redes internas se enumeran a mano, no con `ipaddress.is_private`

**Decisión.** `INTERNAL_NETWORKS` lista los CIDR explícitamente.

**Motivo.** La semántica de `is_private` ha cambiado entre versiones de Python
—el espacio compartido de RFC6598 (100.64.0.0/10) entre ellas—. Para una
herramienta de seguridad, una lista auditable vale más que la comodidad de
delegar en una propiedad cuyo significado puede moverse bajo los pies.

---

## 3. El DNS se congela al arrancar el escaneo

**Decisión.** Los nombres se resuelven una vez, al construir el alcance. Toda
comprobación posterior usa esa foto; un nombre no congelado no se permite.

**Motivo.** Cierra el DNS rebinding durante el escaneo, e impide que una
herramienta siga un redirect hacia un host que resuelve fuera.

---

## 4. Flags anti-telemetría obligatorios, validados antes de ejecutar

**Decisión.** Cada adaptador declara `EGRESS_FLAGS`; el `runner` valida el argv
**antes** de resolver el binario y se niega a ejecutar si falta algo.

**Motivo.** Varias herramientas salen a internet por defecto, y no es evidente:

| Herramienta | Qué hace sin que se lo pidas |
|---|---|
| `nuclei` | Usa el Interactsh **público** (`oast.pro`, `oast.live`…) para OAST, y comprueba actualizaciones al arrancar |
| `wapiti` | Envía un informe automático cuando un módulo falla |
| `nikto` | Consulta actualizaciones al arrancar |
| `semgrep` | Envía métricas de uso |

La validación va antes de resolver el binario a propósito: así una violación de
política falla igual esté la herramienta instalada o no, y los tests la detectan
en cualquier máquina.

---

## 5. El entorno del subproceso se construye por allowlist

**Decisión.** `clean_env()` parte de cero y añade lo imprescindible, en lugar de
heredar el entorno del usuario y quitar lo conocido.

**Motivo.** Deja fuera también las variables que todavía no conocemos. Si una
herramienta estuviera comprometida, no encuentra `AWS_*`, `GITHUB_TOKEN`,
`SSH_AUTH_SOCK` ni nada que exfiltrar. Es el mismo razonamiento que se aplica al
build del frontend.

---

## 6. Selenium en lugar de Playwright

**Decisión.** El crawler autenticado usa Selenium con el `chromium-driver` del
sistema.

**Motivo.** El paquete de Playwright en Kali no trae driver propio: depende de
`/usr/bin/node`. Eso metería Node en el equipo de cada analista, que es justo la
superficie npm que este proyecto evita. Con `chromium-driver` —ya instalado— no
hace falta Node en ninguna máquina salvo la de build.

**Beneficio inesperado.** El Performance API del navegador devuelve los endpoints
que el bundle JS pide en tiempo de ejecución, sin parsear JavaScript.

---

## 7. La etiqueta de severidad de la herramienta manda sobre el CVSS

**Decisión.** Del vector CVSS se deriva la puntuación, pero no se recalifica la
severidad.

**Motivo.** Muchas plantillas de nuclei llevan un CVSS genérico junto a una
severidad `info`. Ascenderlas automáticamente inundaría la cola de triaje con
hallazgos "medios" que nadie pidió. La puntuación se conserva porque sirve para
ordenar y para el informe.

---

## 8. Comprobaciones por ruta y comprobaciones por sitio

**Decisión.** Las cabeceras de seguridad, las versiones declaradas, el transporte
y CORS describen el **origen**; las cookies, el listado de directorio y el
contenido sensible describen la **ruta**.

**Motivo.** Un escaneo de cinco URLs producía catorce hallazgos, de los cuales
siete eran el mismo problema repetido. Agrupando por origen pasan a ser siete
distintos. La regla práctica: si la corrección es una sola, el hallazgo es uno.

---

## 9. Identidad canónica compartida entre herramientas

**Decisión.** `equivalence.py` declara qué comprobaciones de herramientas
distintas son la misma, y si se agrupan o conservan su discriminante.

**Motivo.** El fingerprint incluía `origen:check_id`, de modo que nuclei y un
módulo propio detectando lo mismo **nunca** colapsaban — lo contrario de lo que
el fingerprint promete. En el primer escaneo real, nuclei reportó
`http-missing-security-headers` diez veces, una por cabecera, junto a nuestro
hallazgo único ya agrupado.

Al colapsar gana el origen de mayor rango: nuestros módulos agrupan, razonan la
severidad y escriben la corrección; una herramienta solo dispara.

---

## 10. A nuclei se le pasan orígenes, no cada ruta descubierta

**Decisión.** Salvo en perfil agresivo, el adaptador le pasa los orígenes.

**Motivo.** Sus plantillas construyen su propia ruta desde `{{BaseURL}}`. Darle
las quince rutas de siembra multiplicaba por quince el trabajo sin encontrar nada
más: 46.000 ejecuciones para cubrir lo mismo que 3.081. El escaneo pasó de
cuarenta minutos a seis.

**Excepción.** El fuzzing DAST inyecta en parámetros concretos, así que en perfil
agresivo sí recibe las rutas completas.

---

## 11. El catálogo de nuclei se acota con la huella del probador

**Decisión.** Las etiquetas de nuclei se derivan de la tecnología que detectó
nuestro propio probador, más un conjunto base.

**Motivo.** Sin selección se lanzan 13.687 plantillas, con las de WordPress,
Cisco y Oracle incluidas, contra una aplicación que no es ninguna de las tres.
Con `-pt http` y las etiquetas por huella, 3.081. **Ésta es la razón de tener
probador propio**, no solo el control del egress.

---

## 12. Un tema oscuro en pantalla, uno claro al imprimir

**Decisión.** `tokens.css` define dos superficies con la misma identidad.

**Motivo.** La interfaz es oscura por compromiso —es una herramienta de sesión
larga—, pero el informe se imprime, y un PDF oscuro gasta tóner y se lee mal en
papel. Cambian los valores de superficie y se reajustan las severidades para
contrastar sobre blanco; la escala tipográfica y el ritmo no cambian.

---

## 13. Los títulos de las plantillas de nuclei se dejan en inglés

**Decisión.** No se traducen. El chip de origen (`nuclei:<id>`) deja claro de
quién es cada hallazgo.

**Motivo.** Traducirlos obliga a mantener un diccionario de textos ajenos que
cambia con cada actualización de plantillas, y atribuye a Crux una redacción que
no es suya. El informe queda con dos idiomas, y es el precio honesto.

---

## 14. El secreto completo va en la evidencia, no en la descripción

**Decisión.** La comprobación de contenido sensible muestra el valor ofuscado en
el titular y la descripción; el valor íntegro vive en la evidencia.

**Motivo.** El informe se adjunta a tickets y circula por correo. Quien lee el
resumen no necesita la contraseña; quien reproduce el hallazgo, sí.

---

## 15. "Corregido" solo si la comprobación se volvió a ejecutar

**Decisión.** El barrido que marca hallazgos como corregidos exige que el origen
—y, en nuestros propios módulos, la comprobación concreta— se haya ejecutado en
este escaneo. `FindingState` guarda `source` y `check_id` para poder decidirlo.

**Motivo.** Un hallazgo desaparece por dos motivos opuestos: porque se arregló, o
porque esta vez no se buscó. Un cambio de perfil, una herramienta ausente o un
adaptador que falla producen lo segundo. Confundirlos significa decirle a un
equipo que una vulnerabilidad está resuelta sin haberla comprobado, que es peor
que no decir nada.

**Cómo se detectó.** Verificando el ciclo de triaje: al reescanear en perfil
pasivo, el hallazgo de CORS —cuyo sondeo el perfil pasivo no autoriza—
desaparecía y quedaba marcado como corregido.

**Límite conocido.** Para una herramienta externa la cobertura solo se conoce a
nivel de origen: nuclei no informa de qué plantillas descartó el filtro de
etiquetas. Si el filtro cambia entre escaneos, un hallazgo suyo puede marcarse
corregido sin haberse vuelto a probar. Documentado antes que silenciado.

---

## 16. Las columnas de enum se tipan como enum

**Decisión.** `models.py` usa `SAEnum(..., native_enum=False)` en lugar de
`String`.

**Motivo.** Anotar la columna como `Mapped[MiEnum]` sobre un `String` no
convierte nada al leer: vuelve un `str`. Con `StrEnum` las comparaciones por
`==` siguen funcionando, así que el fallo no se nota —hasta que alguien escribe
`is` y la condición resulta silenciosamente falsa.

---

## 17. La configuración de pnpm vive en `pnpm-workspace.yaml`, y hay que verificarla

**Decisión.** `minimumReleaseAge`, `strictDepBuilds` y `allowBuilds` van en
`frontend/pnpm-workspace.yaml`. No hay `.npmrc`.

**Motivo.** Desde pnpm 12, `.npmrc` solo se lee para auth, registro, TLS y proxy,
y el campo `pnpm` de `package.json` ya no se lee en absoluto. Ponerlos en el
sitio equivocado **no da error**: se ignoran en silencio.

Esto no es trivia de configuración. El primer intento de este proyecto tenía un
`.npmrc` con los tres controles y una instalación que pasaba limpia — y los
controles estaban inertes. El proyecto habría afirmado tener defensas de cadena
de suministro que no existían, que es peor que no tenerlas, porque nadie vuelve
a mirar.

**Cómo se verifica.** Con un control negativo, no leyendo la configuración: se
pide a propósito una versión publicada hace un día y la instalación debe
fallar con `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION`. Si pasa, el control no está
activo.

**Nota sobre `allowBuilds`.** Cada entrada es una decisión tomada a mano, y un
`false` es tan explícito como un `true`: declara que el script se revisó y se
omite. `vue-demi: false` es el único caso hoy.

---

## 18. La rampa de severidad falla la separación para daltonismo, y la mitigación es la etiqueta

**Decisión.** Se conserva la rampa rojo → naranja → amarillo → azul → gris, y
**toda marca de severidad va siempre acompañada de su etiqueta**: en la lista, en
el panel, en la leyenda del informe y en cada segmento de las gráficas. Nunca
color a solas.

**Motivo.** Medido con el validador de paletas, no estimado a ojo:

| par | visión normal | protanopía |
|---|---|---|
| media ↔ alta (pantalla) | ΔE 12,8 | ΔE 8,0 |
| media ↔ alta (impresión) | ΔE 8,6 | **ΔE 1,0** |

Un ΔE de 1,0 es indistinguible. Y no hay color que lo arregle: quien tiene
protanopía no separa rojo de naranja de amarillo, que es precisamente la rampa.
El mejor candidato probado llegaba a 3,4 y era verde oliva, que además rompe la
metáfora —el verde lee como "bien"—.

Así que el color de severidad es **refuerzo redundante**, nunca el portador de la
información. Quien no distinga los tonos lee exactamente lo mismo.

**Lo que sí se corrigió.** `--cx-info` pasó de `#6C778E` a `#6E6E74`: el tono
anterior tiraba a azul y quedaba a ΔE 11,1 de `--cx-low`, por debajo del umbral
de 15 para visión normal. En una barra apilada los dos segmentos se confundían
incluso viendo todos los colores.

**Lo que parece un fallo y no lo es.** El validador marca `info` por "leerse
gris" y los tres primeros niveles por salirse de la banda de luminosidad. Ambas
cosas son deliberadas en una escala de estado: info debe recular y lo grave debe
saltar. Esos avisos son de paletas categóricas, donde todas las series pesan lo
mismo.

---

## 19. El módulo de control de acceso sólo afirma tres cosas

**Decisión.** `authz` reporta falta de autenticación, falta de autorización en
rutas que declaran privilegio en su propio nombre (`/admin`, `/export`,
`/gestion`…), e IDOR con identificadores que **otra sesión mostró como suyos**.
Fuera de esos tres casos, calla.

**Motivo.** Nadie le dice a la herramienta cuál es la política de acceso
prevista, así que «esta sesión no debería ver esto» no se puede deducir en
general. Lo que sí es afirmable con rigor: si el desarrollador llamó `admin` a
la ruta, ésa es la política escrita por él; si un recurso aparece en el listado
de otro usuario, es de otro usuario.

Un hallazgo de control de acceso que resulta ser el comportamiento previsto
quema la confianza en el informe entero. Vale más callar de más.

**Dos reglas que hubo que afinar al probarlas.**

La primera versión suprimía toda ruta a la que el crawler anónimo llegase
siguiendo enlaces, por considerarla pública por diseño. Eso hacía desaparecer
el hallazgo que importaba: que la portada enlace `/invoice/1001` no convierte
esa factura en información pública — enlazarla es parte del fallo. Ahora una
ruta con identificador de recurso nunca se da por pública.

Y lo que se lee sin sesión alguna no se reporta además como IDOR: es falta de
autenticación, que es más grave y la subsume. Duplicar la causa raíz infla la
cola de triaje sin añadir nada.

---

## 20. La comparación de respuestas recorta lo volátil, valores incluidos

**Decisión.** Antes de comparar dos respuestas se eliminan los campos CSRF con
su valor, los identificadores largos, las cadenas base64 y las marcas de tiempo.

**Motivo.** Casi toda aplicación mete un token distinto en cada respuesta. La
primera versión del patrón borraba el *nombre* del campo pero no el *valor*, y
dos respuestas idénticas salían al 0,80 de similitud, por debajo del umbral.
Con protección CSRF —es decir, en casi cualquier aplicación real— el módulo no
habría detectado nunca nada. Lo encontró un test escrito para ese caso.

---

## 21. La prueba de `alg:none` se compara contra un token inválido, no contra el legítimo

**Decisión.** Para demostrar que un servidor acepta JWT sin firmar se envían
dos peticiones: una con un token de firma inválida y otra con el token forjado.
El hallazgo requiere que la primera se rechace y la segunda se acepte.

**Motivo.** Comparar contra el token legítimo parece lo natural y falla en
silencio: si el token que tenemos ya no vale —ha caducado, es de otro entorno,
la aplicación lo rechaza por cualquier motivo—, las dos respuestas difieren y
la prueba se da por negativa aunque el servidor esté tragando tokens sin
firmar. Lo que hay que demostrar es que el servidor sabe distinguir un token
inválido pero no comprueba la firma del que no la lleva.

---

## 22. La redirección abierta se prueba con un dominio reservado y sin seguirla

**Decisión.** El sondeo sustituye el parámetro de destino por una URL en
`.invalid` (reservado por RFC 2606) y lee la cabecera `Location`. No sigue la
redirección.

**Motivo.** Hay que demostrar que la aplicación redirige a cualquier sitio sin
salir del alcance ni para comprobarlo. Un dominio `.invalid` no resuelve, no
existe y no puede pertenecer a nadie, así que el sondeo no toca a terceros
aunque algo se escape. Y leer `Location` basta: seguir la redirección sería
exactamente lo que esta herramienta promete no hacer.

Sólo se prueban parámetros cuyo nombre indica destino (`next`, `redirect_uri`,
`return_to`…). Mandar una URL externa en todos los parámetros sería fuzzing a
ciegas y ruido para el objetivo.

---

## 23. semgrep omite directorios por su cuenta, y hay que decirlo

**Decisión.** Se respetan las exclusiones por defecto de semgrep en el análisis
estático, pero el escaneo emite un hallazgo informativo con lo que quedó fuera.

**Motivo.** Comprobado empíricamente con esta versión —no leído en la
documentación—, semgrep omite `.venv`, `build`, `dist`, `node_modules`, `test`,
`tests` y `vendor`. Para patrones de inyección la omisión es razonable: ese
código no se despliega. Pero callarla no lo es. Un informe que dice «sin
hallazgos» sobre un árbol que nadie miró es peor que no informar, y es
exactamente el mismo principio que el de no marcar nada como corregido sin
haberlo vuelto a comprobar (§15).

**Cómo se descubrió.** El fixture de código vivía en `tests/fixtures/`, así que
semgrep lo ignoraba entero y devolvía cero hallazgos sin un solo error. Un test
verde que no probaba nada.

**Consecuencia para los tests.** El fixture se copia fuera de `tests/` antes de
analizarlo, y hay un test que fija la lista comprobada.

---

## 24. Los secretos NO heredan esas exclusiones

**Decisión.** gitleaks analiza el árbol entero, directorios de pruebas
incluidos.

**Motivo.** La distinción entre código que se despliega y código que no vale
para un patrón de inyección, no para una contraseña. Un secreto en un fichero
de test es un secreto: la credencial existe, funciona y está en el
repositorio.

---

## 25. Un hallazgo por paquete vulnerable, no por CVE

**Decisión.** El adaptador de trivy agrupa las vulnerabilidades por
`(paquete, versión)`. La severidad y el vector CVSS los marca el peor CVE del
grupo, y la evidencia lista los demás.

**Motivo.** Una versión antigua de `jackson-databind` arrastra sesenta CVE. En
el fixture, el escaneo pasaba de 101 filas a 16 al agrupar. Sesenta filas para
una sola acción —actualizar el paquete— dejan el informe ilegible y entierran
los demás hallazgos. El paquete es la unidad de corrección; el CVE es el
detalle.

---

## 26. Sin fichero de bloqueo, el análisis de dependencias no ve nada

**Decisión.** Si hay un manifiesto (`package.json`, `composer.json`, `.csproj`,
`pyproject.toml`) sin su lockfile, se emite un hallazgo de severidad media.

**Motivo.** Comprobado: trivy no produce ningún hallazgo para npm, Composer ni
NuGet a partir del manifiesto solo. En el fixture, añadir los lockfiles hizo
pasar la cobertura de dos ecosistemas a cinco. Sin ese aviso, un informe limpio
sobre un proyecto npm parecería una buena noticia cuando en realidad nadie ha
mirado.

Versionar el lockfile tiene además su propio valor: es lo que hace reproducible
la instalación, que es la base de la postura de cadena de suministro del
proyecto (§17).

---

## 27. Un escaneo de código se registra sin alcance de red

**Decisión.** `run_code_scan` guarda `scope` como `{"ruta": …, "red": "no se
usa"}` en lugar de construir un `Scope` ficticio.

**Motivo.** El registro de auditoría existe para responder con precisión a qué
se tocó. Apuntar que el objetivo fue `127.0.0.1` cuando no se abrió un socket
sería falsearlo, aunque resultara cómodo para reutilizar el mismo tipo de dato.

---

## 28. El sandbox envuelve el proceso entero, no cada herramienta

**Decisión.** `--sandbox` monta el namespace de red y **vuelve a lanzar el
proceso completo dentro**, con una marca de entorno para no montarlo dos veces.

**Motivo.** Envolver el argv de cada herramienta externa parece lo natural y
deja fuera la mitad del tráfico: el probador, el crawler, los checks activos y
el comparador de roles hacen sus peticiones desde el propio proceso de Crux.
Un sandbox que contiene a nuclei mientras nuestro propio código sale por la red
del equipo no contiene nada.

**Detalle de implementación que costó.** `sudo` limpia el entorno, así que la
marca que evita la recursión tuvo que viajar dentro de la orden
(`sudo … env CRUX_EN_SANDBOX=1 …`) y no como variable del subproceso.

---

## 29. Dentro del sandbox, el DNS congelado se impone en lugar de vigilarse

**Decisión.** El namespace recibe su propio `/etc/hosts` con la resolución
congelada del alcance, y **ningún servidor de nombres**.

**Motivo.** Hasta aquí, el DNS congelado era una política que el código
respetaba. Dentro del namespace pasa a ser una propiedad del sistema: los
nombres del alcance resuelven a lo que resolvieron al empezar, y cualquier otro
nombre no resuelve a nada porque no hay a quién preguntar. El rebinding deja de
ser algo que vigilar.

**Verificado** con un control positivo y tres negativos: el objetivo declarado
se alcanza; internet, el DNS público y **una red interna no declarada**, no.
Ese último es el que convierte la decisión §1 de política en propiedad de la red.

---

## 30. Un objetivo en localhost es inalcanzable desde el sandbox, y se dice

**Decisión.** Si el alcance contiene objetivos que resuelven a loopback,
`--sandbox` avisa y se niega a ejecutar.

**Motivo.** Dentro de un namespace de red, `127.0.0.1` es el loopback de ese
namespace, no el del equipo. No es un fallo del aislamiento: es lo que
significa aislar. Pero un escaneo que devolviese cero hallazgos se leería como
que la aplicación no responde, y eso sí sería un error de interpretación con
consecuencias.

---

## 31. El diff distingue «corregido» de «no se volvió a mirar»

**Decisión.** `Scan.coverage` guarda qué orígenes y qué comprobaciones se
ejecutaron, y `crux diff` clasifica aparte los hallazgos que desaparecieron
sin haberse comprobado.

**Motivo.** Es la versión entre dos escaneos arbitrarios del mismo principio de
§15. Un hallazgo que estaba y ya no está puede haberse arreglado o puede no
haberse buscado —otro perfil, una herramienta ausente, un adaptador que
falló—, y confundirlos es decirle a un equipo que algo está resuelto sin
haberlo comprobado.

El comando sale con código distinto de cero si hay regresiones, para poder
encadenarlo en un trabajo programado.

---

## 32. El paquete de instalación se verifica instalándolo sin red

**Decisión.** `install/bundle.sh` produce un tarball autocontenido con el
código, el `dist` ya compilado, las ruedas de Python, las plantillas, las
reglas, la base de vulnerabilidades y un manifiesto con el SHA256 de cada
pieza.

**Motivo.** Decir que algo instala sin internet no vale nada sin demostrarlo.
La comprobación se hace extrayendo el paquete e instalándolo **dentro de un
namespace sin red**, y termina con `crux doctor --verify-supply-chain`
recalculando los hashes en destino.

**Dos cosas que sólo salieron al probarlo.** `tar` intentaba restaurar la
propiedad de los ficheros, lo que rompe la extracción si el uid de quien
empaquetó no existe en destino (`--no-same-owner`). Y pip montaba un entorno
aislado para construir y exigía setuptools, que no estaba en el wheelhouse
(`--no-build-isolation`, más las herramientas de construcción incluidas por si
acaso).

---

## 33. El escaneo aislado corre en un proceso hijo, no en el servidor

**Decisión.** Cuando se pide aislamiento desde la web, la cola monta el
namespace, lanza `python -m crux.core.worker` dentro de él y republica lo que
el hijo cuenta por líneas JSON. El servidor se queda fuera del namespace.

**Motivo.** El aislamiento no envuelve una herramienta: envuelve el proceso
entero, porque la mitad del tráfico de un escaneo la generan los módulos
propios —probador, crawler, authz— desde ese mismo proceso (§28). Por línea de
órdenes eso se resuelve relanzando el comando dentro del namespace. El servidor
web no puede: dentro del namespace `127.0.0.1` es otro loopback, así que el
navegador del analista perdería la interfaz en el instante en que empezara el
escaneo. Un hijo resuelve las dos cosas a la vez —el tráfico contenido, la
interfaz alcanzable— al precio de un límite de proceso que cruzar.

**El trabajo le llega por la entrada estándar, no por argumentos.** Lleva
contraseñas, y `ps` enseña el argv de cualquier proceso a cualquier usuario del
equipo.

**Y la salida se vacía línea a línea.** Sin el vaciado explícito, la salida de
un hijo se almacena en búfer de bloque: el progreso llegaría a la interfaz en
ráfagas de 4 KB, con la barra quieta todo el escaneo y un salto al final.

---

## 34. Pedir aislamiento y no poder darlo es un fallo, no un escaneo normal

**Decisión.** Si el equipo no puede aislar, la API responde 409 antes de
encolar; si el objetivo está en loopback, el trabajo falla con su propia fase
(`aislamiento-imposible`) sin haber montado nada ni escrito ningún escaneo.

**Motivo.** Quien marca esa casilla está diciendo que no quiere que el tráfico
pueda salir. Cumplirlo a medias y en silencio sería peor que no cumplirlo: el
informe saldría indistinguible de uno de verdad contenido. Es el mismo
principio que §15 y §31 aplicado al control en vez de al hallazgo —no decir que
algo se comprobó cuando no se comprobó—, y la razón de que sea 409 y no 400 es
que la petición es correcta: es el equipo el que no puede atenderla.

---

## 35. Las credenciales entran por la API y no vuelven a salir

**Decisión.** `POST /api/jobs` acepta credenciales y roles en el cuerpo. Se
construyen en memoria, se pasan al escaneo y no se persisten. Lo que la API
devuelve de una sesión es su **modo** —«formulario», «cabecera», «cookies»— y
el **nombre** de cada rol. Nunca el usuario, la contraseña, la cabecera ni la
cookie.

**Motivo.** Un `como_dict()` en `Credenciales` habría sido lo cómodo, y es
exactamente lo que acaba colándose en un registro o en una respuesta. La
conversión a diccionario vive en un solo sitio —`core/worker.py`, donde hace
falta para cruzar al proceso aislado— y la dataclase no la ofrece. Hay un test
que serializa el trabajo entero y comprueba que ninguna contraseña aparece en
el JSON.

**Un objeto de credenciales vacío se rechaza** en vez de interpretarse como
«sin autenticar»: es una petición a medio rellenar, y aceptarla escanearía sin
sesión sin decirlo. Y lo que es de red —credenciales, roles, aislamiento— se
rechaza en un análisis de código, porque aceptarlo haría creer que se autenticó
o que se aisló algo donde no se usa la red en ningún momento.


---

## 36. La superficie de ataque es lo que está expuesto, no lo que está roto

**Decisión.** El escaneo guarda en `Scan.surface` lo que vio —URLs sondeadas
con su estado, título, servidor y tecnologías; endpoints del recorrido con sus
métodos y parámetros— y el grafo las dibuja aunque no tengan ningún hallazgo,
huecas para distinguirlas.

**Motivo.** El grafo se reconstruía solo a partir de los hallazgos, así que una
ruta sin fallos no existía en él: la vista se llamaba «superficie de ataque» y
enseñaba el árbol de los fallos. En el fixture pasó de 8 rutas a 29, de las
cuales 21 no tienen ningún hallazgo. Esas 21 son justamente las que nadie ha
mirado, que es una pregunta que un analista se hace.

**Cada nodo lleva su detalle dentro**, para que pulsarlo no cueste otra vuelta
al servidor; y un escaneo guardado antes de esto lo dice en vez de aparentar
que no se encontró nada.

---

## 37. El esquema se migra solo, y solo añadiendo columnas

**Decisión.** `init_db` compara las tablas existentes con el modelo y añade las
columnas que falten, con su valor por defecto. Nunca quita ni cambia tipos.

**Motivo.** Un fichero SQLite por analista no justifica Alembic, pero sin nada
una base creada con una versión anterior arranca bien y revienta al leer la
primera fila. Añadir es el único cambio de esquema que no puede perder datos de
nadie; lo demás necesita decisión humana.

**Lo que costó una prueba.** SQLAlchemy envuelve los valores por defecto
invocables en una función que recibe el contexto de ejecución, así que llamarla
sin argumentos lanza `TypeError`: las columnas JSON se añadían **sin** DEFAULT
y las filas que ya existían recibían NULL donde el código espera un
diccionario. Hay un test que inserta una fila, quita la columna y comprueba que
vuelve con `{}`.

---

## 38. Un juicio de triaje se puede deshacer

**Decisión.** Pulsar el estado que un hallazgo ya tiene lo devuelve a «sin
triar». Antes el botón activo salía desactivado.

**Motivo.** Marcar algo por error es más fácil de cometer que de detectar, y no
había forma de corregirlo desde la interfaz: un falso positivo marcado por
equivocación se arrastraba a todos los escaneos siguientes, porque el juicio
persiste por huella. Volver a «new» es un cambio de estado como cualquier otro.

---

## 39. Borrar un escaneo no borra el juicio sobre sus hallazgos

**Decisión.** Al borrar escaneos se van sus hallazgos, su evidencia, sus tareas
y sus salidas en disco. Los `FindingState` del proyecto se conservan; solo se
limpian los que se quedan sin ningún hallazgo al que referirse.

**Motivo.** El triaje vive por huella y entre escaneos (§15): si se borrara con
el escaneo, limpiar la lista haría que cada falso positivo ya descartado
volviera a aparecer como nuevo en el siguiente. Y al revés, un juicio sin
ningún hallazgo detrás ya no le sirve a nadie y ensucia el recuento del panel
para siempre.

---

## 40. El panel cuenta lo que cambia una decisión

**Decisión.** El panel enseña lo pendiente de triar, lo que cambió desde el
escaneo anterior, la comprobación que más se repite, dónde se concentran los
hallazgos, qué herramienta los encontró, qué lleva más tiempo abierto y qué
tareas fallaron o se omitieron.

**Motivo.** El criterio es que una cifra merece sitio si cambia lo que harías a
continuación. «Cuántos hallazgos hay» no lo hace —siempre hay—; «cuántos quedan
sin mirar» dice cuánto trabajo queda, «lo que más se repite» por dónde empezar
para cerrar varios de una vez, y «qué no se ejecutó» evita leer un adaptador
que falló como que no había nada que encontrar.

---

## 41. Un `ResizeObserver` puede dejar un lienzo en blanco

**Decisión.** El observador del grafo ignora su primera medida, compara el
tamaño antes de actuar y espera 250 ms antes de llamar a `resize()`.

**Motivo.** `observe()` dispara el callback de inmediato, y `cytoscape.resize()`
recrea los lienzos —los deja en blanco— mientras el dibujado inicial está en
marcha. El resultado era un grafo que existía de verdad: los nodos tenían
posiciones correctas, estilos resueltos y `visible() === true`, y la pantalla
estaba completamente vacía. Que el objeto esté bien no significa que se vea; la
comprobación que lo detectó fue mirar los píxeles de la captura, no el estado
del objeto.

**El mismo observador, por el otro lado.** Los lienzos van en posición absoluta
y, durante un instante tras cambiar de tamaño, son más anchos que su
contenedor. Sin recorte eso le sacaba una barra de desplazamiento a la página,
que estrechaba el contenedor, que disparaba otro reajuste: las barras aparecían
y desaparecían sin parar. La cura es `overflow-hidden` en el armazón de la
aplicación y en el lienzo —ninguna vista debe poder sacarle barras a la página
entera—, no afinar más el observador.


---

## 42. Reducir está permitido; perder, no

**Decisión.** Todo tramo que quita hallazgos lleva la cuenta y la justifica. El
escaneo guarda en `Scan.coverage["conteo"]` cuántos produjeron las fases,
cuántos se colapsaron por huella, cuántos absorbió otro mejor explicado y
cuántos quedaron guardados; si la resta no cuadra, o si un absorbido se fue sin
que el hallazgo que debía cubrirlo esté en el informe, se guarda un hallazgo de
severidad alta que lo dice. El grafo de superficie devuelve a la vez cuántos
hallazgos tiene y cuántos dibuja, y la interfaz los compara.

**Motivo.** Un usuario encontró que el grafo decía trece hallazgos y pintaba
once, y los dos que faltaban eran la SQLi crítica y el XSS alto. El defecto no
es de interfaz: un informe que enseña de menos sin avisar da por limpio lo que
nadie miró, y eso en una auditoría se paga fuera, tarde y con el nombre de
quien firmó. La crítica del usuario fue exacta: «no te tendré ahí para
corregirlo».

**El mismo patrón estaba en los cinco adaptadores.** Si la herramienta corría
pero su salida no se podía leer —fichero ausente, JSON truncado, formato
cambiado entre versiones—, el adaptador hacía `return` y la tarea quedaba en
«hecha · 0 hallazgos». Ahora eso es un hallazgo sobre el propio escaneo, de
severidad media, con los bytes que no se pudieron interpretar y qué hacer. Un
informe vacío **sí** se acepta en silencio: puede significar de verdad que no
hay nada, y un aviso que salta siempre deja de leerse.

**La primera versión de la comprobación no valía.** Medía `producidos −
colapsados − absorbidos − guardados` y daba cero siempre, porque definía
«absorbidos» como «los que desaparecieron»: una baja indebida también se
cuenta como baja y la resta sigue cuadrando. La comprobación que sí vale exige
que el hallazgo que supuestamente cubre a cada absorbido **siga en el
informe**. Lo que lo destapó fue un test que simulaba la pérdida y pasaba en
verde.

## 43. El nombre es Crux, y el prefijo corto es `cx`

`audex` era un acrónimo sin significado, de los que hay que explicar cada vez.
*Crux* —del latín *crux*, la misma raíz de *crucial*— es el punto decisivo: en
escalada, el paso que decide la vía. Es lo que hace la herramienta: de
cincuenta hallazgos, señalar los dos que importan.

Se descartó **Faraday** (plataforma de pentest ya existente), **Arachne**
(choca con Arachni) y **Beacon** (es el implante de Cobalt Strike: mala lectura
en una herramienta que se instala en entornos corporativos). La única colisión
que le queda a Crux es **CRUX Linux**, una distribución de código fuente: no es
una herramienta de seguridad, no está en Kali y no ocupa ninguna orden.

El cambio alcanza seis sitios, y conviene que se mantengan en paralelo:

| qué | antes | ahora |
|---|---|---|
| paquete y orden | `audex` | `crux` |
| datos locales | `~/.local/share/audex` | `~/.local/share/crux` |
| señal de aislamiento | `AUDEX_EN_SANDBOX` | `CRUX_EN_SANDBOX` |
| tabla de nftables | `audex_sandbox` | `crux_sandbox` |
| namespaces del sandbox | `axweb<id>` | `cxweb<id>` |
| tokens de diseño | `--ax-*` | `--cx-*` |

**Lo que no se reescribió: la evidencia ya grabada.** Los escaneos anteriores
guardan en su evidencia el User-Agent que de verdad se envió (`audex/0.1`) y
los marcadores de sonda con el nombre viejo. Cambiarlos sería falsear lo que
pasó por el cable. Sí se reetiquetó `tasks.tool`, que es metadato del programa
y no una observación del objetivo.

## 44. La interfaz servía cualquier fichero del equipo

Auto-analizando Crux con Crux apareció esto:

```
GET http://127.0.0.1:8777///////../../../etc/passwd  →  200, /etc/passwd
```

La ruta comodín que devuelve la SPA hacía `DIST / ruta` y preguntaba
`is_file()`. Con `ruta = "../../../etc/passwd"` eso apunta fuera del
directorio, el fichero existe, y `FileResponse` lo servía tan tranquilo.
Cualquier página web abierta en el navegador del analista podía leer
`~/.local/share/crux/crux.db` —con todos los hallazgos de sus clientes— o las
claves de `~/.ssh`, porque el servidor no exige autenticación por diseño.

**La corrección no filtra patrones.** La tentación es rechazar `..`, y es la
defensa que siempre se queda corta: viene `%2e%2e%2f`, viene `....//`, viene
la codificación doble. Lo que se hace es resolver la ruta y comprobar que el
resultado sigue cayendo dentro del directorio permitido:

```python
raiz = DIST.resolve()
candidato = (raiz / ruta).resolve()
if not candidato.is_relative_to(raiz) or not candidato.is_file():
    return None
```

Resolver también sigue los enlaces simbólicos, así que un enlace dentro de
`dist` que apunte fuera tampoco cuela. Y como Starlette entrega la ruta ya
descodificada, todas las codificaciones desembocan en la misma comprobación.

**Lo que esto dice del resto.** Se revisaron los demás puntos donde la API
toca disco: el informe valida el formato contra una lista blanca y recibe el
identificador como entero, y `/assets` lo sirve `StaticFiles`, que ya hace
esta comprobación. Era el único sitio, y lo era porque es el único que
construía una ruta a partir de texto del usuario sin que nadie lo validara.

**Que esto lo encontrara la propia herramienta no es anécdota.** Es el
argumento de que la invariante de §42 no basta: el escaneo puede ser perfecto
y el producto seguir teniendo el fallo que busca en los demás.
`tests/test_travesia_de_rutas.py` prueba ocho vectores contra la aplicación ASGI
directamente, porque httpx y curl normalizan la ruta antes de enviarla y un
cliente educado no puede reproducir el vector original.
