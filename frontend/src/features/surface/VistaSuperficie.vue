<script setup lang="ts">
/**
 * Grafo de superficie de ataque: host → servicio → ruta → hallazgo.
 *
 * Qué se dibuja: **todo lo que el escaneo vio**, no solo lo que salió mal. Las
 * rutas sondeadas y los endpoints del recorrido entran aunque no tengan ningún
 * hallazgo, porque una superficie de ataque es lo que está expuesto. Una ruta
 * sin hallazgos es parte de la superficie —y a veces la parte interesante: la
 * que nadie ha mirado—. Se dibujan huecas, para distinguirlas de un vistazo.
 *
 * La severidad peor se propaga hacia arriba desde el backend, así que un host
 * se colorea por lo más grave que cuelga de él: "¿qué máquina está peor?" se
 * responde sin hacer un solo clic.
 *
 * Se usa el layout `breadthfirst` que trae Cytoscape en lugar de fcose: la
 * estructura ya es jerárquica, el resultado se lee mejor, y evita una
 * dependencia más en un proyecto que las cuenta.
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import Severidad from '@/components/Severidad.vue'
import { useSesion } from '@/stores/sesion'
import type { NodoDeSuperficie, Superficie } from '@/api/types'

const sesion = useSesion()
const router = useRouter()
const lienzo = ref<HTMLElement | null>(null)
const cy = shallowRef<any>(null)
const cargando = ref(false)
const fallo = ref<string | null>(null)
const datos = ref<Superficie | null>(null)
const nodo = ref<NodoDeSuperficie['data'] | null>(null)
let observador: ResizeObserver | null = null

// ── Filtros ────────────────────────────────────────────────────────────────
const minimo = ref(0)                 // índice en ORDEN_SEVERIDAD, 0 = todo
const soloConHallazgos = ref(false)
const busqueda = ref('')
const disposicion = ref<'radial' | 'arbol'>('radial')

/**
 * Con muchos nodos las etiquetas se pisan y el grafo deja de leerse.
 *
 * A partir de cierto tamaño solo se rotulan los hosts y los servicios —que son
 * pocos y orientan—, y el nombre de una ruta o un hallazgo aparece al pasar
 * por encima o al pulsarlo, donde además se ve todo lo demás. Un rótulo
 * ilegible no informa: estorba.
 */
const denso = computed(() => (visibles.value?.nodes.length ?? 0) > 60)

const SEV_ES: Record<string, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}
const RANGO: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
}
// Nombres de token, no valores: Cytoscape pinta sobre canvas y no resuelve
// var(--...), así que hay que darle el color ya calculado. Mantener aquí los
// nombres evita duplicar los hexadecimales fuera del sistema de diseño.
const TOKEN_SEV: Record<string, string> = {
  critical: '--cx-crit', high: '--cx-high', medium: '--cx-med',
  low: '--cx-low', info: '--cx-info',
}

function leer(nombre: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim()
}

const resumen = computed(() => datos.value?.resumen ?? null)

/**
 * Qué nodos pasan los filtros.
 *
 * Un nodo intermedio se queda si alguno de sus descendientes se queda: ocultar
 * el servicio y dejar colgando sus rutas rompería el árbol.
 */
const visibles = computed<Superficie | null>(() => {
  const d = datos.value
  if (!d) return null
  // ORDEN_SEVERIDAD va de crítica a info, pero los botones van de «todo» a
  // «crítica»: el índice del botón ES el umbral (0 = info = todo). Restarlo de
  // la longitud dejaba «todo» pidiendo crítica, así que la vista arrancaba
  // enseñando solo lo crítico y parecía que faltaban nodos.
  const umbral = minimo.value
  const texto = busqueda.value.trim().toLowerCase()

  const pasa = (n: NodoDeSuperficie) => {
    const x = n.data
    if (texto && !`${x.label} ${JSON.stringify(x.detalle ?? {})}`.toLowerCase()
      .includes(texto)) return false
    if (x.tipo === 'hallazgo') return RANGO[x.severidad ?? 'info'] >= umbral
    if (x.tipo === 'ruta' && soloConHallazgos.value && x.sin_hallazgos) return false
    return true
  }

  const supervivientes = new Set(d.nodes.filter(pasa).map((n) => n.data.id))
  // Un hallazgo filtrado no debe arrastrar a su ruta fuera, pero una ruta
  // filtrada sí se lleva sus hallazgos: el filtro de texto se aplica a cada
  // nivel y el árbol tiene que seguir siendo un árbol.
  const padres = new Map<string, string>()
  for (const e of d.edges) padres.set(e.data.target, e.data.source)
  for (const id of [...supervivientes]) {
    let p = padres.get(id)
    while (p) { supervivientes.add(p); p = padres.get(p) }
  }
  const sueltos = (id: string) => {
    const p = padres.get(id)
    return p === undefined || supervivientes.has(p)
  }
  const nodes = d.nodes.filter((n) => supervivientes.has(n.data.id) && sueltos(n.data.id))
  const vivos = new Set(nodes.map((n) => n.data.id))
  return {
    ...d,
    nodes,
    edges: d.edges.filter((e) => vivos.has(e.data.source) && vivos.has(e.data.target)),
  }
})

async function cargar() {
  const scanId = sesion.escaneoActual
  if (!scanId) return
  cargando.value = true
  fallo.value = null
  nodo.value = null
  try {
    datos.value = await api.superficie(scanId)
    await dibujar()
  } catch (e) {
    fallo.value = e instanceof Error ? e.message : String(e)
  } finally {
    cargando.value = false
  }
}

/**
 * Cuántas veces se ha pedido dibujar.
 *
 * Cada letra escrita en el filtro lanza un dibujado, y dibujar es asíncrono
 * —importar Cytoscape, esperar un fotograma—. Sin este testigo, dos dibujados
 * solapados acaban con el segundo destruyendo el grafo que creó el primero y
 * la pantalla en blanco, que es justo lo que pasaba al teclear deprisa.
 */
let generacion = 0
let temporizador: number | undefined
let reajuste: number | undefined

/** Redibuja, pero no en cada tecla. */
function redibujarPronto() {
  clearTimeout(temporizador)
  temporizador = window.setTimeout(dibujar, 160)
}

async function dibujar() {
  const mia = ++generacion
  const d = visibles.value
  if (!d || !lienzo.value || !d.nodes.length) {
    cy.value?.destroy()
    cy.value = null
    return
  }

  const cytoscape = (await import('cytoscape')).default
  // Cytoscape mide el contenedor al crearse. Si el navegador todavía no ha
  // aplicado el layout, lo mide a cero y no dibuja nada.
  await new Promise((r) => requestAnimationFrame(r))
  if (mia !== generacion) return          // llegó otro filtro mientras tanto
  cy.value?.destroy()

  const color = (e: any) => leer(TOKEN_SEV[e.data('severidad')] ?? '--cx-fg-faint')
  cy.value = cytoscape({
    container: lienzo.value,
    elements: [...d.nodes, ...d.edges],
    // Sin desplazamiento por rueda: en una página con scroll, hacer zoom sin
    // querer al pasar por encima del grafo es de las cosas que más molestan.
    wheelSensitivity: 0.2,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': color,
          // En un grafo denso solo se rotula lo que orienta —host y
          // servicio—; el resto aparece al pasar por encima (`.destacado`) o
          // al pulsarlo. Un rótulo ilegible no informa: estorba.
          label: denso.value ? '' : 'data(label)',
          color: leer('--cx-fg-dim'),
          'font-family': leer('--cx-mono'),
          'font-size': '10px',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          'text-max-width': '140px',
          'text-wrap': 'ellipsis',
          width: 14, height: 14,
          'border-width': 0,
        },
      },
      // Dos familias que no se confunden. La ESTRUCTURA —host, servicio,
      // ruta— va en contorno: dice por dónde se llega. Los HALLAZGOS van
      // rellenos y con la figura de su severidad, la misma que en el resto de
      // la interfaz: rombo, triángulo, cuadrado, círculo y círculo hueco.
      { selector: 'node[tipo="host"], node[tipo="servicio"], node[tipo="ruta"]',
        style: { 'background-color': leer('--cx-bg'), 'border-width': 2,
                 'border-color': color } },
      { selector: 'node[tipo="host"]',
        style: { width: 30, height: 30, shape: 'round-rectangle', label: 'data(label)',
                 'border-width': 2.5, 'font-size': '12px', color: leer('--cx-fg') } },
      { selector: 'node[tipo="servicio"]',
        style: { width: 22, height: 22, shape: 'hexagon', label: 'data(label)' } },
      { selector: 'node[tipo="ruta"]',
        style: { width: 13, height: 13, shape: 'ellipse' } },
      // Una ruta sin hallazgos se queda en gris: está ahí, se sondeó, y no
      // tiene nada encontrado.
      { selector: 'node[tipo="ruta"][?sin_hallazgos]',
        style: { 'border-width': 1.5, 'border-color': leer('--cx-border-strong') } },
      { selector: 'node[tipo="hallazgo"]',
        style: { width: 13, height: 13, shape: 'rectangle', 'text-max-width': '180px' } },
      { selector: 'node[tipo="hallazgo"][severidad="critical"]',
        style: { width: 21, height: 21, shape: 'diamond' } },
      { selector: 'node[tipo="hallazgo"][severidad="high"]',
        style: { width: 19, height: 17, shape: 'triangle' } },
      { selector: 'node[tipo="hallazgo"][severidad="low"]',
        style: { shape: 'ellipse' } },
      { selector: 'node[tipo="hallazgo"][severidad="info"]',
        style: { shape: 'ellipse', 'background-opacity': 0, 'border-width': 2,
                 'border-color': color } },
      {
        selector: 'edge',
        style: {
          width: 1,
          'line-color': leer('--cx-border-strong'),
          // Recta: con `bezier`, dos aristas entre los mismos nodos se abren en
          // abanico y dibujan elipses que no significan nada.
          'curve-style': 'straight',
          'target-arrow-shape': 'none',
          opacity: 0.6,
        },
      },
      { selector: 'node:selected',
        style: { 'border-width': 3, 'border-color': leer('--cx-accent'),
                 'border-opacity': 1, label: 'data(label)' } },
      // Lo que está bajo el ratón, y su camino, sí se rotula siempre.
      // Lo que está bajo el ratón, y su camino, se rotula siempre.
      { selector: '.destacado',
        style: { label: 'data(label)', color: leer('--cx-fg'), 'z-index': 15 } },
      { selector: '.atenuado', style: { opacity: 0.15 } },
    ],
    layout: disposicion.value === 'arbol'
      ? {
          name: 'breadthfirst',
          directed: true,
          spacingFactor: 1.5,
          padding: 40,
          roots: d.nodes.filter((n) => n.data.tipo === 'host').map((n) => n.data.id),
        }
      : {
          // Radial: el host en el centro y cada nivel en su anillo. Con muchas
          // rutas aprovecha el espacio mucho mejor que el árbol, que las pone
          // todas en una fila y las deja ilegibles.
          //
          // Es `concentric` y no `breadthfirst` con `circle`: ese segundo, con
          // este grafo, colocaba los nodos tan lejos del origen que `fit` ya no
          // los recuperaba —pantalla en blanco y barra de desplazamiento—.
          // Aquí el anillo lo decide el tipo de nodo, que es lo que queremos
          // decir de todas formas: host dentro, hallazgos fuera.
          name: 'concentric',
          concentric: (n: any) =>
            ({ host: 4, servicio: 3, ruta: 2 }[n.data('tipo') as string] ?? 1),
          levelWidth: () => 1,
          minNodeSpacing: denso.value ? 26 : 50,
          padding: 50,
          avoidOverlap: true,
        },
  })

  // Pulsar un nodo abre su ficha al lado. Antes solo se enseñaba la etiqueta,
  // que es justo lo que ya se veía en el propio grafo.
  cy.value.on('tap', 'node', (ev: any) => { nodo.value = ev.target.data() })
  cy.value.on('tap', (ev: any) => { if (ev.target === cy.value) nodo.value = null })
  // Al pasar por encima, se resalta el camino completo hasta ese nodo.
  cy.value.on('mouseover', 'node', (ev: any) => {
    const vecindad = ev.target.closedNeighborhood().union(ev.target.predecessors())
    cy.value.elements().difference(vecindad).addClass('atenuado')
    vecindad.nodes().addClass('destacado')
  })
  cy.value.on('mouseout', 'node', () => {
    cy.value.elements().removeClass('atenuado').removeClass('destacado')
  })

  cy.value.fit(undefined, 40)

  // El contenedor cambia de tamaño al abrirse la ficha lateral o al girar la
  // pantalla; sin esto el grafo se queda con las medidas del primer dibujo.
  //
  // Dos cuidados, los dos aprendidos por las malas: `observe()` dispara el
  // callback de inmediato, y `resize()` recrea los lienzos —los deja en
  // blanco— mientras el dibujado inicial todavía está en marcha. Resultado: el
  // grafo existía, con sus nodos colocados y visibles según Cytoscape, y la
  // pantalla completamente vacía. Así que la primera medida se ignora y el
  // resto se atiende en el fotograma siguiente, con el dibujado ya hecho.
  observador?.disconnect()
  let ancho = lienzo.value.clientWidth
  let alto = lienzo.value.clientHeight
  observador = new ResizeObserver(() => {
    const caja = lienzo.value
    if (!caja || (caja.clientWidth === ancho && caja.clientHeight === alto)) return
    ancho = caja.clientWidth
    alto = caja.clientHeight
    clearTimeout(reajuste)
    // Solo `resize()`, nunca `fit()`: el lienzo se ajusta al nuevo tamaño pero
    // el encuadre se respeta. Reencuadrar aquí deshacía el zoom y el
    // desplazamiento del analista cada vez que cambiaba el ancho —y eso pasa
    // al abrirse o cerrarse la ficha, es decir, a cada clic—. Para volver a
    // encuadrar está el botón, que es cuando se pide a propósito.
    reajuste = window.setTimeout(() => cy.value?.resize(), 250)
  })
  observador.observe(lienzo.value)
}

function encuadrar() { cy.value?.fit(undefined, 40) }

function irAlHallazgo() {
  if (!nodo.value?.finding_id) return
  sesion.seleccionado = nodo.value.finding_id
  router.push('/hallazgos')
}

/** Los campos del detalle, ya en castellano y sin los vacíos. */
const campos = computed(() => {
  const d = nodo.value?.detalle ?? {}
  const NOMBRES: Record<string, string> = {
    url: 'URL', status: 'estado HTTP', titulo: 'título', servidor: 'servidor',
    tipo_contenido: 'tipo', longitud: 'bytes', tecnologias: 'tecnologías',
    redirecciones: 'redirecciones', metodos: 'métodos', params: 'parámetros',
    descubierta_por: 'descubierta por', hallazgos: 'hallazgos', host: 'host',
    esquema: 'esquema', puerto: 'puerto', rutas: 'rutas', severidad: 'severidad',
    origen: 'herramienta', check_id: 'comprobación', objetivo: 'objetivo',
    param: 'parámetro', cwe: 'CWE', owasp: 'OWASP', que_pasa: 'qué pasa',
  }
  const LARGOS = ['descripcion', 'correccion', 'titulo']
  return Object.entries(d)
    .filter(([k, v]) => !LARGOS.includes(k) && v !== null && v !== '' &&
      !(Array.isArray(v) && !v.length))
    .map(([k, v]) => ({
      k: NOMBRES[k] ?? k,
      v: Array.isArray(v) ? v.join(', ') : String(v),
    }))
})

onMounted(cargar)
watch(() => sesion.escaneoActual, cargar)
watch([minimo, soloConHallazgos, busqueda, disposicion], redibujarPronto)
onBeforeUnmount(() => {
  clearTimeout(temporizador)
  clearTimeout(reajuste)
  observador?.disconnect()
  cy.value?.destroy()
})
</script>

<template>
  <div class="relative flex min-h-0 overflow-hidden">
    <div class="relative flex-1 min-w-0 flex flex-col overflow-hidden">
      <!-- El lienzo recorta: Cytoscape posiciona sus canvas en absoluto y los
           redimensiona un paso por detrás del contenedor. -->
      <div ref="lienzo" class="flex-1 min-h-0 bg-bg overflow-hidden" />

      <!-- Controles y leyenda, encima del lienzo y no flotando sobre él:
           flotando tapaban la parte alta del grafo, y «encuadrar» no puede
           saber que ahí arriba hay algo. -->
      <div class="order-first shrink-0 flex flex-col gap-2 px-[clamp(16px,3vw,44px)] py-3
                  border-b border-line">
        <div class="flex items-baseline gap-3 flex-wrap">
          <h1 class="m-0 text-[17px] font-bold">Superficie de ataque</h1>
          <span v-if="resumen" class="font-mono text-[12px] text-fg-dim">
            {{ resumen.hosts }} host · {{ resumen.servicios }} servicio(s) ·
            {{ resumen.rutas }} ruta(s)
            <template v-if="resumen.rutas_sin_hallazgos">
              ({{ resumen.rutas_sin_hallazgos }} sin hallazgos)
            </template>
            · {{ resumen.hallazgos }} hallazgo(s)
          </span>
          <span
            v-if="resumen && resumen.hallazgos_dibujados !== resumen.hallazgos"
            class="text-[12px] text-crit"
          >
            el grafo dibuja {{ resumen.hallazgos_dibujados }} de
            {{ resumen.hallazgos }}: falta alguno y eso es un fallo, no un filtro
          </span>
          <span v-if="resumen?.hallazgos_sin_ubicar" class="text-[12px] text-med">
            {{ resumen.hallazgos_sin_ubicar }} sin ubicar: llegaron con una ruta
            relativa y cuelgan de «objetivo sin host». Vuelve a escanear y
            quedarán en su sitio.
          </span>
        </div>

        <div class="flex gap-2 flex-wrap items-center">
          <input
            v-model="busqueda"
            placeholder="Filtrar por ruta, título o parámetro"
            aria-label="Filtrar el grafo"
            class="w-[250px] bg-surface border border-line rounded-cx px-[9px] py-[5px]
                   font-mono text-[12px] text-fg outline-none focus:border-accent-dim
                   placeholder:text-fg-faint"
          >
          <div class="flex gap-px bg-line border border-line rounded-cx overflow-hidden">
            <button
              v-for="(n, i) in ['todo', 'baja+', 'media+', 'alta+', 'crítica']"
              :key="n"
              class="px-[9px] py-[5px] text-[12px] bg-surface"
              :class="minimo === i ? '!bg-surface-3 text-accent' : 'text-fg-dim hover:text-fg'"
              :aria-pressed="minimo === i"
              @click="minimo = i"
            >{{ n }}</button>
          </div>
          <label class="flex items-center gap-[6px] text-[12px] text-fg-dim
                        bg-surface border border-line rounded-cx px-[9px] py-[5px]">
            <input v-model="soloConHallazgos" type="checkbox" class="accent-accent">
            solo rutas con hallazgos
          </label>
          <div class="flex gap-px bg-line border border-line rounded-cx overflow-hidden">
            <button
              v-for="l in [{ id: 'radial', t: 'radial' }, { id: 'arbol', t: 'árbol' }]"
              :key="l.id"
              class="px-[9px] py-[5px] text-[12px] bg-surface"
              :class="disposicion === l.id ? '!bg-surface-3 text-accent' : 'text-fg-dim hover:text-fg'"
              :aria-pressed="disposicion === l.id"
              @click="disposicion = l.id as 'radial' | 'arbol'"
            >{{ l.t }}</button>
          </div>
          <button
            class="bg-surface border border-line rounded-cx px-[9px] py-[5px]
                   text-[12px] text-fg-dim hover:text-fg"
            @click="encuadrar"
          >Encuadrar</button>
        </div>

        <div class="flex gap-x-4 gap-y-1 flex-wrap text-[12px] text-fg-dim">
          <span v-for="(_, nivel) in TOKEN_SEV" :key="nivel" class="flex items-center gap-[6px]">
            <i aria-hidden="true" class="cx-fig" :class="`sev-${nivel}`" style="font-size: 13px" />
            {{ SEV_ES[nivel] }}
          </span>
        </div>
        <p class="m-0 text-[12px] text-fg-dim">
          Relleno, un hallazgo. En contorno, por dónde se llega: cuadrado el
          host, hexágono el servicio, círculo la ruta.
        </p>
        <p v-if="denso" class="m-0 text-[12px] text-fg-faint">
          Pasa el ratón por un nodo para ver su nombre y su camino; púlsalo para
          abrir su ficha.
        </p>
      </div>

      <p v-if="cargando"
         class="absolute inset-0 grid place-items-center text-fg-faint text-[13px]">
        dibujando el grafo…
      </p>
      <p v-else-if="fallo"
         class="absolute inset-0 grid place-items-center text-crit text-[13px]">
        {{ fallo }}
      </p>
      <div v-else-if="resumen && !visibles?.nodes.length"
           class="absolute inset-0 grid place-items-center px-8">
        <p class="m-0 max-w-[420px] text-center text-fg-faint text-[13px]">
          <template v-if="resumen.es_codigo">
            Este es un análisis de código: no hay superficie de red que mapear.
          </template>
          <template v-else-if="!resumen.superficie_registrada && !resumen.hallazgos">
            Este escaneo se guardó antes de que Crux registrara la superficie,
            y no dejó hallazgos. Vuelve a lanzarlo para verla.
          </template>
          <template v-else-if="busqueda || minimo || soloConHallazgos">
            Ningún nodo pasa los filtros.
          </template>
          <template v-else>
            Este escaneo no tiene nada que mapear.
          </template>
        </p>
      </div>
    </div>

    <!-- Ficha del nodo seleccionado. -->
    <aside
      v-if="nodo"
      class="w-[330px] shrink-0 bg-surface border-l border-line overflow-y-auto
             flex flex-col gap-3 px-4 py-4"
      aria-live="polite"
    >
      <div class="flex items-start gap-2">
        <h2 class="m-0 flex-1 text-[16px] font-bold leading-snug break-words">
          {{ nodo.detalle?.titulo || nodo.label }}
        </h2>
        <button class="text-fg-faint hover:text-fg text-[16px] leading-none"
                aria-label="Cerrar la ficha" @click="nodo = null">×</button>
      </div>
      <div class="flex gap-2 flex-wrap">
        <span class="text-[12px] text-fg-dim px-[8px] py-[2px] rounded-cx border border-line-strong">
          {{ nodo.tipo }}
        </span>
        <Severidad v-if="nodo.severidad" :nivel="nodo.severidad" como="ambas" />
        <span v-if="nodo.sin_hallazgos"
              class="text-[12px] text-fg-dim px-[8px] py-[2px] rounded-cx border border-line-strong">
          sin hallazgos
        </span>
      </div>

      <dl class="m-0 flex flex-col gap-[7px]">
        <div v-for="c in campos" :key="c.k" class="flex gap-3">
          <dt class="lbl w-[92px] shrink-0 !normal-case !tracking-normal !text-[12px]">
            {{ c.k }}
          </dt>
          <dd class="m-0 flex-1 min-w-0 font-mono text-[12px] text-fg break-words">
            {{ c.v }}
          </dd>
        </div>
      </dl>

      <p v-if="nodo.detalle?.descripcion" class="m-0 text-[12.5px] text-fg-dim leading-relaxed">
        {{ nodo.detalle.descripcion }}
      </p>
      <div v-if="nodo.detalle?.correccion" class="flex flex-col gap-1">
        <h3 class="lbl m-0">Corrección</h3>
        <p class="m-0 text-[12.5px] text-fg-dim leading-relaxed">
          {{ nodo.detalle.correccion }}
        </p>
      </div>

      <button
        v-if="nodo.finding_id"
        class="mt-auto px-3 py-[7px] rounded-cx bg-accent text-accent-ink
               font-bold text-[12.5px]"
        @click="irAlHallazgo"
      >Ver en el triaje</button>
      <p v-else-if="nodo.tipo === 'ruta' && nodo.sin_hallazgos"
         class="m-0 mt-auto text-[12px] text-fg-faint leading-relaxed">
        Esta ruta se vio pero no tiene hallazgos. No significa que esté bien:
        significa que lo que se ejecutó no encontró nada en ella.
      </p>
    </aside>
  </div>
</template>
