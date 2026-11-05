<script setup lang="ts">
/**
 * El radar del panel.
 *
 * Dos reglas de lectura y nada más: cuanto más cerca del centro, más grave; y
 * cada dirección es una ruta del objetivo. Así un vistazo responde a las dos
 * preguntas con las que se abre una auditoría —¿hay algo grave?, ¿dónde se
 * concentra?— sin leer una sola cifra.
 *
 * Lo que no hace: no pretende enseñar mil hallazgos uno a uno. Cada franja de
 * cada sector tiene un aforo según el arco que le toca; lo que no cabe se
 * resume en un «+n» y no se pierde, porque la lista completa está a un clic.
 * Un punto que no se puede distinguir del de al lado no informa.
 */
import { computed } from 'vue'
import type { Hallazgo, Severidad } from '@/api/types'

const props = defineProps<{ hallazgos: Hallazgo[] }>()
const emit = defineEmits<{ abrir: [id: number] }>()

const RANGO: Record<Severidad, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const ORDEN: Severidad[] = ['critical', 'high', 'medium', 'low', 'info']
const ES: Record<Severidad, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}

// Geometría, en tanto por ciento de la caja cuadrada.
const K = 41                      // radio del círculo
const FRANJA: Record<Severidad, number> = {
  critical: 13, high: 36, medium: 60, low: 82, info: 92,   // radio, en % de K
}
const ANILLOS = [100, 72, 48, 24]                          // fronteras entre franjas
const TALLA: Record<Severidad, number> = {
  critical: 23, high: 20, medium: 14, low: 14, info: 14,   // font-size de la figura
}
const MAX_SECTORES = 12
const LADO_NOMINAL = 640          // px; solo para estimar cuántas figuras caben

/**
 * De qué ruta cuelga un hallazgo.
 *
 * En un escaneo web es la ruta de la URL, sin parámetros: `/search?q=1` y
 * `/search?q=2` son el mismo sitio. En un análisis de código el objetivo es
 * `fichero:línea` o `fichero:paquete`, y lo que agrupa es el fichero.
 */
function rutaDe(objetivo: string): string {
  try {
    if (objetivo.includes('://')) return new URL(objetivo).pathname || '/'
  } catch { /* no era una URL bien formada: se trata como texto */ }
  const sinCola = objetivo.replace(/:[^/:]*$/, '')
  return sinCola || objetivo || 'sin ubicar'
}

function punto(radio: number, grados: number) {
  const a = (grados * Math.PI) / 180
  return {
    x: 50 + (K * radio * Math.sin(a)) / 100,
    y: 50 - (K * radio * Math.cos(a)) / 100,
  }
}

function recortar(texto: string, largo: number) {
  return texto.length > largo ? `${texto.slice(0, largo - 1)}…` : texto
}

const escena = computed(() => {
  const grupos = new Map<string, Hallazgo[]>()
  for (const h of props.hallazgos) {
    const clave = rutaDe(h.target)
    if (!grupos.has(clave)) grupos.set(clave, [])
    grupos.get(clave)!.push(h)
  }

  let sectores = [...grupos.entries()]
    .map(([clave, items]) => ({
      clave, items,
      peor: Math.max(...items.map((h) => RANGO[h.severity])),
    }))
    // Lo más grave primero: empieza arriba y gira en el sentido del reloj.
    .sort((a, b) => b.peor - a.peor || b.items.length - a.items.length
      || a.clave.localeCompare(b.clave))

  if (sectores.length > MAX_SECTORES) {
    const resto = sectores.slice(MAX_SECTORES - 1)
    sectores = [
      ...sectores.slice(0, MAX_SECTORES - 1),
      {
        clave: `otras ${resto.length} rutas`,
        items: resto.flatMap((s) => s.items),
        peor: Math.max(...resto.map((s) => s.peor)),
      },
    ]
  }

  // El arco de cada sector crece con lo que contiene, pero despacio: una ruta
  // con cuarenta hallazgos no debe aplastar a las demás.
  const pesos = sectores.map((s) => 1 + Math.log2(s.items.length))
  const total = pesos.reduce((a, b) => a + b, 0)

  const figuras: {
    id: number; x: number; y: number; nivel: Severidad; titulo: string; objetivo: string
  }[] = []
  const resumidos: { x: number; y: number; texto: string; nivel: Severidad }[] = []
  const rotulos: { x: number; y: number; texto: string; ancla: string; fuerte: boolean }[] = []
  const divisiones: number[] = []

  let desde = 0
  sectores.forEach((s, i) => {
    const arco = (pesos[i] / total) * 360
    const hasta = desde + arco
    // Margen para que las figuras de dos sectores vecinos no se toquen.
    const margen = sectores.length > 1 ? arco * 0.14 : 0
    const util = arco - margen * 2

    for (const nivel of ORDEN) {
      const lista = s.items.filter((h) => h.severity === nivel)
      if (!lista.length) continue
      const radio = FRANJA[nivel]
      const largoPx = ((util * Math.PI) / 180) * ((radio * K) / 100) * (LADO_NOMINAL / 100)
      const porFila = Math.max(1, Math.floor(largoPx / 22))
      const aforo = porFila * 2          // dos filas, alternando el radio
      const cabenTodos = lista.length <= aforo
      const dibujados = cabenTodos ? lista : lista.slice(0, Math.max(1, aforo - 1))
      const huecos = dibujados.length + (cabenTodos ? 0 : 1)
      const enDosFilas = huecos > porFila

      dibujados.forEach((h, j) => {
        const grados = desde + margen + ((j + 0.5) / huecos) * util
        const r = radio + (enDosFilas ? (j % 2 ? 4.5 : -4.5) : 0)
        figuras.push({
          id: h.id, nivel, titulo: h.title, objetivo: h.target, ...punto(r, grados),
        })
      })
      if (!cabenTodos) {
        const grados = desde + margen + ((huecos - 0.5) / huecos) * util
        resumidos.push({
          nivel, texto: `+${lista.length - dibujados.length}`, ...punto(radio, grados),
        })
      }
    }

    const centro = desde + arco / 2
    const seno = Math.sin((centro * Math.PI) / 180)
    rotulos.push({
      ...punto(107, centro),
      texto: recortar(s.clave, 22),
      // El rótulo se ancla por el lado que mira al círculo, para que crezca
      // hacia fuera y no encima de las figuras.
      ancla: seno > 0.25 ? 'translate(0, -50%)'
        : seno < -0.25 ? 'translate(-100%, -50%)' : 'translate(-50%, -50%)',
      fuerte: i === 0,
    })
    if (sectores.length > 1) divisiones.push(desde)
    desde = hasta
  })

  // El que decide: el más grave. Lleva su nombre escrito al lado.
  const primero = [...props.hallazgos].sort(
    (a, b) => RANGO[b.severity] - RANGO[a.severity])[0]
  const marca = primero ? figuras.find((f) => f.id === primero.id) : undefined

  return { figuras, resumidos, rotulos, divisiones, marca }
})

const cuenta = computed(() => {
  const c: Record<string, number> = {}
  for (const h of props.hallazgos) c[h.severity] = (c[h.severity] ?? 0) + 1
  return ORDEN.map((nivel) => ({ nivel, n: c[nivel] ?? 0 })).filter((x) => x.n > 0)
})
</script>

<template>
  <section aria-label="Hallazgos por ruta y gravedad" class="flex flex-col gap-3 min-w-0">
    <div class="relative w-full aspect-square font-mono text-[12px]">
      <!-- El instrumento. Todo lo decorativo va oculto a los lectores de
           pantalla; lo que cuenta —cada hallazgo— es un botón con su nombre. -->
      <div aria-hidden="true" class="absolute inset-0 pointer-events-none">
        <div class="absolute rounded-full border-[1.5px] border-[#3A5688] bg-[#08101E]"
             style="inset: 9%" />
        <div
          class="cx-barrido absolute rounded-full"
          style="inset: 9%; animation: cx-giro 8s linear infinite;
                 background: conic-gradient(from 0deg, rgba(95,212,255,0) 0deg,
                   rgba(95,212,255,0) 285deg, rgba(95,212,255,.2) 360deg)"
        />
        <div
          v-for="(a, i) in ANILLOS.slice(1)"
          :key="a"
          class="absolute rounded-full border"
          :class="i === 2 ? 'border-[#6B2E3B] bg-[var(--cx-crit-tint)]' : 'border-line'"
          :style="{ inset: `${50 - (K * a) / 100}%` }"
        />
        <div
          v-for="g in escena.divisiones"
          :key="g"
          class="absolute h-px bg-line origin-left"
          :style="{ left: '50%', top: '50%', width: `${K}%`,
                    transform: `rotate(${g - 90}deg)` }"
        />
        <!-- La mira. El centro es lo que decide. -->
        <div class="absolute left-1/2 top-1/2 w-[26px] h-[2px] bg-fg
                    -translate-x-1/2 -translate-y-1/2" />
        <div class="absolute left-1/2 top-1/2 w-[2px] h-[26px] bg-fg
                    -translate-x-1/2 -translate-y-1/2" />
      </div>

      <span
        v-for="r in escena.rotulos"
        :key="r.texto"
        class="absolute whitespace-nowrap"
        :class="r.fuerte ? 'text-fg font-bold' : 'text-fg-dim'"
        :style="{ left: `${r.x}%`, top: `${r.y}%`, transform: r.ancla }"
      >{{ r.texto }}</span>

      <span
        v-for="(r, i) in escena.resumidos"
        :key="`r${i}`"
        class="absolute -translate-x-1/2 -translate-y-1/2 px-[5px] rounded-cx
               bg-bg border border-line-strong text-[12px] text-fg"
        :style="{ left: `${r.x}%`, top: `${r.y}%` }"
        :title="`${r.texto.slice(1)} más de severidad ${ES[r.nivel]} en esta ruta`"
      >{{ r.texto }}</span>

      <button
        v-for="f in escena.figuras"
        :key="f.id"
        class="absolute -translate-x-1/2 -translate-y-1/2 size-[28px] grid place-items-center
               rounded-full hover:bg-white/10"
        :style="{ left: `${f.x}%`, top: `${f.y}%` }"
        :aria-label="`${f.titulo}, severidad ${ES[f.nivel]}, en ${f.objetivo}`"
        :title="`${f.titulo}\n${f.objetivo}`"
        @click="emit('abrir', f.id)"
      >
        <i
          aria-hidden="true"
          class="cx-fig"
          :class="`sev-${f.nivel}`"
          :style="{
            fontSize: `${TALLA[f.nivel]}px`,
            boxShadow: f.nivel === 'critical' ? '0 0 20px var(--cx-crit)' : undefined,
          }"
        />
      </button>

      <span
        v-if="escena.marca"
        aria-hidden="true"
        class="absolute whitespace-nowrap text-fg font-bold text-[13px] pointer-events-none"
        :style="{
          left: `${escena.marca.x}%`, top: `${escena.marca.y}%`,
          transform: escena.marca.x > 62
            ? 'translate(calc(-100% - 16px), -150%)' : 'translate(16px, -150%)',
        }"
      >{{ recortar(escena.marca.titulo, 30) }}</span>

      <p
        v-if="!props.hallazgos.length"
        class="absolute inset-0 m-0 grid place-items-center text-fg-dim font-sans text-[14px]"
      >Nada abierto en este escaneo.</p>
    </div>

    <div class="flex flex-wrap items-center gap-x-[22px] gap-y-2 text-[13px]">
      <span v-for="c in cuenta" :key="c.nivel" class="flex items-center gap-2">
        <i aria-hidden="true" class="cx-fig" :class="`sev-${c.nivel}`" style="font-size: 14px" />
        {{ ES[c.nivel] }} {{ c.n }}
      </span>
      <span class="text-fg-dim">Más cerca del centro, más grave. Cada dirección es una ruta.</span>
    </div>
  </section>
</template>
