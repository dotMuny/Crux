<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, RouterView } from 'vue-router'
import { useSesion } from '@/stores/sesion'
import PaletaDeComandos from '@/components/PaletaDeComandos.vue'

const sesion = useSesion()
const paletaAbierta = ref(false)

function atajos(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    paletaAbierta.value = !paletaAbierta.value
    return
  }
  if (e.key === 'Escape') paletaAbierta.value = false
  const enCampo = ['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName)
  if (enCampo || paletaAbierta.value) return
  // j/k para recorrer la lista sin soltar el teclado, como en la maqueta.
  if (e.key === 'j') sesion.mover(1)
  if (e.key === 'k') sesion.mover(-1)
}

onMounted(() => {
  window.addEventListener('keydown', atajos)
  sesion.cargar()
})
onUnmounted(() => window.removeEventListener('keydown', atajos))

const PERFIL_ES: Record<string, string> = {
  passive: 'pasivo', 'safe-active': 'activo seguro', aggressive: 'agresivo',
}

const SECCIONES = [
  { to: '/panel', texto: 'Panel' },
  { to: '/hallazgos', texto: 'Hallazgos' },
  { to: '/superficie', texto: 'Superficie' },
  { to: '/escaneos', texto: 'Escaneos' },
]
</script>

<template>
  <!-- `overflow-hidden`: ninguna vista debe poder sacarle barras de
       desplazamiento a la página entera. El grafo de superficie coloca sus
       lienzos en posición absoluta y, durante un instante tras cambiar de
       tamaño, son más anchos que su contenedor; sin esto aparecía una barra,
       que estrechaba el contenedor, que disparaba otro reajuste… y las barras
       se quedaban parpadeando. -->
  <div class="flex flex-col h-full overflow-hidden">
    <header
      class="flex items-center gap-x-7 gap-y-2 flex-wrap px-[clamp(16px,3vw,44px)]
             pt-[14px] border-b border-line shrink-0"
    >
      <!-- La mira: el centro es lo que decide, y eso es lo que significa el
           nombre. -->
      <span class="flex items-center gap-[10px] pb-[12px]">
        <svg aria-hidden="true" width="24" height="24" viewBox="0 0 26 26" fill="none"
             stroke="currentColor" stroke-width="1.6">
          <circle cx="13" cy="13" r="8" />
          <path d="M13 1v8M13 17v8M1 13h8M17 13h8" />
        </svg>
        <span class="text-[19px] font-bold tracking-[.14em]">CRUX</span>
      </span>

      <nav aria-label="Secciones" class="flex gap-1 self-end">
        <RouterLink
          v-for="r in SECCIONES"
          :key="r.to"
          :to="r.to"
          class="min-h-[44px] px-4 flex items-center text-fg-dim hover:text-fg
                 border-b-2 border-transparent transition-colors"
          active-class="!text-fg font-bold !border-accent"
        >{{ r.texto }}</RouterLink>
      </nav>

      <span class="flex-1" />

      <span
        v-if="sesion.escaneo"
        class="font-mono text-[12px] text-fg-dim truncate pb-[12px]"
      >
        {{ sesion.proyectoActual?.name }}, escaneo #{{ sesion.escaneo.id }},
        {{ PERFIL_ES[sesion.escaneo.profile] ?? sesion.escaneo.profile }}
      </span>

      <button
        class="mb-[10px] min-h-[36px] px-[14px] flex items-center gap-[14px]
               bg-surface text-fg-dim border border-line rounded-cx
               hover:text-fg hover:border-line-strong"
        @click="paletaAbierta = true"
      >
        <span>Buscar o lanzar</span>
        <kbd class="font-mono text-[12px] text-fg">Ctrl K</kbd>
      </button>
    </header>

    <p
      v-if="sesion.error"
      class="px-[clamp(16px,3vw,44px)] py-2 text-[13px] text-crit-fg
             bg-[var(--cx-crit-tint)] border-b border-crit shrink-0"
      role="alert"
    >{{ sesion.error }}</p>

    <RouterView class="flex-1 min-h-0" />

    <PaletaDeComandos v-model:abierta="paletaAbierta" />
  </div>
</template>
