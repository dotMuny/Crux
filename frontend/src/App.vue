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
      class="flex items-center gap-5 flex-wrap px-[18px] py-[11px]
             bg-surface border-b border-line shrink-0"
    >
      <span class="flex items-center gap-[9px] font-black text-[13px] tracking-[.14em]">
        <i class="size-[7px] rounded-full bg-accent shadow-[0_0_0_3px_rgba(63,213,190,.14)]" />
        CRUX
      </span>

      <nav class="flex gap-1">
        <RouterLink
          v-for="r in [
            { to: '/panel', texto: 'Panel' },
            { to: '/hallazgos', texto: 'Hallazgos' },
            { to: '/superficie', texto: 'Superficie' },
            { to: '/escaneos', texto: 'Escaneos' },
          ]"
          :key="r.to"
          :to="r.to"
          class="px-3 py-[5px] rounded-cx text-[13px] text-fg-dim hover:text-fg
                 hover:bg-surface-2 transition-colors"
          active-class="bg-surface-2 text-fg"
        >{{ r.texto }}</RouterLink>
      </nav>

      <span v-if="sesion.escaneo" class="font-mono text-[12.5px] text-fg-dim truncate">
        {{ sesion.proyectoActual?.name }}
        <span class="text-fg-faint">/</span> escaneo {{ sesion.escaneo.id }}
        <span class="text-fg-faint">/</span> {{ sesion.escaneo.profile }}
      </span>

      <span class="flex-1" />

      <!-- La promesa central de la herramienta, visible siempre. -->
      <span
        class="flex items-center gap-[7px] text-[11.5px] font-medium text-accent
               border border-accent-dim rounded-full px-[11px] py-[4px]
               bg-[rgba(63,213,190,.06)]"
      >
        <svg viewBox="0 0 16 16" class="size-3" fill="none" stroke="currentColor" stroke-width="1.6">
          <path d="M8 1.6 2.8 3.9v3.6c0 3 2.1 5.7 5.2 6.9 3.1-1.2 5.2-3.9 5.2-6.9V3.9L8 1.6Z" />
          <path d="m5.9 8.1 1.5 1.6 2.7-3" />
        </svg>
        0 conexiones fuera del alcance
      </span>

      <button
        class="font-mono text-[11px] text-fg-dim border border-line-strong border-b-2
               rounded px-[7px] py-[3px] bg-surface-2 hover:text-fg"
        @click="paletaAbierta = true"
      >⌘K</button>
    </header>

    <p
      v-if="sesion.error"
      class="px-[18px] py-2 text-[12.5px] text-crit bg-[rgba(255,77,94,.08)]
             border-b border-line shrink-0"
    >{{ sesion.error }}</p>

    <RouterView class="flex-1 min-h-0" />

    <PaletaDeComandos v-model:abierta="paletaAbierta" />
  </div>
</template>
