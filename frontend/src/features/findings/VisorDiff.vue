<script setup lang="ts">
/**
 * Diff entre la observación actual de un hallazgo y la anterior.
 *
 * Responde a la pregunta que se hace el analista al reabrir un hallazgo
 * recurrente: ¿esto ha cambiado desde la última vez? Distingue un hallazgo
 * intacto de uno que ha empeorado o está a medio corregir.
 *
 * CodeMirror se carga de forma perezosa: pesa, y la mayoría de los hallazgos
 * se tría sin abrir nunca esta pestaña.
 */
import { nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'

const props = defineProps<{ findingId: number }>()

interface Lado { scan_id: number; fecha: string; severidad: string; texto: string }
interface Respuesta {
  comparable: boolean
  motivo?: string
  antes?: Lado
  ahora?: Lado
  identicas?: boolean
}

const contenedor = ref<HTMLElement | null>(null)
const datos = ref<Respuesta | null>(null)
const cargando = ref(false)
const vista = shallowRef<{ destroy(): void } | null>(null)
// Con dos respuestas idénticas no hay diff que enseñar; se ofrece verlo
// igualmente, pero el estado por defecto es decirlo con palabras.
const forzarVista = ref(false)
const fallo = ref<string | null>(null)

function destruir() {
  vista.value?.destroy()
  vista.value = null
}

async function montar() {
  destruir()
  datos.value = null
  fallo.value = null
  cargando.value = true
  try {
    const r = await fetch(`/api/findings/${props.findingId}/diff`)
    const d = (await r.json()) as Respuesta
    datos.value = d
    // Se apaga el indicador ANTES de montar el editor, no al final: mientras
    // `cargando` es cierto la plantilla enseña "comparando…" y el contenedor
    // del editor ni siquiera está en el DOM, así que esperarlo no servía de
    // nada. Es lo que dejaba el panel en blanco.
    cargando.value = false
    if (!d.comparable || !d.antes || !d.ahora) return
    if (d.identicas && !forzarVista.value) return

    const [{ MergeView }, { EditorView }, { EditorState }] = await Promise.all([
      import('@codemirror/merge'),
      import('@codemirror/view'),
      import('@codemirror/state'),
    ])

    // Tema derivado de los mismos tokens que el resto de la interfaz, para que
    // el editor no parezca una pieza pegada de otro sitio.
    const tema = EditorView.theme({
      '&': {
        backgroundColor: 'var(--cx-surface-3)',
        color: 'var(--cx-code)',
        fontSize: 'var(--cx-text-xs)',
      },
      '.cm-content': { fontFamily: 'var(--cx-pre)', padding: '10px 0' },
      '.cm-gutters': {
        backgroundColor: 'var(--cx-surface-2)',
        color: 'var(--cx-fg-faint)',
        border: 'none',
        borderRight: '1px solid var(--cx-border)',
      },
      '.cm-scroller': { lineHeight: '1.7' },
      '.cm-changedLine': { backgroundColor: 'rgba(245,230,99,.09)' },
      '.cm-deletedChunk': { backgroundColor: 'rgba(255,77,77,.13)' },
      '.cm-insertedLine': { backgroundColor: 'rgba(87,227,137,.12)' },
      '.cm-changedText': { background: 'rgba(245,230,99,.24)' },
      '&.cm-merge-a .cm-changedLine': { backgroundColor: 'rgba(255,77,77,.11)' },
      '&.cm-merge-b .cm-changedLine': { backgroundColor: 'rgba(87,227,137,.10)' },
    }, { dark: true })

    const comunes = [
      tema,
      EditorView.editable.of(false),
      EditorState.readOnly.of(true),
      EditorView.lineWrapping,
    ]

    // nextTick de Vue, no requestAnimationFrame: lo que hay que esperar es a
    // que Vue aplique el DOM tras asignar `datos`, no a un fotograma. Con rAF
    // el contenedor todavía no existía y la función salía en silencio, que es
    // la razón de que el panel apareciera vacío sin un solo error en consola.
    await nextTick()
    if (!contenedor.value) {
      fallo.value = 'no se pudo montar el visor de diferencias'
      return
    }
    vista.value = new MergeView({
      a: { doc: d.antes.texto, extensions: comunes },
      b: { doc: d.ahora.texto, extensions: comunes },
      parent: contenedor.value,
      collapseUnchanged: { margin: 2, minSize: 6 },
      gutter: true,
    })
  } catch (e) {
    fallo.value = e instanceof Error ? e.message : String(e)
  } finally {
    cargando.value = false
  }
}

watch([() => props.findingId, forzarVista], montar, { immediate: true })
onBeforeUnmount(destruir)
</script>

<template>
  <div class="border-b border-line">
    <p v-if="fallo" class="px-[15px] py-3 text-[12.5px] text-crit">{{ fallo }}</p>

    <p v-else-if="cargando" class="px-[15px] py-3 text-fg-faint text-[12px] font-mono">
      comparando con la observación anterior…
    </p>

    <p
      v-else-if="datos && !datos.comparable"
      class="px-[15px] py-3 text-fg-faint text-[12.5px]"
    >{{ datos.motivo ?? 'No hay una observación anterior con la que comparar.' }}</p>

    <template v-else-if="datos?.antes && datos?.ahora">
      <div class="flex items-center gap-3 flex-wrap px-[15px] py-2 bg-surface-2
                  border-b border-line font-mono text-[12px] text-fg-dim">
        <span>escaneo {{ datos.antes.scan_id }} <span class="text-fg-faint">→</span>
          escaneo {{ datos.ahora.scan_id }}</span>
        <span
          class="lbl !text-[12px] ml-auto"
          :class="datos.identicas ? 'text-fg-faint' : 'text-med'"
        >{{ datos.identicas ? 'respuesta idéntica' : 'la respuesta ha cambiado' }}</span>
      </div>

      <p
        v-if="datos.identicas && !forzarVista"
        class="px-[15px] py-3 text-[12.5px] text-fg-dim"
      >
        El objetivo responde exactamente igual que en el escaneo anterior:
        este hallazgo sigue sin tocarse.
        <button class="text-accent hover:underline ml-1" @click="forzarVista = true">
          ver la respuesta de todas formas
        </button>
      </p>
      <div v-show="!datos.identicas || forzarVista" ref="contenedor"
           class="max-h-[340px] overflow-auto" />
    </template>
  </div>
</template>
