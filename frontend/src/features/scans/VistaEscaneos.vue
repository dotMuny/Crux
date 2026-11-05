<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, seguirTrabajo } from '@/api/client'
import { useSesion } from '@/stores/sesion'
import Severidad from '@/components/Severidad.vue'
import { ORDEN_SEVERIDAD } from '@/stores/sesion'
import type { Almacenamiento, Credenciales, EventoDeProgreso, Rol } from '@/api/types'

const sesion = useSesion()
const router = useRouter()

// Los dos pilares comparten formulario: cambia qué se pide, no el flujo.
const tipo = ref<'web' | 'code'>('web')
const objetivo = ref('')
const perfil = ref('safe-active')
const proyecto = ref('default')

const esCodigo = computed(() => tipo.value === 'code')
const marcador = computed(() => esCodigo.value
  ? '/ruta/al/repositorio'
  : 'https://app.intra.corp/  ·  10.20.4.0/24')
const explicacion = computed(() => esCodigo.value
  ? 'Analiza el código, sus dependencias y sus secretos. No usa la red: la base de vulnerabilidades se consultó al instalar.'
  : 'El alcance se confina a redes internas y se congela al arrancar. Un objetivo que resuelva a una IP pública se rechaza.')

// ── Sesión con la que se recorre la aplicación ──────────────────────────────
// Sin sesión solo se ve lo público, que en una aplicación interna es la menor
// parte: el formulario de acceso y poco más.
type ModoAuth = 'ninguna' | 'formulario' | 'cabecera' | 'cookies'
const modoAuth = ref<ModoAuth>('ninguna')
const acceso = reactive({
  url: '', usuario: '', clave: '',
  selectorUsuario: '', selectorClave: '', senal: '', proveedor: '',
})
const cabecerasCrudas = ref('')
const cookiesCrudas = ref('')
const selectoresAbiertos = ref(false)

// ── Roles a comparar ───────────────────────────────────────────────────────
interface FilaDeRol {
  nombre: string; rol: string
  usuario: string; clave: string   // modo formulario
  cabecera: string                 // modo cabecera
}
const roles = ref<FilaDeRol[]>([])
const puedeComparar = computed(
  () => modoAuth.value === 'formulario' || modoAuth.value === 'cabecera',
)

function anadirRol() {
  roles.value.push({ nombre: '', rol: '', usuario: '', clave: '', cabecera: '' })
}
function quitarRol(i: number) {
  roles.value.splice(i, 1)
}

// ── Aislamiento de red ─────────────────────────────────────────────────────
const sandbox = ref(false)
const aislamiento = ref<{ disponible: boolean; motivo: string } | null>(null)

onMounted(async () => {
  // Se pregunta al servidor en vez de suponerlo: el aislamiento necesita `ip`,
  // `nft` y privilegios, y la casilla debe decir qué falta en lugar de salir
  // desactivada sin explicación.
  try {
    aislamiento.value = await api.aislamiento()
  } catch {
    aislamiento.value = { disponible: false, motivo: 'no se pudo comprobar' }
  }
})

// Dentro de un namespace de red, 127.0.0.1 es el loopback del propio
// namespace: un objetivo en localhost es inalcanzable desde el aislamiento.
// El servidor también lo rechaza; decirlo aquí evita el viaje.
const objetivoEnLocalhost = computed(() =>
  /(^|\/\/)(127\.|localhost|\[?::1)/.test(objetivo.value))

const lanzando = ref(false)
const progreso = ref<EventoDeProgreso | null>(null)
const fallo = ref<string | null>(null)
const avisos = ref<string[]>([])

/** Interpreta un bloque de «clave: valor», una por línea. */
function pares(texto: string, separador: string): Record<string, string> {
  const salida: Record<string, string> = {}
  for (const linea of texto.split('\n')) {
    const corte = linea.indexOf(separador)
    if (corte <= 0) continue
    const clave = linea.slice(0, corte).trim()
    if (clave) salida[clave] = linea.slice(corte + separador.length).trim()
  }
  return salida
}

function credenciales(): Credenciales | null {
  switch (modoAuth.value) {
    case 'formulario':
      return {
        url_login: acceso.url.trim(),
        usuario: acceso.usuario,
        clave: acceso.clave,
        selector_usuario: acceso.selectorUsuario.trim() || null,
        selector_clave: acceso.selectorClave.trim() || null,
        senal_de_exito: acceso.senal.trim() || null,
        proveedor_identidad: acceso.proveedor.trim() || null,
      }
    case 'cabecera':
      return { cabeceras: pares(cabecerasCrudas.value, ':') }
    case 'cookies':
      return { cookies: pares(cookiesCrudas.value, '=') }
    default:
      return null
  }
}

function rolesParaEnviar(): Rol[] {
  if (!puedeComparar.value) return []
  return roles.value
    .filter((r) => r.nombre.trim())
    .map((r) => ({
      nombre: r.nombre.trim(),
      rol: r.rol.trim() || r.nombre.trim(),
      credenciales: modoAuth.value === 'formulario'
        // La URL de acceso es la misma para todos los roles: lo que cambia es
        // con qué usuario se entra, que es justo lo que se compara.
        ? { url_login: acceso.url.trim(), usuario: r.usuario, clave: r.clave,
            proveedor_identidad: acceso.proveedor.trim() || null }
        : { cabeceras: pares(r.cabecera, ':') },
    }))
}

/** Lo que falta por rellenar, dicho antes de molestar al servidor. */
function queFalta(): string | null {
  if (!objetivo.value.trim()) return 'falta el objetivo'
  if (esCodigo.value) return null
  if (modoAuth.value === 'formulario' && !acceso.url.trim())
    return 'el acceso por formulario necesita la URL del formulario'
  if (modoAuth.value === 'formulario' && !acceso.usuario)
    return 'el acceso por formulario necesita un usuario'
  if (modoAuth.value === 'cabecera'
      && !Object.keys(pares(cabecerasCrudas.value, ':')).length)
    return 'no hay ninguna cabecera válida; se espera «Nombre: valor» por línea'
  if (modoAuth.value === 'cookies'
      && !Object.keys(pares(cookiesCrudas.value, '=')).length)
    return 'no hay ninguna cookie válida; se espera «nombre=valor» por línea'
  if (sandbox.value && objetivoEnLocalhost.value)
    return 'un objetivo en localhost es inalcanzable desde el aislamiento de red'
  return null
}

async function lanzar() {
  const pendiente = queFalta()
  if (pendiente) {
    fallo.value = pendiente
    return
  }
  lanzando.value = true
  fallo.value = null
  avisos.value = []
  progreso.value = null
  try {
    const trabajo = await api.lanzar({
      // Un análisis de código recibe una ruta y nada más; partir por espacios
      // rompería cualquier ruta que los tenga.
      targets: esCodigo.value
        ? [objetivo.value.trim()]
        : objetivo.value.split(/[\s,]+/).filter(Boolean),
      tipo: tipo.value,
      profile: perfil.value,
      project: proyecto.value || 'default',
      ...(esCodigo.value ? {} : {
        credenciales: credenciales(),
        roles: rolesParaEnviar(),
        sandbox: sandbox.value,
      }),
    })
    avisos.value = trabajo.avisos ?? []
    seguirTrabajo(
      trabajo.id,
      (ev) => {
        progreso.value = ev
        // Ninguno de estos es un fallo del programa. El alcance rechazado y el
        // aislamiento imposible son controles de seguridad funcionando, y
        // merecen decirse con esas palabras.
        if (['alcance-rechazado', 'ruta-invalida', 'aislamiento-imposible',
          'autenticacion-fallida'].includes(ev.fase)) fallo.value = ev.mensaje
      },
      async () => {
        lanzando.value = false
        await sesion.cargar()
      },
    )
  } catch (e) {
    fallo.value = e instanceof Error ? e.message : String(e)
    lanzando.value = false
  }
}

function abrir(id: number) {
  sesion.abrirEscaneo(id)
  router.push('/hallazgos')
}

// ── Limpiar la lista ───────────────────────────────────────────────────────
const marcados = ref<Set<number>>(new Set())
const confirmando = ref(false)
const borrando = ref(false)
const borrado = ref<string | null>(null)
const almacen = ref<Almacenamiento | null>(null)

function marcar(id: number) {
  // Se reemplaza el Set entero: mutarlo no dispara la reactividad de Vue.
  const copia = new Set(marcados.value)
  copia.has(id) ? copia.delete(id) : copia.add(id)
  marcados.value = copia
  confirmando.value = false
}

function marcarTodos() {
  marcados.value = marcados.value.size === sesion.escaneos.length
    ? new Set()
    : new Set(sesion.escaneos.map((e) => e.id))
  confirmando.value = false
}

async function borrar() {
  if (!confirmando.value) {
    // Un borrado no se deshace, así que pide confirmación. Un diálogo del
    // navegador se despacha sin leerlo; el segundo clic en el mismo sitio, no.
    confirmando.value = true
    return
  }
  borrando.value = true
  try {
    const r = await sesion.borrarEscaneos([...marcados.value])
    borrado.value = `${r.borrados.length} escaneo(s) borrados`
      + (r.triajes_huerfanos ? `, ${r.triajes_huerfanos} juicio(s) de triaje sin hallazgo` : '')
      + ` · ${formatearBytes(r.bytes_liberados)} liberados en disco`
    marcados.value = new Set()
    almacen.value = await api.almacenamiento()
  } catch (e) {
    fallo.value = e instanceof Error ? e.message : String(e)
  } finally {
    borrando.value = false
    confirmando.value = false
  }
}

function formatearBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} kB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

onMounted(async () => {
  try {
    almacen.value = await api.almacenamiento()
  } catch { /* la cifra de disco es accesoria: su fallo no rompe la vista */ }
})

const CAMPO = `bg-bg border border-line rounded-cx px-3 py-[9px] font-mono text-[13px]
               text-fg outline-none focus:border-accent-dim placeholder:text-fg-faint`
</script>

<template>
  <div class="overflow-y-auto">
    <div class="max-w-[940px] mx-auto px-5 py-8 flex flex-col gap-8">
      <section class="flex flex-col gap-4">
        <h1 class="m-0 text-[28px] font-bold leading-tight">Lanzar un escaneo</h1>

        <div class="flex gap-px bg-line border border-line rounded-cx overflow-hidden w-fit">
          <button
            v-for="o in [
              { id: 'web', texto: 'Aplicación web' },
              { id: 'code', texto: 'Código' },
            ]"
            :key="o.id"
            class="px-4 py-[7px] text-[13px] bg-surface"
            :class="tipo === o.id ? '!bg-surface-3 text-accent' : 'text-fg-dim hover:text-fg'"
            :aria-pressed="tipo === o.id"
            @click="tipo = o.id as 'web' | 'code'"
          >{{ o.texto }}</button>
        </div>
        <div class="flex gap-2 flex-wrap items-stretch">
          <input
            v-model="objetivo"
            :placeholder="marcador"
            :aria-label="esCodigo ? 'Ruta del repositorio' : 'Objetivos'"
            :class="[CAMPO, 'flex-1 min-w-[260px]']"
            @keydown.enter="lanzar"
          >
          <select
            v-if="!esCodigo"
            v-model="perfil"
            aria-label="Perfil"
            class="bg-bg border border-line rounded-cx px-3 py-[9px] text-[13px] text-fg"
          >
            <option value="passive">pasivo</option>
            <option value="safe-active">activo seguro</option>
            <option value="aggressive">agresivo</option>
          </select>
          <input
            v-model="proyecto"
            placeholder="proyecto"
            aria-label="Proyecto"
            :class="[CAMPO, 'w-[150px] !font-sans']"
          >
          <button
            class="px-4 py-[9px] rounded-cx bg-accent text-accent-ink font-bold text-[13px]
                   disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="lanzando || !objetivo.trim()"
            @click="lanzar"
          >{{ lanzando ? (esCodigo ? 'analizando…' : 'escaneando…')
                       : (esCodigo ? 'Analizar' : 'Escanear') }}</button>
        </div>

        <p class="m-0 text-[12.5px] text-fg-faint">{{ explicacion }}</p>

        <!-- ── Sesión ──────────────────────────────────────────────────── -->
        <div v-if="!esCodigo" class="flex flex-col gap-3 pt-2 border-t border-line">
          <div class="flex items-baseline gap-3 flex-wrap">
            <h2 class="lbl m-0">Sesión</h2>
            <span class="text-[12px] text-fg-faint">
              sin ella solo se ve lo que la aplicación muestra sin autenticar
            </span>
          </div>

          <div class="flex gap-px bg-line border border-line rounded-cx overflow-hidden w-fit">
            <button
              v-for="m in [
                { id: 'ninguna', texto: 'Sin autenticar' },
                { id: 'formulario', texto: 'Formulario' },
                { id: 'cabecera', texto: 'Cabecera o JWT' },
                { id: 'cookies', texto: 'Cookies' },
              ]"
              :key="m.id"
              class="px-3 py-[6px] text-[12.5px] bg-surface"
              :class="modoAuth === m.id ? '!bg-surface-3 text-accent' : 'text-fg-dim hover:text-fg'"
              :aria-pressed="modoAuth === m.id"
              @click="modoAuth = m.id as ModoAuth"
            >{{ m.texto }}</button>
          </div>

          <div v-if="modoAuth === 'formulario'" class="flex flex-col gap-2">
            <div class="flex gap-2 flex-wrap">
              <input
                v-model="acceso.url"
                placeholder="https://app.intra.corp/"
                aria-label="URL de acceso"
                :class="[CAMPO, 'flex-1 min-w-[240px]']"
              >
              <input
                v-model="acceso.usuario"
                placeholder="usuario"
                aria-label="Usuario"
                autocomplete="off"
                :class="[CAMPO, 'w-[150px]']"
              >
              <input
                v-model="acceso.clave"
                type="password"
                placeholder="contraseña"
                aria-label="Contraseña"
                autocomplete="off"
                :class="[CAMPO, 'w-[150px]']"
              >
            </div>
            <p class="m-0 text-[12px] text-fg-dim max-w-[80ch]">
              La URL de la aplicación, aunque el formulario esté en Keycloak o en
              un ADFS: Crux sigue la redirección y entra donde le manden. Si no
              consigue entrar, el escaneo se para y dice por qué; no sigue como
              anónimo.
            </p>
            <button
              class="self-start min-h-[32px] text-[13px] text-accent hover:text-fg"
              @click="selectoresAbiertos = !selectoresAbiertos"
            >{{ selectoresAbiertos ? '− ' : '+ ' }}El acceso no es el habitual</button>
            <div v-if="selectoresAbiertos" class="flex flex-col gap-2">
              <p class="m-0 text-[12px] text-fg-dim max-w-[80ch]">
                El proveedor de identidad solo hace falta si la aplicación salta a
                él con JavaScript, como las que usan keycloak-js: si lo hace con
                una redirección, se descubre solo. Se usa para entrar y nada más;
                no se audita. Los campos se buscan por nombre («username»,
                «password» y sus variantes); si el formulario usa otros, dilo con
                un selector CSS.
              </p>
              <input
                v-model="acceso.proveedor"
                placeholder="proveedor de identidad · https://sso.intra.corp"
                aria-label="Proveedor de identidad"
                :class="[CAMPO, 'w-full']"
              >
              <div class="flex gap-2 flex-wrap">
                <input
                  v-model="acceso.selectorUsuario"
                  placeholder="selector del usuario · #user"
                  aria-label="Selector CSS del campo de usuario"
                  :class="[CAMPO, 'flex-1 min-w-[180px]']"
                >
                <input
                  v-model="acceso.selectorClave"
                  placeholder="selector de la contraseña · #pwd"
                  aria-label="Selector CSS del campo de contraseña"
                  :class="[CAMPO, 'flex-1 min-w-[180px]']"
                >
                <input
                  v-model="acceso.senal"
                  placeholder="texto que confirma el acceso · Salir"
                  aria-label="Texto que confirma el acceso"
                  :class="[CAMPO, 'flex-1 min-w-[180px]']"
                >
              </div>
            </div>
          </div>

          <textarea
            v-if="modoAuth === 'cabecera'"
            v-model="cabecerasCrudas"
            rows="2"
            placeholder="Authorization: Bearer eyJhbGciOi…"
            aria-label="Cabeceras fijas, una por línea"
            :class="[CAMPO, 'resize-y']"
          />
          <textarea
            v-if="modoAuth === 'cookies'"
            v-model="cookiesCrudas"
            rows="2"
            placeholder="SESSIONID=8f2c…"
            aria-label="Cookies, una por línea"
            :class="[CAMPO, 'resize-y']"
          />
          <p
            v-if="modoAuth === 'cookies'"
            class="m-0 text-[12px] text-fg-faint"
          >
            Es la salida para lo que no cubrimos: si la aplicación entra por SSO,
            autentícate tú en el navegador y pega aquí la cookie de sesión.
          </p>
          <p v-if="modoAuth !== 'ninguna'" class="m-0 text-[12px] text-fg-faint">
            Lo que escribas aquí se usa en memoria durante el escaneo. No se
            guarda en la base, no vuelve por la API y no queda en el informe: de
            la sesión se registra el modo, no la credencial.
          </p>

          <!-- ── Roles ────────────────────────────────────────────────── -->
          <div v-if="puedeComparar" class="flex flex-col gap-2 pt-1">
            <div class="flex items-baseline gap-3 flex-wrap">
              <h2 class="lbl m-0">Roles a comparar</h2>
              <span class="text-[12px] text-fg-faint">
                hacen falta dos: lo que delata un fallo de autorización es que
                dos roles distintos vean lo mismo
              </span>
            </div>
            <div
              v-for="(r, i) in roles"
              :key="i"
              class="flex gap-2 flex-wrap items-center"
            >
              <input
                v-model="r.nombre"
                placeholder="nombre · ana"
                :aria-label="`Nombre del rol ${i + 1}`"
                :class="[CAMPO, 'w-[140px]']"
              >
              <input
                v-model="r.rol"
                placeholder="rol · admin"
                :aria-label="`Papel del rol ${i + 1}`"
                :class="[CAMPO, 'w-[130px]']"
              >
              <template v-if="modoAuth === 'formulario'">
                <input
                  v-model="r.usuario"
                  placeholder="usuario"
                  autocomplete="off"
                  :aria-label="`Usuario del rol ${i + 1}`"
                  :class="[CAMPO, 'w-[140px]']"
                >
                <input
                  v-model="r.clave"
                  type="password"
                  placeholder="contraseña"
                  autocomplete="off"
                  :aria-label="`Contraseña del rol ${i + 1}`"
                  :class="[CAMPO, 'w-[140px]']"
                >
              </template>
              <input
                v-else
                v-model="r.cabecera"
                placeholder="Authorization: Bearer …"
                :aria-label="`Cabecera del rol ${i + 1}`"
                :class="[CAMPO, 'flex-1 min-w-[200px]']"
              >
              <button
                class="px-2 py-[7px] text-[12px] text-fg-dim hover:text-crit"
                :aria-label="`Quitar el rol ${i + 1}`"
                @click="quitarRol(i)"
              >quitar</button>
            </div>
            <button
              class="self-start text-[12px] text-accent hover:underline"
              @click="anadirRol"
            >+ añadir un rol</button>
            <p v-if="roles.length === 1" class="m-0 text-[12px] text-med">
              Con un solo rol no hay comparación posible.
            </p>
          </div>

          <!-- ── Aislamiento ──────────────────────────────────────────── -->
          <div class="flex flex-col gap-1 pt-2 border-t border-line">
            <label class="flex items-center gap-[9px] text-[13px]"
                   :class="aislamiento?.disponible ? 'text-fg' : 'text-fg-faint'">
              <input
                v-model="sandbox"
                type="checkbox"
                :disabled="!aislamiento?.disponible"
                class="accent-accent"
              >
              Aislar la red durante el escaneo
            </label>
            <p v-if="aislamiento && !aislamiento.disponible" class="m-0 text-[12px] text-med">
              No se puede aquí: {{ aislamiento.motivo }}. Sin aislamiento el
              escaneo funciona igual, y el egress cero se sigue comprobando
              herramienta por herramienta; lo que no se puede es imponerlo.
            </p>
            <p v-else class="m-0 text-[12px] text-fg-faint">
              El escaneo corre en un namespace de red que solo tiene ruta hacia
              las direcciones del alcance, con el DNS congelado. Lo demás no es
              que esté desaconsejado: no existe. Si no se puede montar, el
              escaneo falla en vez de ejecutarse sin aislar.
            </p>
            <p v-if="sandbox && objetivoEnLocalhost" class="m-0 text-[12px] text-med">
              Dentro del aislamiento, 127.0.0.1 es el loopback del propio
              namespace: un objetivo en localhost no se puede alcanzar desde
              dentro. Escanéalo sin aislar, o haz que escuche en una dirección
              encaminable.
            </p>
          </div>
        </div>

        <div v-if="progreso" class="flex flex-col gap-2">
          <div class="h-[6px] bg-surface-3 rounded-[2px] overflow-hidden">
            <div
              class="h-full bg-accent transition-[width] duration-300"
              :style="{ width: `${progreso.progreso * 100}%` }"
            />
          </div>
          <p class="m-0 font-mono text-[12px] text-fg-dim">
            {{ progreso.fase }} · {{ progreso.mensaje }}
          </p>
        </div>
        <p v-for="a in avisos" :key="a" class="m-0 text-[13px] text-med">{{ a }}</p>
        <p v-if="fallo" class="m-0 text-[13px] text-crit">{{ fallo }}</p>
      </section>

      <section class="flex flex-col gap-3">
        <div class="flex items-center gap-3 flex-wrap">
          <h2 class="m-0 text-[17px] font-bold">Escaneos</h2>
          <button
            v-if="sesion.escaneos.length"
            class="text-[12px] text-fg-dim hover:text-fg"
            @click="marcarTodos"
          >{{ marcados.size === sesion.escaneos.length ? 'no marcar ninguno' : 'marcar todos' }}</button>
          <div v-if="marcados.size" class="ml-auto flex items-center gap-3">
            <span class="font-mono text-[12px] text-fg-dim">
              {{ marcados.size }} marcado(s)
            </span>
            <button
              class="border rounded-cx px-3 py-[5px] text-[12.5px]"
              :class="confirmando
                ? 'bg-crit border-crit text-sev-ink font-bold'
                : 'border-line-strong text-fg-dim hover:border-crit hover:text-crit'"
              :disabled="borrando"
              @click="borrar"
            >{{ borrando ? 'borrando…'
                         : confirmando ? `Sí, borrar ${marcados.size}` : 'Borrar' }}</button>
            <button
              v-if="confirmando"
              class="text-[12px] text-fg-dim hover:text-fg"
              @click="confirmando = false"
            >cancelar</button>
          </div>
        </div>
        <p v-if="confirmando" class="m-0 text-[12.5px] text-med">
          Se borran los hallazgos, la evidencia y las salidas de las herramientas
          en disco. El triaje del proyecto se conserva —vive por huella, no por
          escaneo—, salvo el que se quede sin ningún hallazgo detrás. No tiene
          vuelta atrás.
        </p>
        <p v-if="borrado" class="m-0 text-[12.5px] text-accent">{{ borrado }}</p>

        <div
          v-for="e in sesion.escaneos"
          :key="e.id"
          class="flex items-center gap-3 px-3 py-[2px]
                 bg-surface border border-line rounded-cx hover:border-line-strong"
          :class="[e.id === sesion.escaneoActual ? 'border-accent-dim' : '',
                   marcados.has(e.id) ? '!border-crit' : '']"
        >
          <input
            type="checkbox"
            class="accent-accent shrink-0"
            :checked="marcados.has(e.id)"
            :aria-label="`Marcar el escaneo ${e.id} para borrarlo`"
            @change="marcar(e.id)"
          >
        <button
          class="flex items-center gap-4 flex-wrap text-left flex-1 min-w-0 py-[10px]"
          @click="abrir(e.id)"
        >
          <span class="font-mono text-[13px] text-fg-dim">#{{ e.id }}</span>
          <span class="text-[12px] px-[8px] py-[2px] rounded-cx border border-line-strong"
                :class="e.kind === 'code' ? 'text-fg' : 'text-fg-dim'"
          >{{ e.kind === 'code' ? 'código' : 'web' }}</span>
          <span class="font-mono text-[13px] truncate flex-1 min-w-[160px]">
            {{ e.targets.join(', ') || '—' }}
          </span>
          <span class="flex gap-3 items-center">
            <span
              v-for="nivel in ORDEN_SEVERIDAD"
              :key="nivel"
              class="flex items-center gap-[5px] font-mono text-[12px] tabular-nums"
              :class="e.por_severidad[nivel] ? 'text-fg' : 'text-fg-faint'"
            >
              <!-- Cabina oscura también aquí: una severidad sin hallazgos
                   se apaga en vez de seguir pidiendo la vista. -->
              <Severidad :nivel="nivel" como="figura" :talla="13"
                         :class="e.por_severidad[nivel] ? '' : 'opacity-30'" />
              {{ e.por_severidad[nivel] ?? 0 }}
            </span>
          </span>
          <span v-if="e.kind !== 'code'" class="text-[13px] text-fg-dim">
            {{ ({ passive: 'pasivo', 'safe-active': 'activo seguro', aggressive: 'agresivo' } as Record<string, string>)[e.profile] ?? e.profile }}
          </span>
        </button>
          <a
            :href="api.informe(e.id, 'pdf')"
            target="_blank"
            class="text-[12px] text-accent hover:underline shrink-0"
          >PDF</a>
        </div>

        <p v-if="!sesion.escaneos.length" class="m-0 text-[13px] text-fg-faint">
          Todavía no hay escaneos. Lanza uno arriba.
        </p>

        <!-- Dónde vive esto: la pregunta se responde aquí, no en el README. -->
        <details v-if="almacen" class="mt-2">
          <summary class="lbl cursor-pointer select-none">
            Dónde se guardan · {{ almacen.escaneos }} escaneos,
            {{ almacen.hallazgos }} hallazgos
          </summary>
          <div class="flex flex-col gap-1 pt-2 font-mono text-[12px] text-fg-dim">
            <p class="m-0 font-sans text-[12.5px] text-fg-faint">
              En disco, en un fichero SQLite de tu equipo. No en el navegador:
              limpiar la sesión o cambiar de navegador no borra ningún escaneo.
            </p>
            <div v-for="pieza in almacen.piezas" :key="pieza.ruta"
                 class="flex gap-3 flex-wrap">
              <span class="w-[190px] shrink-0 text-fg-faint">{{ pieza.nombre }}</span>
              <span class="flex-1 min-w-[220px] truncate">{{ pieza.ruta }}</span>
              <span class="tabular-nums">{{ formatearBytes(pieza.bytes) }}</span>
            </div>
          </div>
        </details>
      </section>
    </div>
  </div>
</template>
