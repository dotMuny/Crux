/**
 * Registro mínimo de ECharts.
 *
 * Las importaciones nombradas van estáticas y en su propio módulo a propósito:
 * hacerlas dentro de un `import()` dinámico trae el barrel entero —todos los
 * tipos de gráfica y todos los componentes— y el tree-shaking no llega a
 * cruzar esa frontera. Son 358 kB comprimidos frente a una fracción, para una
 * sola gráfica de barras.
 *
 * El módulo entero se carga de forma perezosa desde la vista del panel.
 */
import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { SVGRenderer } from 'echarts/renderers'

echarts.use([BarChart, GridComponent, LegendComponent, TooltipComponent, SVGRenderer])

export { echarts }
