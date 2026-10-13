# DocuTraceX

Aplicación web para el **análisis forense estático** de documentos Microsoft Office, PDF y correo electrónico, ejecutada en local sobre Windows. Mesa de investigación interactiva: árbol de componentes, evidencias vinculadas a su origen, IOC, visor hexadecimal, estados de análisis e informes.

> **Estado:** planificación / especificación consolidada. Ninguna fase se considera implementada hasta que existan código, pruebas y criterios de aceptación satisfechos.

## Principios

- No ejecutar macros, fórmulas, JavaScript, acciones PDF, controles, enlaces, medios ni adjuntos.
- No abrir URLs, resolver dominios ni contactar recursos remotos.
- Original inmutable; trabajar sobre componentes o copias aisladas.
- Primero los parsers/analizadores aplicables; después un único extractor común de IOC sobre sus resultados.
- Mostrar errores, límites y análisis parciales; «sin detecciones» ≠ seguro.
- Herramientas y runtimes en `tools\` con rutas relativas, sin instalaciones globales.
- No ampliar el alcance de formatos sin decisión expresa.

## Interfaz y estilo

La interfaz estará **íntegramente en inglés**, será **visual** y se basará en **paneles/secciones desplegables**. Toma [**WinHound**](https://github.com/G92MZ/winhound) como **referencia directa de estilo**: mismos colores, mismos tipos de menú, misma organización de la navegación y los mismos componentes visuales, para mantener una familia coherente entre las herramientas propias.

- Navegación principal: Overview, Marks, Components/analysis, Reports y Tasks.
- Overview: resumen conciso y expandible, alineado con el informe.
- Uso local, sin login ni gestión de usuarios.

## Backlog de tareas

Lista de trabajo derivada del mega resumen y la hoja de ruta. Agrupada por área; cada formato lleva sus subtareas juntas. El orden refleja dependencias, no fechas. Marca las casillas conforme avances.

### Fase 0 — Cierre de especificación y decisiones abiertas

- [ ] Confirmar extensiones incluidas/excluidas; `.docb` fuera, sin módulo propio
- [ ] Definir estados normalizados: correcto, hallazgo, discrepancia, error, no compatible, no ejecutado, parcial
- [ ] Definir modelos de análisis, componente, relación, IOC, hallazgo y evidencia
- [ ] Política de límites: sin cuotas fijas (tamaño, duración, memoria, componentes, ratio, anidamiento); máx. 100 adjuntos/correo; sin timeout global + cancelación manual
- [ ] Diseñar salvaguardas: streaming, cancelación, estados parciales, gestión ordenada de procesos
- [ ] Retención manual de casos; sin limpieza automática por antigüedad
- [ ] Definir manifiesto versionado y flujo de reapertura desde carpeta
- [ ] Definir criterios de análisis parcial y de discrepancias
- [ ] Crear plantilla de ficha de compatibilidad (nada se integra sin ella)
- [ ] Incorporar decisiones funcionales (ejecución automática, UI inglés en paneles tipo WinHound, Overview, Marks, panel de casos, informe único, local sin auth, un análisis por instancia)
- [ ] **Decisión abierta — presupuestos de recursos** configurables por caso con alerta/pausa (no abortar), para no colgar la instancia ni perder la muestra
- [ ] **Decisión abierta — reemplazo del Python *embeddable*** (evaluar python-build-standalone u otra distribución portable con pip)
- [x] **Decidido — identificador primario: libmagic** (motor del comando `file`, licencia BSD, firmas ampliables) en vez de TrID. TrID es *freeware no comercial* y pieza única; libmagic es permisivo y redistribuible para una distribución gratuita. DIE descartado porque identificaba DOCX/XLSX/PPTX como **ZIP** (son contenedores comprimidos); Apache Tika descartado por el peso del runtime Java salvo que se incorpore por Apache POI

*Aceptación: cada formato con alcance mínimo + pruebas; exclusiones documentadas; plantilla de ficha lista; «sin detecciones» ≠ seguro.*

### Infraestructura, repositorio y calidad

- [ ] Crear estructura de aplicación y configuración
- [ ] Definir rutas relativas (sin rutas de una máquina concreta)
- [ ] Configurar pruebas automatizadas, linting y análisis estático
- [ ] Añadir revisión de dependencias/vulnerabilidades (SCA)
- [ ] Crear documentación base, plantillas de issues y PR
- [ ] Establecer convenciones de logs, manejo de errores y versionado
- [ ] Montar CI (tests + lint + análisis en cada PR)

*Aceptación: entorno reproducible; tests básicos y CI operativos; sin rutas específicas de máquina.*

### App base, gestión de casos y ciclo de vida

- [ ] Interfaz web básica en inglés con carga de ficheros y paneles desplegables (ref. WinHound)
- [ ] Navegación: Overview, Marks, Components/analysis, Reports, Tasks
- [ ] Validar nombre, extensión y estructura de entrada (sin máximo fijo de tamaño)
- [ ] Guardar original sin modificar + ID único + carpeta aislada `cases\<analysis_id>\`
- [ ] Estructura de caso: `case.json`, `original\`, `extracted\`, `results\`, `reports\` con rutas relativas
- [ ] Manifiesto versionado: esquema, ID, fechas, hashes, metadatos, estado, versiones de herramientas
- [ ] Pantalla inicial: listado de casos con búsqueda y filtros
- [ ] Acción «Reabrir caso» por selección de carpeta (restaurar sin reejecutar); admitir casos movidos/copiados
- [ ] Validar manifiesto, esquema, rutas contenidas y hashes al reabrir; abrir como degradado si hay discrepancias
- [ ] Borrado manual explícito con confirmación (sin borrado automático)
- [ ] Prevención de traversal, rutas UNC/absolutas inesperadas y sobrescrituras
- [ ] Mostrar contenido potencialmente activo como datos escapados

*Aceptación: original verificable por hash; análisis aislados y persistentes; reapertura sin reejecutar (incluso tras mover); manifiestos corruptos y hashes discrepantes detectados.*

### Gestor de tareas y cola (pestaña Tasks)

- [ ] Gestor central de tareas + pestaña global «Tasks» accesible desde todos los módulos
- [ ] Por tarea: tipo/acción, caso y archivo/componente, estado, progreso, fase, inicio/duración, errores
- [ ] Estados: en cola, en ejecución, pausada, cancelando, cancelada, completada, parcial/con advertencias, fallida (distinguir progreso desconocido de 0 %)
- [ ] Un análisis de caso por instancia; resto en cola; paralelismo solo con instancias en puertos distintos
- [ ] Cancelación; pausa/reanudación solo donde sea seguro
- [ ] Acción «Rerun task»: relanzar una herramienta/fase aislada sobre el mismo caso/componente; no repetir el caso entero sin petición
- [ ] Historial de intentos (fecha, herramienta/versión, estado, duración, errores, resultados); versionar resultados previos sin sobrescribir
- [ ] Al completar un intento: actualizar resultados e informe, recalcular IOC, preservar Marks/comentarios y señalar los que requieren revisión
- [ ] Aislamiento de errores: una tarea fallida no bloquea las independientes

*Aceptación: lista unificada visible; cola secuencial por instancia; relanzamiento aislado con historial; Marks preservadas.*

### Núcleo común (hashes, identificación, modelos)

- [ ] Hashes MD5, SHA-1 y SHA-256 (original y componentes)
- [ ] libmagic (motor del comando `file`, BSD) como identificador general primario — registrar versión, salida y errores; empaquetar la DLL nativa + `magic.mgc` en `tools\` (verificar que el paquete de binarios Windows esté mantenido; `python-magic-bin` está abandonado)
- [ ] Firmas ampliables vía formato `magic(5)` para añadir tipos nuevos; la extensibilidad ambiciosa (reglas complejas) se reserva a la fase YARA
- [ ] DIE y Apache Tika quedan descartados como identificador general (DIE marcaba todo OOXML como ZIP; Tika arrastra Java)
- [ ] Adaptador de herramientas: versión, argumentos, código de salida, stdout/stderr, duración, resultado normalizado, prueba funcional
- [ ] Modelos de componente, relación, hallazgo y evidencia (IDs estables, no índices efímeros)
- [ ] Modelo persistente de Marks por hallazgo: TP/FP/Suspicious/Informational/Unreviewed, comentarios, fecha de revisión; sin tocar la evidencia automática
- [ ] Pivotado desde cada Mark a su origen (fichero/componente, parser, sección, offset)
- [ ] Diseñar modelo y motor común de IOC (sin ejecutarlo dentro de cada parser; ejecución en fase posterior)
- [ ] Comparación extensión / libmagic / validador estructural / parser semántico, con registro de discrepancias
- [ ] Extracción de cadenas (ASCII/UTF-16) con implementación propia en Python — Sysinternals Strings descartado (su licencia prohíbe redistribuir)
- [ ] FLOSS descartado

*Aceptación: hashes calculados diferenciados de cadenas con aspecto de hash; discrepancias explícitas; motor IOC diseñado pero no ejecutado aún.*

### Runtimes portables (Python, y Java/POI condicional)

- [ ] Inventariar versiones mínima/máxima de Python por herramienta/biblioteca
- [ ] Identificar dependencias nativas, runtimes y restricciones de Windows por combinación
- [ ] Separar dos problemas: aislar *dependencias* (venvs sobre 1 intérprete) vs aislar *intérpretes* (solo si una herramienta no arranca en la versión elegida)
- [ ] Probar Python 3.13 x64 como candidato inicial (no definitivo) contra toda la matriz
- [ ] Evaluar python-build-standalone como distribución portable con pip (en vez del *embeddable*)
- [ ] Decidir nº de entornos/intérpretes según la matriz (permitir varios si hace falta)
- [ ] Método reproducible para fijar/distribuir dependencias por entorno
- [ ] Forzar invocación explícita del intérprete/entorno asignado (nunca Python global ni PATH)
- [ ] Pruebas automatizadas de importación, ejecución y compatibilidad por entorno
- [ ] Diagnóstico visible de versiones/entornos; probar traslado a otra ruta/máquina
- [ ] Java + Apache POI: decidir por pruebas si se incorpora (compatibilidad, licencia, utilidad real); JARs + **OpenJDK** portable (Temurin/Zulu/Liberica, GPLv2+CPE — **nunca Oracle JDK**) en `tools\` con rutas relativas; nunca Java global

*Aceptación: toda herramienta Python con ficha revisada y pruebas en su entorno; sin invocación accidental del Python global; incompatibilidades resueltas o herramienta excluida.*

### Gestor portable de herramientas

- [ ] Inventario de versiones, fuentes, licencias y dependencias
- [ ] Comprobar actualizaciones desde la interfaz (mostrar instalada/candidata/fuente); instalación como acción explícita, sin actualización silenciosa
- [ ] Descarga solo desde fuentes aprobadas
- [ ] Verificación de hashes/firmas cuando existan
- [ ] Validación y prueba funcional antes de activar
- [ ] Actualización transaccional con rollback; logs de instalación/actualización
- [ ] Permisos adecuados; panel de estado
- [ ] Gestionar Python y, si se aprueba, Java/POI portables; no modificar PATH ni exigir runtimes globales

*Aceptación: descargas corruptas no reemplazan instalaciones válidas; actualización fallida permite rollback; versiones/licencias/estado visibles.*

### Componentes y visor hexadecimal

- [ ] Árbol de componentes y relaciones
- [ ] Panel de hallazgos con enlace a origen
- [ ] Visor de texto seguro (datos escapados)
- [ ] Visor hexadecimal por componente
- [ ] Búsqueda de bytes, ASCII y UTF-16; salto a offset; selección, copia y exportación
- [ ] Lectura por rangos para ficheros grandes (sin cargar completos)
- [ ] Distinguir offsets de original / ZIP comprimido / descomprimido / objeto PDF / parte MIME decodificada / extraído
- [ ] Mostrar procedencia, versión de herramienta y límites

*Aceptación: navegación hallazgo→evidencia; no se confunden offsets de representaciones distintas; componentes grandes no requieren carga completa.*

### Motor OOXML común

- [ ] Inventario ZIP, `[Content_Types].xml`, relaciones y `docProps`
- [ ] Parser XML seguro (sin entidades externas ni red); evaluar `defusedxml`
- [ ] Detectar relaciones externas, destinos rotos, partes huérfanas, duplicados ZIP, tipos incoherentes, XML malformado y rutas peligrosas
- [ ] IDs estables por ruta interna normalizada
- [ ] Extraer medios/objetos a espacio aislado, calcular hashes e identificar con libmagic; registrar metadatos para la fase IOC
- [ ] Manejar firmas, cifrado, partes desconocidas, `AlternateContent` y límites
- [ ] Detener el análisis profundo automático (apertura como análisis independiente)

*Aceptación: inventario reproducible; componentes trazables; sin extracción fuera del espacio de trabajo; errores y parcial visibles.*

### Office moderno — Word, Excel y PowerPoint

**Word (.docx/.docm/.dotx/.dotm)**
- [ ] Reconstruir párrafos, tablas, encabezados/pies, enlaces, comentarios, notas, cuadros de texto/formas
- [ ] Campos, texto oculto y revisiones recuperables; metadatos core/app/personalizados
- [ ] Plantillas adjuntas y relaciones externas
- [ ] Detección de HYPERLINK, INCLUDETEXT, INCLUDEPICTURE, DDE/DDEAUTO
- [ ] Inventario de `vbaProject.bin`/VBA; extracción de objetos y medios

**Excel (.xlsx/.xlsm/.xltx/.xltm/.xlam)**
- [ ] Inventario de libro, hojas, relaciones y visibilidad; shared strings y estilos
- [ ] Celdas con coordenadas: fórmula y valor en caché separados (nunca ejecutar/recalcular)
- [ ] Fórmulas compartidas/matriciales, nombres definidos, tablas, filtros, áreas de impresión, comentarios
- [ ] Gráficos, conexiones, consultas, enlaces externos, cachés de dinámicas, `calcChain`
- [ ] Patrones estáticos sospechosos (HYPERLINK, WEBSERVICE, FILTERXML, indirección, ofuscación); VBA y objetos; hojas hidden/veryHidden

**PowerPoint (.pptx/.pptm/.potx/.potm/.ppsx/.ppsm/.ppam/.sldx/.sldm)**
- [ ] Inventario de diapositivas, layouts, masters y relaciones
- [ ] Reconstrucción de texto/formas y orden aproximado; notas y comentarios
- [ ] Acciones, hipervínculos, medios, gráficos y diagramas; elementos ocultos
- [ ] Relaciones externas, OLE, ActiveX y VBA; extracción segura con procedencia

*Aceptación: vistas marcadas como reconstrucción, no clon; texto ligado al XML de origen; sin ejecutar macros/fórmulas, abrir enlaces, activar controles ni reproducir medios; fórmula y valor en caché diferenciados.*

### Office antiguo y OLE/CFB (.doc/.dot, .xls/.xlt/.xla, .ppt/.pot)

- [ ] Validar estructura real OLE/CFB (no fiar de la extensión)
- [ ] Inventariar directorios y streams; extraer de forma segura con hashes; visor hexadecimal
- [ ] Recopilar Strings/resultados textuales para el extractor común de IOC
- [ ] Detectar y extraer VBA
- [ ] Integrar `oledump.py` y `oletools` según compatibilidad; evaluar `olefile`
- [ ] Parsers semánticos para Word, Excel/BIFF y PowerPoint
- [ ] Evaluar Apache POI como complemento (no sustituye OLE/CFB ni análisis VBA)

*Aceptación: la extensión no determina por sí sola la ruta de análisis; infraestructura común y parsers específicos separados.*

### XLSB (.xlsb)

- [ ] Elegir parser(es): comparar `pyxlsb` (LGPL-3.0) y `python-calamine` (MIT) y conservar discrepancias — preferir `python-calamine` si se quiere evitar el copyleft de `pyxlsb`
- [ ] Validar estructura e inventariar componentes y relaciones
- [ ] Reconstruir hojas y celdas; fórmulas y valores en caché distinguidos (nunca recalcular)
- [ ] Hojas ocultas/veryHidden, nombres definidos y enlaces externos
- [ ] Detectar e inspeccionar VBA (oletools/oledump) cuando exista
- [ ] Extraer objetos aislados con hash, identificación y procedencia
- [ ] Corpus de pruebas propio: benignos, con macros, malformados y límite

*Aceptación: elementos no soportados/errores/parciales explícitos; sin prometer paridad con XLSX sin pruebas; sin ejecutar/recalcular fórmulas.*

### PDF (.pdf) — todas las subtareas

- [ ] Modelo de objetos, referencias, xref, trailers, `ObjStm` y catálogo
- [ ] Inventario de páginas, recursos y flujos; objetos duplicados/no referenciados y ciclos
- [ ] Texto por página y metadatos (orden aproximado, fuentes, texto oculto/solapado, grupos OCG)
- [ ] Enlaces y anotaciones; comparar texto visible con destino (sin conectar)
- [ ] Acciones/JS estático: `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/URI`, `/GoToR`, `/SubmitForm`, `/ImportData` (nunca ejecutar)
- [ ] Formularios AcroForm/XFA (campos, valores, acciones)
- [ ] Adjuntos `/EmbeddedFiles`/`/AF`: extraer aislados, hash, libmagic, procedencia; detener análisis profundo automático
- [ ] Cifrado y permisos (análisis parcial); firmas: presencia vs integridad vs cobertura vs cadena/timestamp
- [ ] Revisiones incrementales
- [ ] OCR automático (Tesseract + idiomas) cuando no haya texto nativo suficiente; rasterizador portable **`pypdfium2`** (Apache/BSD) preferido, o Poppler/`pdftoppm` (GPL, como subproceso); evitar PyMuPDF (AGPL) y Ghostscript (AGPL); marcar texto OCR como tal; progreso por página en la web
- [ ] Visor hexadecimal; informes y regresión
- [ ] Herramientas candidatas: `pypdf`, `qpdf`, `pdfid.py`, `pdf-parser.py`, `pyHanko`, Pillow, `pypdfium2`, Tesseract

*Aceptación: no ejecutar acciones/JS ni contactar URLs; procedencia de objetos/recursos; cifrado/errores/límites como parcial; firma/JS/adjunto ≠ malware por sí solos.*

### Correo — EML, EMLX y MSG (MBOX/OFT/PST/OST excluidos)

**EML/MIME (módulo `email`)**
- [ ] Cabeceras originales: remitente/destinatarios, asunto, fecha, Message-ID, Reply-To, Return-Path, Received
- [ ] Extraer y mostrar `Authentication-Results`, `Received-SPF` como valores declarados (advertir que se falsifican)
- [ ] Validación DKIM criptográfica offline **solo si viajan los datos necesarios** (sin DNS); marcar «no verificable» cuando falte la clave del selector — será el caso común
- [ ] Separar resultados declarados de validados (válido/inválido/no concluyente/no verificable)
- [ ] Multipart, cuerpos texto/HTML, codificaciones y adjuntos; MIME malformado/truncado como parcial

**MSG (`extract-msg`, `olefile`)**
- [ ] Validación estructural; propiedades MAPI; remitente/destinatarios/asunto/fechas/cuerpos
- [ ] Cabeceras de transporte solo si están presentes

**EMLX (Apple Mail)**
- [ ] Investigar/validar estructura con muestras reales; extraer cabeceras, cuerpo y adjuntos; truncamiento como parcial

**Adjuntos y pruebas**
- [ ] Extraer a espacio aislado con nombre seguro, hash, tamaño, libmagic y procedencia; detener análisis profundo automático
- [ ] Nunca ejecutar adjuntos, abrir enlaces, renderizar HTML activo ni DNS/HTTP
- [ ] Pruebas: benignos/malformados, texto/HTML/multipart, codificaciones, hasta 100 adjuntos, nombres peligrosos, Received/autenticación falsos, duplicados, truncamiento; verificar ausencia de red

*Aceptación: originales inalterados; lectura de autenticación automática y etiquetada como declarada; validación offline automática sin red; IOC con procedencia tras los parsers; PST/OST no incluidos.*

### Detecciones transversales y extractor común de IOC

- [ ] Ejecutar el extractor común **solo tras finalizar todos los parsers** y reunir sus resultados (texto, metadatos, cabeceras, macros, cadenas)
- [ ] Detectar IPv4/IPv6, URLs, dominios y cadenas con apariencia de hash; normalizar y deduplicar sin perder ubicaciones/contextos
- [ ] Mantener diferenciados hashes calculados vs cadenas que parecen hashes
- [ ] Reglas específicas de documentos (ID, versión, explicación, pruebas)
- [ ] Correlación interna entre componentes/hallazgos del mismo caso (coincidencias, ubicación, procedencia, contexto)
- [ ] No comparar contra listas externas/importadas en esta fase
- [ ] Discrepancias nombre/libmagic/estructura/parser; metadatos anómalos, ofuscación, contenido oculto
- [ ] Priorización explicable; versionado y regresión de reglas

*Aceptación: cada regla con ID/versión/explicación/pruebas; la correlación enlaza coincidencias sin afirmar malicia; procedencia conservada; indicadores ≠ certezas.*

### Informes y exportación (Overview, Marks, HTML/JSON)

- [ ] Informe HTML único vigente por caso: índice, secciones desplegables, enlaces internos a evidencias; actualizar al cambiar resultados/Marks
- [ ] Overview como resumen conciso y expandible alineado con el informe
- [ ] Pestaña Marks: 5 estados (TP/FP/Suspicious/Informational/Unreviewed), comentarios, fecha de revisión, persistencia
- [ ] Pivotado desde cada Mark a su evidencia (fichero/componente, parser, sección, offset)
- [ ] Agrupar IOCs repetidos conservando ocurrencias/contextos/procedencia
- [ ] Exportación JSON para automatización; PDF pospuesto a fase posterior
- [ ] HTML seguro: datos escapados, sin ejecutar contenido, sin recursos externos, sin abrir enlaces
- [ ] Relevancia automática vs selección manual separadas; desmarcar no elimina hallazgo/evidencia; persistir selección en el caso
- [ ] Por hallazgo: procedencia, evidencia, ubicación, herramienta/regla y versión; hashes, estados, errores, límites, discrepancias y partes no analizadas
- [ ] Opciones para omitir datos sensibles innecesarios

*Aceptación: informes reproducibles con procedencia; distingue automático vs manual; una actualización regenera el informe sin pisar clasificaciones; selección persiste al reabrir; HTML sin contenido activo.*

### Endurecimiento, seguridad y regresión

- [ ] Traversal, nombres peligrosos, ZIP bombs, XML malicioso/entidades externas
- [ ] PDF con xref malformados, ciclos y flujos enormes
- [ ] MIME excesivo, MSG/EML/EMLX corruptos, adjuntos peligrosos
- [ ] Archivos enormes, descompresión extrema, anidamiento profundo, miles de objetos (sin cuotas fijas)
- [ ] Agotamiento de CPU/memoria/disco, cancelación manual, terminación controlada
- [ ] Verificar límite de 100 adjuntos/correo
- [ ] Cola secuencial por instancia y aislamiento de errores entre tareas
- [ ] Verificar estados/transiciones de Tasks y el relanzamiento aislado (historial, IOC/informe actualizados, Marks conservadas)
- [ ] Verificar ausencia de red cuando sea viable
- [ ] Revisar logs, dependencias, licencias y vulnerabilidades; confirmar original inalterado y no ejecución de contenido activo
- [ ] Mantener corpus benigno/malformado/límite/adversarial por familia

*Aceptación: casos adversariales terminan de forma controlada; sin escape del espacio de trabajo; límites generan parciales explícitos; errores no se convierten en falsos «sin detecciones».*

### Distribución portable Windows y revisión final

- [ ] Resolver rutas relativas; empaquetar/gestionar runtimes y herramientas
- [ ] Verificar Python portable (y Java si aplica); evitar cambios globales de PATH
- [ ] Instalar, actualizar, rollback y desinstalar; diagnóstico de herramientas/versiones
- [ ] Documentar requisitos del sistema y permisos
- [ ] Probar traslado y ejecución en máquina Windows limpia compatible
- [ ] Revisión final: pruebas unitarias, integración, regresión, seguridad y portabilidad
- [ ] Revisar alcance y exclusiones; verificar procedencia, no ejecución y no red
- [ ] Publicar limitaciones conocidas

*Aceptación: sin rutas absolutas de desarrollo; uso real de los runtimes incluidos; detección de herramientas ausentes/incompatibles; distribución reproducible.*

### Transversal — inventario de herramientas y fichas de compatibilidad

- [ ] Tarea específica de inventario de todas las apps/herramientas/bibliotecas/parsers para todos los formatos del alcance
- [ ] Plantilla de ficha de compatibilidad: versiones (mín/máx Python), dependencias nativas/runtimes, licencia/redistribución, Windows/portabilidad, formatos/funcionalidades, pruebas, limitaciones, alternativa, fuente y versión fijada
- [ ] Una ficha revisada **antes** de integrar cada herramienta/biblioteca/parser/runtime
- [ ] Matriz general de herramientas, versiones, licencias y dependencias (mantenida)
- [ ] Verificaciones de integridad (hash/firma) por fuente oficial
- [ ] Candidatos a evaluar (con licencia; todo pensado para redistribución gratuita):
    - Identificación: **libmagic / `file`** (BSD) — primario; `puremagic` (MIT) como respaldo en Python puro
    - XML/OOXML: `defusedxml` (PSF), `python-docx` · `openpyxl` · `python-pptx` (MIT), `zipdump.py` (dominio público)
    - OLE/VBA: `oletools` · `olefile` (BSD), `oledump.py` (dominio público)
    - XLSB: `python-calamine` (MIT, preferido) o `pyxlsb` (LGPL-3.0)
    - PDF: `pypdf` (BSD), `qpdf` (Apache-2.0), `pdfid.py` · `pdf-parser.py` (dominio público), `pyHanko` (MIT), `Pillow` (HPND), **`pypdfium2`** (Apache/BSD, rasterizado) o Poppler/`pdftoppm` (GPL), `Tesseract` + idiomas (Apache-2.0)
    - Correo: `extract-msg` (BSD), módulo `email`/`hashlib` (PSF)
    - Condicional: Apache POI (Apache-2.0) + OpenJDK (GPLv2+CPE)
    - Descartados por licencia/encaje: **TrID** (freeware no comercial), **Sysinternals Strings** (prohíbe redistribuir), **DIE** (marca OOXML como ZIP), **PyMuPDF/Ghostscript** (AGPL), **FLOSS**, Oracle JDK

*Aceptación: ninguna dependencia integrada sin ficha completada y revisada; matriz mantenida; el estudio de runtime/Python va en su fase propia.*

### Tarea futura — motor YARA

- [ ] Incorporar un motor YARA a la aplicación (al final de la hoja de ruta)
- [ ] Definir alcance, selección de motor, gestión de reglas, integración con los análisis y pruebas
- [ ] Pendiente de concretar por decisión expresa; se detallará al abordar esta tarea

*Nota: fuera del alcance activo; sin diseño detallado por ahora.*

## Alcance de formatos

| Familia | Incluidos | Excluidos |
|---|---|---|
| Word moderno | `.docx` `.docm` `.dotx` `.dotm` | — |
| Excel moderno | `.xlsx` `.xlsm` `.xltx` `.xltm` `.xlam` | — |
| PowerPoint moderno | `.pptx` `.pptm` `.potx` `.potm` `.ppsx` `.ppsm` `.ppam` `.sldx` `.sldm` | — |
| Office antiguo | `.doc` `.dot` `.xls` `.xlt` `.xla` `.ppt` `.pot` | — |
| Excel binario | `.xlsb` (módulo propio) | — |
| PDF | `.pdf` | — |
| Correo | `.msg` `.eml` `.emlx` | `.mbox` `.oft` `.pst` `.ost` |
| Otros | — | `.docb` |

---

Referencia funcional/visual: [WinHound](https://github.com/G92MZ/winhound).
