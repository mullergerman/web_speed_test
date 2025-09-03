# Medidor de Velocidad Web para Android

Este programa Python mide la velocidad de descarga completa de sitios web, incluyendo todos los assets (CSS, JS, imágenes, fuentes) y proporciona análisis detallado para detectar cuellos de botella.

## Características

- ✅ Descarga páginas web completas con todos los assets
- ⏱️ Medición detallada del tiempo de cada asset individual  
- 🚫 Bypass completo de cache para pruebas limpias
- 📊 Reportes detallados con estadísticas
- 💾 Exportación de resultados en formato JSON
- 🔄 Descarga en paralelo para mayor eficiencia
- 📱 Optimizado para Android/Termux

## Archivos del Programa

- `web_speed_tester.py` - Programa principal que prueba los 3 sitios predefinidos
- `quick_test.py` - Herramienta para probar un solo sitio web
- `README.md` - Esta documentación

## Uso

### Probar los 3 sitios predefinidos (Google, YouTube, Facebook)
```bash
python3 web_speed_tester.py
```

### Probar un sitio específico
```bash
python3 quick_test.py https://www.ejemplo.com
python3 quick_test.py www.github.com  # También funciona sin https://
```

## Qué Mide el Programa

1. **Página Principal**:
   - Tiempo de descarga
   - Tamaño en bytes
   - Código de respuesta HTTP

2. **Assets Detectados y Descargados**:
   - **CSS**: Archivos de estilos
   - **JavaScript**: Scripts y librerías
   - **Imágenes**: JPG, PNG, SVG, WebP, etc.
   - **Fuentes**: WOFF, TTF, EOT, etc.

3. **Métricas por Asset**:
   - Tiempo total de descarga
   - Tiempo hasta el primer byte
   - Tamaño del archivo
   - Estado de éxito/fallo

## Ejemplo de Reporte

```
============================================================
REPORTE DETALLADO - https://www.youtube.com
============================================================

📊 RESUMEN GENERAL:
   Página principal: 0.71s (301,812 bytes)
   Assets totales: 9 (exitosos: 8, fallidos: 1)
   Tiempo total: 4.77s
   Tamaño total: 2,958,948 bytes (2.82 MB)

⏱️ ESTADÍSTICAS DE TIEMPO:
   Tiempo promedio por asset: 0.507s
   Asset más lento: 0.745s
   Asset más rápido: 0.265s

📁 POR TIPO DE ASSET:
   JS:
     Cantidad: 3 (éxito: 100.0%)
     Tiempo total: 2.00s
     Tiempo promedio: 0.667s
     Tamaño total: 1,541,165 bytes

🐌 ASSETS MÁS LENTOS (Top 10):
    1. 0.745s - js - https://m.youtube.com/s/_/ytmweb/_/js/...
    2. 0.692s - js - https://www.youtube.com/static/r/8c93d2c0/...
```

## Archivos de Resultados

Los resultados se guardan automáticamente en archivos JSON con formato:
`web_speed_results_YYYYMMDD_HHMMSS.json`

Este archivo contiene todos los datos detallados en formato estructurado para análisis posterior.

## Bypass de Cache

El programa está configurado para evitar cualquier tipo de cache:

- Headers HTTP específicos (`Cache-Control`, `Pragma`, `Expires`)
- User-Agent de Android real
- Nuevas conexiones para cada prueba
- Sin reutilización de sesiones entre sitios

## Detección de Cuellos de Botella

El programa ayuda a identificar cuellos de botella mostrando:

1. **Assets más lentos**: Lista ordenada por tiempo de descarga
2. **Estadísticas por tipo**: Promedio de tiempo por tipo de recurso  
3. **Assets fallidos**: Recursos que no se pudieron descargar
4. **Tiempo total vs tiempo de assets**: Comparación de tiempos

## Personalización

Para modificar los sitios a probar, edita el array `websites` en `web_speed_tester.py`:

```python
websites = [
    "https://www.google.com",
    "https://www.youtube.com", 
    "https://www.facebook.com",
    "https://tu-sitio-personalizado.com"  # Agregar aquí
]
```

## Solución de Problemas

**Error de conexión**: Verifica tu conexión a internet
**Timeouts**: Algunos assets pueden tomar más de 30 segundos (límite actual)
**Assets fallidos**: Normal para algunos recursos como imágenes base64 o URLs inválidas

## Compatibilidad

- ✅ Python 3.6+
- ✅ Android/Termux
- ✅ Linux
- ✅ Librería `requests` (incluida)

---

Desarrollado para análisis de rendimiento web en dispositivos Android.
