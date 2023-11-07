# VirusScan
Probado en linux
![Screenshot_2023-11-05_22_24_09](https://github.com/f3nixuy/VirusScan/assets/50671074/4cdb72b4-2c8d-40b4-bda2-1abead98e515)
Este programa es un analizador de archivos y URLs que utiliza la API de VirusTotal, un servicio de análisis de archivos y direcciones web en busca de malware y amenazas. El funcionamiento del programa se puede dividir en los siguientes pasos:

1. Importación de bibliotecas:
   - El programa importa las bibliotecas `requests` para realizar solicitudes HTTP y `tkinter` para la creación de una interfaz gráfica de usuario.

2. Definición de la clave de API:
   - Debes reemplazar `'TU_API_KEY'` con tu clave de API de VirusTotal para que el programa pueda comunicarse con el servicio.

3. Funciones de análisis:
   - El programa define dos funciones: `analizar_archivo()` y `analizar_url()`, que se utilizan para analizar archivos y URLs, respectivamente.

4. Función `analizar_archivo()`:
   - Abre un cuadro de diálogo de selección de archivo para que el usuario elija un archivo.
   - Luego, envía el archivo seleccionado a VirusTotal para su análisis utilizando la clave de API.
   - Obtiene un `scan_id` como respuesta.
   - Solicita un informe sobre el archivo utilizando el `scan_id`.
   - Muestra el informe en una ventana emergente utilizando la función `mostrar_informe()`.

5. Función `analizar_url()`:
   - Obtiene la URL ingresada por el usuario en un campo de entrada.
   - Envía la URL a VirusTotal para su análisis utilizando la clave de API.
   - Obtiene un informe sobre la URL.
   - Muestra el informe en una ventana emergente utilizando la función `mostrar_informe()`.

6. Función `mostrar_informe()`:
   - Crea una ventana emergente para mostrar el informe.
   - Verifica si el informe contiene información sobre la detección de amenazas (`positives`).
   - Muestra si el archivo o URL es seguro o malicioso en función de los resultados.
   - Muestra un informe detallado de los escaneos, destacando en rojo los resultados que encontraron virus y en negro los resultados que no encontraron virus.

7. Creación de la interfaz gráfica:
   - El programa crea una ventana principal (`root`) con botones y campos de entrada para que el usuario interactúe con el programa.
   - El botón "Cargar Archivo" llama a la función `analizar_archivo()` para analizar un archivo.
   - La entrada de URL y el botón "Analizar URL" están destinados a analizar URLs.

8. Inicio de la aplicación:
   - La función `root.mainloop()` inicia la interfaz gráfica y permite al usuario utilizar el programa.

En resumen, este programa te permite analizar archivos y URLs en busca de malware y amenazas utilizando la API de VirusTotal. Los resultados se muestran en una ventana emergente, lo que te permite determinar si un archivo o URL es seguro o malicioso.
