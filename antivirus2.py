#F3nix
import requests
import tkinter as tk
from tkinter import filedialog

# Reemplaza 'TU_API_KEY' con tu API Key de VirusTotal
API_KEY = '7355b70aefd94c439512581538d55139be7f02ffa2b48ff5e486aadb1dbd53df'

def analizar_archivo():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            params = {'apikey': API_KEY}
            # Enviar el archivo y obtener el scan_id
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            scan_id = response.json()['scan_id']
            # Solicitar el informe usando el scan_id
            params = {'apikey': API_KEY, 'resource': scan_id}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            report = response.json()
            mostrar_informe(report)


def analizar_url():
    url = url_entry.get()
    if url:
        params = {'apikey': API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        report = response.json()
        mostrar_informe(report)

def mostrar_informe(report):
    informe_window = tk.Toplevel()
    informe_window.title('Informe de VirusTotal')

    if 'positives' in report:
        resultado_label = tk.Label(informe_window, text='Resultado del análisis:')
        resultado_label.pack()
        if report['positives'] > 0:
            resultado_label.config(foreground='red')
            tk.Label(informe_window, text='El archivo/URL es malicioso.', foreground='red').pack()
        else:
            resultado_label.config(foreground='black')
            tk.Label(informe_window, text='El archivo/URL es seguro.', foreground='black').pack()

    tk.Label(informe_window, text='Resultado completo del análisis:').pack()
    result_text = tk.Text(informe_window, height=10, width=40)

    # Verificar si 'scans' está presente en el diccionario
    if 'scans' in report:
        detected_results = []
        undetected_results = []

        for scan_name, scan_info in report['scans'].items():
            result = f"{scan_name}:\n"
            for scan_key, scan_value in scan_info.items():
                result += f"  {scan_key}: {scan_value}\n"

            if scan_info['detected']:
                detected_results.append(result)
            else:
                undetected_results.append(result)

        # Mostrar primero los resultados que encontraron virus en rojo
        for result in detected_results:
            result_text.insert(tk.END, result, 'red')

        # Mostrar luego los resultados que no encontraron virus en negro
        for result in undetected_results:
            result_text.insert(tk.END, result, 'black')

        result_text.tag_configure('red', foreground='red')
        result_text.tag_configure('black', foreground='black')
        result_text.pack()

    tk.Button(informe_window, text='Cerrar', command=informe_window.destroy).pack()

root = tk.Tk()
root.title('Analizador VirusTotal')

file_button = tk.Button(root, text='Cargar Archivo', command=analizar_archivo)
url_label = tk.Label(root, text='URL a Analizar:')
url_entry = tk.Entry(root)
url_button = tk.Button(root, text='Analizar URL', command=analizar_url)

file_button.pack()
url_label.pack()
url_entry.pack()
url_button.pack()

root.mainloop()
