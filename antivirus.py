# F3nix
import tkinter as tk
from tkinter import filedialog
import requests

# Reemplaza 'TU_API_KEY' con tu API Key de VirusTotal
API_KEY = 'ACATUAPI'

def analizar_archivo():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            params = {'apikey': API_KEY}
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            scan_id = response.json()['scan_id']
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
    result_text.delete(1.0, tk.END)
    red_text = ""
    black_text = ""

    result_text.insert(tk.END, 'Resultado completo del análisis:\n', 'heading')

    if 'positives' in report:
        total_motores = report['total']
        motores_detectados = report['positives']
        result_text.insert(tk.END, f'Total de motores de antivirus utilizados: {total_motores}\n')
        result_text.insert(tk.END, f'Motores de antivirus que encontraron el archivo malicioso: {motores_detectados}\n')

        if 'scans' in report:
            results = []

            for scan_name, scan_info in report['scans'].items():
                scan_result = f"{scan_name}:\n"
                for scan_key, scan_value in scan_info.items():
                    scan_result += f"  {scan_key}: {scan_value}\n"
                results.append((scan_result, scan_info['detected']))

            results.sort(key=lambda x: x[1], reverse=True)

            for result, detected in results:
                if detected:
                    red_text += result
                else:
                    black_text += result

        if report['positives'] > 0:
            result_text.config(foreground='red')
            red_text = 'El archivo/URL es malicioso.\n' + red_text
        else:
            result_text.config(foreground='black')
            black_text = 'El archivo/URL es seguro.\n' + black_text

        result_text.insert(tk.END, red_text, 'red')
        result_text.insert(tk.END, black_text, 'black')

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

result_text = tk.Text(root, height=10, width=40)
result_text.tag_configure('red', foreground='red')
result_text.tag_configure('black', foreground='black')
result_text.tag_configure('heading', font=('Helvetica', 12, 'bold'))
result_text.pack()

root.mainloop()

