# Virus-Scan
# 🛡️ Analizador Profundo de Malware, Conexiones y SUB-Scan

![Platform](https://img.shields.io/badge/Plataforma-Windows%2010%20%7C%2011-0078D6?style=for-the-badge&logo=windows)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/Estado-Activo-107C10?style=for-the-badge)

Herramienta gráfica de ciberseguridad y análisis forense en **Python** para Windows. Analiza tus carpetas en busca de archivos infectados o de alto riesgo mediante un motor de **2 fases (Barrido General + SUB-Scan Profundo)**, detectando conexiones ocultas, código ofuscado y firmas de hacking sin generar falsos positivos en programas legítimos.

---

## ✨ Características Principales (`¿Cómo funciona?`)

* **🔍 Escaneo en 2 Fases Automáticas:**
  * **Fase 1 (Barrido de Sistema y Red Viva):** Detecta ejecutables ocultos, dobles extensiones engañosas (`.pdf.exe`), scripts en zonas críticas y procesos con conexiones TCP/UDP activas mediante `netstat` y `tasklist`.
  * **Fase 2 (SUB-Scan Forense):** Inspecciona el interior de los archivos sospechosos (ASCII y UTF-16) buscando cadenas de ataque reales.
* **🧬 Detección de Ofuscación y Empaquetadores:** Calcula la **entropía matemática de Shannon** para descubrir binarios cifrados o empaquetados (`UPX`, `VMProtect`, `Themida`), cargas en `Base64` y comandos ocultos de PowerShell (`-EncodedCommand`, `IEX`).
* **🌐 Rastreo de Conexiones Internas (C2):** Extrae direcciones IP incrustadas en el código, *webhooks* de Discord/Telegram usados por *stealers*, dominios `.onion` (Tor) y túneles `ngrok`.
* **🛡️ Filtro Inteligente Anti Falsos Positivos:** Verifica **Firmas Digitales Oficiales de Windows (Authenticode)** y protege aplicaciones seguras conocidas (*Chrome*, *Opera GX*, *Gemini*, *Edge*, *Discord*, *Steam*).
* **⚡ Gestión en un Clic:**
  * **ELIMINAR:** Mata el proceso activo, corta todas sus conexiones de red (`taskkill /F /T`) y borra el archivo del disco.
  * **CONSERVAR:** Mantiene el archivo en tu equipo y lo retira de la lista de revisión.
  * **MARCAR COMO 100% SEGURO:** Añade el programa a tu lista blanca local (`lista_blanca_seguros.txt`).

---

## 🚀 Cómo usarlo paso a paso desde GitHub

### 1. Clonar o descargar el repositorio
Abre una terminal en tu PC y ejecuta:
```bash
git clone https://github.com/ignaciobelliazziaguilar166-bot/Virus-Scan.git
cd Virus-Scan.Python
```
*(También puedes hacer clic en el botón verde **`<> Code`** arriba a la derecha y elegir **`Download ZIP`**).*

### 2. Ejecutar con permisos de Administrador
Abre **Terminal (Administrador)** o **CMD (Administrador)** y lanza el programa:
```cmd
python Virus-Scan.oython
```

### 3. Analizar y gestionar archivos
1. Selecciona la carpeta o unidad que deseas revisar (o deja tu carpeta de usuario por defecto).
2. Haz clic en **`Iniciar Análisis + SUB-Scan`**.
3. Revisa las pestañas **`☣️ 100% Virus o Malware`** y **`⚠️ Archivos Sospechosos / Riesgo Alto`**.
4. Haz clic sobre cualquier archivo para ver su **Reporte Forense** en el panel inferior y elige **`ELIMINAR`**, **`CONSERVAR`** o **`MARCAR COMO 100% SEGURO`**.
