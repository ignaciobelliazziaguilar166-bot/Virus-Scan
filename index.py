import os
import re
import math
import hashlib
import subprocess
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

ARCHIVO_WHITELIST = "lista_blanca_seguros.txt"

# Ejecutables legítimos conocidos que usan APIs de red, memoria y credenciales de forma segura
EJECUTABLES_SEGUROS_POR_DEFECTO = {
    'chrome.exe', 'googleupdate.exe', 'googlecrashhandler.exe', 'googlecrashhandler64.exe',
    'opera.exe', 'opera_gx.exe', 'opera_autoupdate.exe', 'opera_crashreporter.exe', 'launcher.exe',
    'gemini.exe', 'msedge.exe', 'msedgewebview2.exe', 'brave.exe', 'firefox.exe',
    'discord.exe', 'update.exe', 'spotify.exe', 'steam.exe', 'steamwebhelper.exe',
    'code.exe', 'explorer.exe', 'svchost.exe', 'taskmgr.exe', 'python.exe', 'pythonw.exe',
    'onedrive.exe', 'teams.exe', 'nvcontainer.exe', 'nvidia share.exe', 'securityhealthsystray.exe'
}

# Carpetas oficiales de programas conocidos para evitar falsos positivos en AppData y Program Files
RUTAS_OFICIALES_SEGURAS = (
    '\\google\\chrome\\application',
    '\\google\\update',
    '\\programs\\opera gx',
    '\\programs\\opera',
    '\\opera software\\opera gx stable',
    '\\microsoft\\edge\\application',
    '\\microsoft\\edgewebview\\application',
    '\\bravesoftware\\brave-browser\\application',
    '\\mozilla firefox',
    '\\windows\\system32',
    '\\windows\\syswow64',
    '\\windows\\winsxs',
    '\\windows defender',
    '\\microsoft\\windows\\start menu'
)

EXTENSIONES_RIESGO = {
    '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.hta',
    '.jar', '.msi', '.com', '.dll', '.js', '.wsf', '.pif'
}
EXTENSIONES_DOCUMENTOS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg',
    '.png', '.txt', '.zip', '.rar', '.mp4', '.mp3'
}

# 1. Patrones de códigos ofuscados y empaquetadores de Malware
PATRONES_OFUSCACION = {
    "Comando PowerShell Ofuscado (-EncodedCommand)": re.compile(r'-(?:enc|encodedcommand)\s+[a-zA-Z0-9+/=]{20,}', re.I),
    "Decodificación Base64 en Script": re.compile(r'(?:FromBase64String|base64\s+-d|b64decode\s*\()', re.I),
    "Ejecución Dinámica Oculta (IEX / Invoke-Expression)": re.compile(r'(?:Invoke-Expression|\bIEX\s*\(|\beval\s*\(\s*base64)', re.I),
    "Empaquetador de Binarios Oculto (UPX/VMProtect/Themida)": re.compile(r'(?:UPX0|UPX1|UPX!|VMProtect|Themida|MPRESS1|ASPack)', re.I),
    "Descompresión de Payload en Memoria": re.compile(r'(?:IO\.Compression\.GzipStream.*MemoryStream|marshal\.loads\s*\(\s*zlib)', re.I)
}

# 2. Patrones de firmas reales de Hacking / Malware (Exige indicadores específicos de ataque)
FIRMAS_HACKING = {
    "Ransomware: Destrucción de Copias de Seguridad": re.compile(r'(?:vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete.*catalog)', re.I),
    "Reemplazo Oculto de Procesos (Process Hollowing)": re.compile(r'(?:NtUnmapViewOfSection|ZwUnmapViewOfSection)', re.I),
    "Robo de Memoria de Contraseñas de Windows (LSASS Dump)": re.compile(r'(?:sekurlsa::logonpasswords|MiniDumpWriteDump.*lsass|comsvcs\.dll.*MiniDump)', re.I),
    "Bypass de Seguridad / Desactivación de Antivirus": re.compile(r'(?:AmsiScanBuffer.*0x|amsiInitFailed|Set-MpPreference\s+-DisableRealtimeMonitoring)', re.I),
    "Reverse Shell / Puerta Trasera (Backdoor)": re.compile(r'(?:powershell(?:\.exe)?\s+.*-w(?:indowstyle)?\s+hidden|nc\.exe\s+-e\s+cmd|System\.Net\.Sockets\.TCPClient.*GetStream)', re.I),
    "Descarga Silenciosa de Malware (Dropper)": re.compile(r'(?:URLDownloadToFileA|Net\.WebClient.*DownloadFile\(|Net\.WebClient.*DownloadString\(|Start-BitsTransfer.*http)', re.I),
    "Firma de Prueba de Virus Estandarizada (EICAR)": re.compile(r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*')
}

# 3. Patrones de conexiones internas maliciosas (C2, Webhooks de robo de datos, Tor, IPs directas)
PATRONES_CONEXIONES_INTERNAS = {
    "Webhook Exfiltración (Discord / Telegram C2)": re.compile(r'(?:discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+)', re.I),
    "Red Oscura / Túnel Anónimo (.onion / Ngrok / Pastebin Raw)": re.compile(r'(?:[a-z2-7]{16,56}\.onion|[a-z0-9-]+\.ngrok(?:-free)?\.app|pastebin\.com/raw/[A-Za-z0-9]+)', re.I),
    "Dirección IP Externa Incrustada (Hardcoded IP)": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
}

IPS_IGNORADAS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "1.0.0.0", "2.0.0.0",
    "4.0.0.0", "5.1.0.0", "6.0.0.0", "8.8.8.8", "8.8.4.4", "1.1.1.1"
}


class AnalizadorSeguridadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Analizador Profundo de Malware y Conexiones (Anti Falsos Positivos)")
        self.root.geometry("1140x720")
        self.root.configure(padx=15, pady=15)

        self.archivos_detectados = {}
        self.escaneando = False
        self.whitelist_usuario = self.cargar_whitelist()

        # --- ENCABEZADO Y CONTROLES DE CARPETA ---
        frame_top = tk.Frame(self.root)
        frame_top.pack(fill=tk.X, pady=(0, 6))

        tk.Label(frame_top, text="Carpeta a analizar:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)

        self.ruta_var = tk.StringVar(value=os.path.expanduser("~"))
        self.entry_ruta = tk.Entry(frame_top, textvariable=self.ruta_var, width=52, font=("Segoe UI", 10))
        self.entry_ruta.pack(side=tk.LEFT, padx=10)

        tk.Button(frame_top, text="Cambiar Carpeta", command=self.seleccionar_carpeta).pack(side=tk.LEFT, padx=5)
        self.btn_escanear = tk.Button(
            frame_top, text="Iniciar Análisis + SUB-Scan", bg="#005fb8", fg="white",
            font=("Segoe UI", 10, "bold"), padx=10, command=self.iniciar_escaneo
        )
        self.btn_escanear.pack(side=tk.LEFT, padx=5)

        # --- OPCIÓN DE FILTRO DE PROGRAMAS SEGUROS ---
        frame_filtro = tk.Frame(self.root)
        frame_filtro.pack(fill=tk.X, pady=(0, 6))

        self.filtrar_seguros_var = tk.BooleanVar(value=True)
        chk_seguros = tk.Checkbutton(
            frame_filtro,
            text="Proteger programas seguros (Omitir Chrome, Opera GX, Gemini.exe y programas con Firma Digital Oficial verificada)",
            variable=self.filtrar_seguros_var,
            font=("Segoe UI", 9, "bold"), fg="#107c10"
        )
        chk_seguros.pack(side=tk.LEFT)

        # --- BARRA DE PROGRESO Y ESTADO ---
        self.lbl_estado = tk.Label(
            self.root,
            text="Listo para analizar. Filtro inteligente activo contra falsos positivos en navegadores y apps legítimas.",
            anchor="w", fg="#333333", font=("Segoe UI", 9)
        )
        self.lbl_estado.pack(fill=tk.X, pady=(0, 4))

        self.progreso = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode="determinate")
        self.progreso.pack(fill=tk.X, pady=(0, 10))

        # --- PESTAÑAS (APARTADOS): 100% VIRUS O MALWARE vs SOSPECHOSOS ---
        style = ttk.Style()
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[12, 5])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_malware = tk.Frame(self.notebook)
        self.notebook.add(self.tab_malware, text="☣️ 100% Virus o Malware (0)")

        self.tab_sospechosos = tk.Frame(self.notebook)
        self.notebook.add(self.tab_sospechosos, text="⚠️ Archivos Sospechosos / Riesgo Alto (0)")

        self.tree_malware = self.crear_tabla(self.tab_malware)
        self.tree_sospechosos = self.crear_tabla(self.tab_sospechosos)

        # --- PANEL DE DETALLES DEL SUB-SCAN ---
        frame_detalles = tk.LabelFrame(
            self.root, text="Inspector Forense del SUB-Scan (Selecciona un archivo para ver conexiones internas, firma digital y código)",
            font=("Segoe UI", 9, "bold"), padx=8, pady=6
        )
        frame_detalles.pack(fill=tk.X, pady=(10, 5))

        self.txt_detalles = tk.Text(frame_detalles, height=6, font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4", wrap=tk.WORD)
        self.txt_detalles.pack(fill=tk.X)
        self.txt_detalles.insert(tk.END, "Selecciona un archivo de la lista para ver el desglose técnico del SUB-Scan...")
        self.txt_detalles.config(state=tk.DISABLED)

        # --- BOTONES DE ACCIÓN: ELIMINAR, CONSERVAR Y LISTA BLANCA ---
        frame_botones = tk.Frame(self.root)
        frame_botones.pack(fill=tk.X, pady=(10, 0))

        self.btn_eliminar = tk.Button(
            frame_botones,
            text="ELIMINAR (Borrar archivo y cortar conexiones)",
            bg="#d83b01", fg="white", font=("Segoe UI", 10, "bold"),
            padx=15, pady=8, command=self.eliminar_seleccionados
        )
        self.btn_eliminar.pack(side=tk.LEFT, padx=(0, 12))

        self.btn_conservar = tk.Button(
            frame_botones,
            text="CONSERVAR (Mantener archivo en el PC)",
            bg="#107c10", fg="white", font=("Segoe UI", 10, "bold"),
            padx=15, pady=8, command=self.conservar_seleccionados
        )
        self.btn_conservar.pack(side=tk.LEFT, padx=(0, 12))

        self.btn_whitelist = tk.Button(
            frame_botones,
            text="MARCAR COMO 100% SEGURO (No volver a detectar)",
            bg="#005fb8", fg="white", font=("Segoe UI", 9, "bold"),
            padx=12, pady=8, command=self.agregar_a_whitelist_seleccionados
        )
        self.btn_whitelist.pack(side=tk.LEFT)

    def cargar_whitelist(self):
        seguros = set(EJECUTABLES_SEGUROS_POR_DEFECTO)
        if os.path.exists(ARCHIVO_WHITELIST):
            try:
                with open(ARCHIVO_WHITELIST, "r", encoding="utf-8") as f:
                    for linea in f:
                        item = linea.strip().lower()
                        if item:
                            seguros.add(item)
            except Exception:
                pass
        return seguros

    def guardar_en_whitelist(self, nombre_o_ruta):
        item = nombre_o_ruta.strip().lower()
        self.whitelist_usuario.add(item)
        try:
            with open(ARCHIVO_WHITELIST, "a", encoding="utf-8") as f:
                f.write(item + "\n")
        except Exception:
            pass

    def crear_tabla(self, contenedor):
        columnas = ("archivo", "veredicto", "ofuscacion_firmas", "conexiones", "ruta")
        tree = ttk.Treeview(contenedor, columns=columnas, show="headings", selectmode="extended")
        tree.heading("archivo", text="Nombre del Archivo")
        tree.heading("veredicto", text="Nivel / Veredicto SUB-Scan")
        tree.heading("ofuscacion_firmas", text="Código Ofuscado / Firmas de Hacking")
        tree.heading("conexiones", text="Conexiones Internas y de Red")
        tree.heading("ruta", text="Ruta Completa")

        tree.column("archivo", width=155)
        tree.column("veredicto", width=195)
        tree.column("ofuscacion_firmas", width=270)
        tree.column("conexiones", width=220)
        tree.column("ruta", width=250)

        scrollbar = ttk.Scrollbar(contenedor, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tree.bind("<<TreeviewSelect>>", self.mostrar_detalle_subscan)
        return tree

    def seleccionar_carpeta(self):
        carpeta = filedialog.askdirectory(initialdir=self.ruta_var.get())
        if carpeta:
            self.ruta_var.set(carpeta)

    def es_programa_seguro_conocido(self, ruta_completa, nombre_archivo):
        """Verifica si el archivo pertenece a Chrome, Opera GX, Gemini.exe o la Lista Blanca."""
        if not self.filtrar_seguros_var.get():
            return False

        nombre_lower = nombre_archivo.lower()
        ruta_lower = ruta_completa.lower()

        if nombre_lower in self.whitelist_usuario or ruta_lower in self.whitelist_usuario:
            return True

        if any(ruta_segura in ruta_lower for ruta_segura in RUTAS_OFICIALES_SEGURAS):
            return True

        return False

    def verificar_firma_digital_windows(self, ruta_completa):
        """
        Comprueba mediante Authenticode de Windows si el ejecutable tiene una firma digital
        oficial válida (ej: Google LLC, Opera Norway AS, Microsoft Corporation).
        """
        try:
            comando = [
                "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                f"$s = Get-AuthenticodeSignature -LiteralPath '{ruta_completa}'; "
                f"if ($s.Status -eq 'Valid') {{ Write-Output ('VALID|' + $s.SignerCertificate.Subject) }} else {{ Write-Output 'INVALID' }}"
            ]
            proc = subprocess.run(comando, capture_output=True, text=True, timeout=5, creationflags=0x08000000)
            salida = (proc.stdout or "").strip()
            if salida.startswith("VALID|"):
                emisor = salida.split("|", 1)[1]
                return True, emisor
        except Exception:
            pass
        return False, None

    def obtener_procesos_y_conexiones(self):
        conexiones_por_pid = {}
        procesos_activos = {}

        try:
            salida_netstat = subprocess.check_output("netstat -ano", shell=True, text=True, stderr=subprocess.DEVNULL)
            for linea in salida_netstat.splitlines():
                partes = linea.split()
                if len(partes) >= 5 and partes[0] in ("TCP", "UDP"):
                    dir_remota = partes[2]
                    pid = partes[-1]
                    if pid.isdigit() and pid != "0":
                        if pid not in conexiones_por_pid:
                            conexiones_por_pid[pid] = set()
                        if dir_remota not in ("*:*", "0.0.0.0:0", "[::]:0") and not dir_remota.startswith("127.0.0.1"):
                            conexiones_por_pid[pid].add(dir_remota)

            salida_tasklist = subprocess.check_output("tasklist /FO CSV /NH", shell=True, text=True, stderr=subprocess.DEVNULL)
            for linea in salida_tasklist.splitlines():
                partes = [p.strip('"') for p in linea.split('","')]
                if len(partes) >= 2:
                    nombre_proc = partes[0].lower()
                    pid = partes[1]
                    remotas = list(conexiones_por_pid.get(pid, []))
                    if nombre_proc not in procesos_activos:
                        procesos_activos[nombre_proc] = []
                    procesos_activos[nombre_proc].append((pid, remotas))
        except Exception:
            pass

        return procesos_activos

    def calcular_entropia(self, datos_bytes):
        if not datos_bytes:
            return 0.0
        conteo = [0] * 256
        for b in datos_bytes:
            conteo[b] += 1
        longitud = len(datos_bytes)
        entropia = 0.0
        for c in conteo:
            if c > 0:
                p = c / longitud
                entropia -= p * math.log2(p)
        return round(entropia, 2)

    def fase1_evaluar_archivo(self, ruta_completa, nombre_archivo, procesos_activos):
        """FASE 1: Filtra programas legítimos y selecciona candidatos para el SUB-Scan."""
        if self.es_programa_seguro_conocido(ruta_completa, nombre_archivo):
            return None, [], []

        nombre_lower = nombre_archivo.lower()
        ruta_lower = ruta_completa.lower()
        _, ext = os.path.splitext(nombre_lower)

        motivos_fase1 = []

        # 1. Doble extensión engañosa (ej: foto.jpg.exe)
        partes = nombre_lower.split('.')
        if len(partes) > 2:
            penultima_ext = '.' + partes[-2]
            ultima_ext = '.' + partes[-1]
            if penultima_ext in EXTENSIONES_DOCUMENTOS and ultima_ext in EXTENSIONES_RIESGO:
                motivos_fase1.append("Doble extensión engañosa")

        # 2. Ejecutables o scripts en carpetas temporales o de descargas (donde suele caer el malware)
        zonas_criticas = ['appdata\\local\\temp', 'downloads', 'descargas', 'public', 'appdata\\roaming']
        if ext in EXTENSIONES_RIESGO:
            if any(zona in ruta_lower for zona in zonas_criticas):
                motivos_fase1.append(f"Ejecutable/Script en zona sensible ({ext})")
            elif ext in {'.bat', '.cmd', '.vbs', '.ps1', '.scr', '.hta', '.wsf', '.pif'}:
                motivos_fase1.append(f"Script ejecutable ({ext})")

        # 3. Archivo oculto con extensión ejecutable
        try:
            atributos = ctypes.windll.kernel32.GetFileAttributesW(ruta_completa)
            if atributos != -1 and (atributos & 2) and ext in EXTENSIONES_RIESGO:
                motivos_fase1.append("Ejecutable oculto en el sistema")
        except Exception:
            pass

        # 4. Procesos activos desconocidos con conexión de red
        pids_asociados = []
        ips_remotas_vivas = []
        if nombre_lower in procesos_activos:
            for pid, remotas in procesos_activos[nombre_lower]:
                pids_asociados.append(pid)
                ips_remotas_vivas.extend(remotas)
            if ips_remotas_vivas and ext in EXTENSIONES_RIESGO:
                motivos_fase1.append("Proceso activo con conexión a Internet")

        if motivos_fase1:
            return motivos_fase1, pids_asociados, list(set(ips_remotas_vivas))
        return None, [], []

    def ejecutar_sub_scan(self, ruta_completa, nombre_archivo, motivos_fase1, pids, ips_vivas):
        """
        FASE 2 (SUB-SCAN PROFUNDO):
        Analiza cadenas de ataque completas y descarta programas con Firma Digital Oficial válida.
        """
        puntaje = 0
        ofuscaciones = []
        firmas_detectadas = []
        conexiones_internas = []
        sha256_hash = "No disponible"
        entropia = 0.0
        _, ext = os.path.splitext(nombre_archivo.lower())

        if "Doble extensión engañosa" in motivos_fase1:
            puntaje += 50
        if "Ejecutable oculto en el sistema" in motivos_fase1:
            puntaje += 35
        if ips_vivas:
            conexiones_internas.append(f"Conexión activa -> {', '.join(ips_vivas[:3])}")

        try:
            with open(ruta_completa, "rb") as f:
                datos_bytes = f.read(5 * 1024 * 1024)

            if datos_bytes:
                sha256_hash = hashlib.sha256(datos_bytes).hexdigest()
                entropia = self.calcular_entropia(datos_bytes[:512 * 1024])

                texto_ascii = datos_bytes.decode("latin-1", errors="ignore")
                texto_utf16 = datos_bytes.replace(b"\x00", b"").decode("latin-1", errors="ignore")
                texto_combinado = texto_ascii + "\n" + texto_utf16

                # 1. Buscar códigos ofuscados reales
                for nombre_pat, regex in PATRONES_OFUSCACION.items():
                    if regex.search(texto_combinado):
                        ofuscaciones.append(nombre_pat)
                        puntaje += 35

                # 2. Buscar firmas críticas de hacking / malware
                for nombre_firma, regex in FIRMAS_HACKING.items():
                    if regex.search(texto_combinado):
                        firmas_detectadas.append(nombre_firma)
                        puntaje += 70

                # 3. Detección inteligente de Inyección de Procesos (Exige las 3 APIs juntas para no marcar navegadores)
                apis_inyeccion = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
                if all(api in texto_combinado for api in apis_inyeccion):
                    firmas_detectadas.append("Cadena completa de Inyección de Procesos en Memoria")
                    puntaje += 45

                # 4. Detección inteligente de Stealer (Archivo que NO es navegador intentando leer carpetas de Chrome/Opera/Discord)
                rutas_robo_navegadores = ("\\Google\\Chrome\\User Data", "\\Opera Software\\Opera GX Stable", "\\Discord\\Local Storage\\leveldb")
                if any(r.lower() in texto_combinado.lower() for r in rutas_robo_navegadores) and "CryptUnprotectData" in texto_combinado:
                    firmas_detectadas.append("Stealer: Acceso externo a credenciales de Chrome/Opera/Discord")
                    puntaje += 75

                # 5. Buscar conexiones internas maliciosas (Webhooks C2, Tor, IPs directas en scripts)
                for nombre_con, regex in PATRONES_CONEXIONES_INTERNAS.items():
                    hallazgos = regex.findall(texto_combinado)
                    if hallazgos:
                        if "IP Externa" in nombre_con:
                            # Solo penalizar IPs incrustadas si es un script o si ya tiene otros indicios sospechosos
                            ips_filtradas = [
                                ip for ip in set(hallazgos)
                                if ip not in IPS_IGNORADAS and not ip.startswith(("10.", "192.168.", "169.254.", "172."))
                            ]
                            if ips_filtradas and (ext in {'.bat', '.ps1', '.vbs', '.js', '.cmd'} or puntaje >= 35):
                                conexiones_internas.append(f"IPs internas: {', '.join(ips_filtradas[:3])}")
                                puntaje += 30
                        else:
                            muestra = ", ".join(list(set(hallazgos))[:2])
                            conexiones_internas.append(f"{nombre_con}: {muestra[:70]}")
                            puntaje += 80

                # Evaluar entropía alta solo si va acompañada de otro factor de riesgo
                if entropia >= 7.45 and puntaje >= 25:
                    ofuscaciones.append(f"Alta entropía ({entropia}/8.0 - Posible cifrado/packer)")
                    puntaje += 20

        except Exception:
            pass

        # --- FILTRO DEFINITIVO ANTI FALSOS POSITIVOS: VERIFICAR FIRMA DIGITAL OFICIAL ---
        estado_firma = "No firmado digitalmente"
        if puntaje >= 25 and ext in {'.exe', '.dll', '.msi'} and self.filtrar_seguros_var.get():
            es_firmado_valido, emisor = self.verificar_firma_digital_windows(ruta_completa)
            if es_firmado_valido:
                estado_firma = f"Firma Digital Oficial Válida ({emisor[:60]})"
                # Si tiene firma oficial válida y no es un archivo de prueba EICAR ni un script con Webhook malicioso, es seguro
                if not any("EICAR" in f or "Ransomware" in f for f in firmas_detectadas) and not any("Webhook" in c for c in conexiones_internas):
                    return None

        es_100_malware = (
            puntaje >= 70
            or any("EICAR" in f or "Ransomware" in f or "Stealer" in f or "Hollowing" in f for f in firmas_detectadas)
            or any("Webhook" in c or "Red Oscura" in c for c in conexiones_internas)
        )

        # Mostrar únicamente archivos que tengan hallazgos reales
        tiene_alerta_real = (
            es_100_malware
            or puntaje >= 35
            or len(ofuscaciones) > 0
            or len(firmas_detectadas) > 0
            or "Doble extensión engañosa" in motivos_fase1
            or "Ejecutable oculto en el sistema" in motivos_fase1
        )

        if not tiene_alerta_real:
            return None

        veredicto = f"100% MALWARE (Score: {min(puntaje, 100)}%)" if es_100_malware else f"Sospechoso (Riesgo: {min(puntaje, 95)}%)"
        resumen_ofuscacion_firmas = " | ".join(firmas_detectadas + ofuscaciones) if (firmas_detectadas or ofuscaciones) else " | ".join(motivos_fase1)
        resumen_conexiones = " | ".join(conexiones_internas) if conexiones_internas else ("En ejecución (PID: " + ",".join(pids) + ")" if pids else "Sin conexiones maliciosas internas")

        reporte_detallado = (
            f"ARCHIVO: {nombre_archivo}  |  SHA-256: {sha256_hash}\n"
            f"VEREDICTO SUB-SCAN: {veredicto}  |  FIRMA DIGITAL: {estado_firma}  |  ENTROPÍA: {entropia}/8.0\n"
            f"• CÓDIGOS OFUSCADOS: {', '.join(ofuscaciones) if ofuscaciones else 'Ninguno detectado'}\n"
            f"• FIRMAS DE HACKING / MALWARE: {', '.join(firmas_detectadas) if firmas_detectadas else 'Ninguna firma directa'}\n"
            f"• CONEXIONES INTERNAS Y RED: {', '.join(conexiones_internas) if conexiones_internas else 'Sin IPs/Webhooks maliciosos'}"
        )

        return {
            "es_100_malware": es_100_malware,
            "veredicto": veredicto,
            "resumen_ofuscacion_firmas": resumen_ofuscacion_firmas,
            "resumen_conexiones": resumen_conexiones,
            "reporte_detallado": reporte_detallado,
            "ruta": ruta_completa,
            "nombre": nombre_archivo,
            "pids": pids
        }

    def iniciar_escaneo(self):
        if self.escaneando:
            return
        ruta_base = self.ruta_var.get()
        if not os.path.exists(ruta_base):
            messagebox.showerror("Error", "La carpeta seleccionada no existe.")
            return

        self.escaneando = True
        self.btn_escanear.config(state=tk.DISABLED)
        for tree in (self.tree_malware, self.tree_sospechosos):
            for item in tree.get_children():
                tree.delete(item)
        self.archivos_detectados.clear()
        self.actualizar_titulos_pestanas(0, 0)
        self.progreso["value"] = 0

        hilo = threading.Thread(target=self.proceso_escaneo_completo, args=(ruta_base,), daemon=True)
        hilo.start()

    def proceso_escaneo_completo(self, ruta_base):
        self.root.after(0, lambda: self.lbl_estado.config(text="FASE 1/2: Analizando red y filtrando programas seguros (Chrome, Opera GX, Gemini.exe)..."))
        procesos_activos = self.obtener_procesos_y_conexiones()

        candidatos_subscan = []
        total_revisados = 0

        for raiz, dirs, archivos in os.walk(ruta_base):
            raiz_lower = raiz.lower()
            if any(ruta_segura in raiz_lower for ruta_segura in RUTAS_OFICIALES_SEGURAS) and self.filtrar_seguros_var.get():
                continue

            for nombre in archivos:
                total_revisados += 1
                if total_revisados % 300 == 0:
                    self.root.after(0, lambda c=total_revisados, r=raiz: self.lbl_estado.config(
                        text=f"FASE 1/2: {c} archivos revisados... Explorando: {r[:65]}..."
                    ))

                ruta_completa = os.path.join(raiz, nombre)
                motivos, pids, ips_vivas = self.fase1_evaluar_archivo(ruta_completa, nombre, procesos_activos)
                if motivos:
                    candidatos_subscan.append((ruta_completa, nombre, motivos, pids, ips_vivas))

        total_candidatos = len(candidatos_subscan)
        cont_malware = 0
        cont_sospechosos = 0

        for idx, (ruta_completa, nombre, motivos, pids, ips_vivas) in enumerate(candidatos_subscan, start=1):
            porcentaje = int((idx / max(total_candidatos, 1)) * 100)
            self.root.after(0, lambda p=porcentaje, n=nombre, i=idx, t=total_candidatos: (
                self.progreso.configure(value=p),
                self.lbl_estado.config(text=f"FASE 2/2 (SUB-Scan y Firma Digital {i}/{t}): Verificando '{n}'...")
            ))

            resultado = self.ejecutar_sub_scan(ruta_completa, nombre, motivos, pids, ips_vivas)
            if resultado:
                if resultado["es_100_malware"]:
                    cont_malware += 1
                else:
                    cont_sospechosos += 1
                self.root.after(0, self.agregar_resultado_ui, resultado, cont_malware, cont_sospechosos)

        self.root.after(0, lambda: self.finalizar_escaneo(total_revisados, total_candidatos, cont_malware, cont_sospechosos))

    def agregar_resultado_ui(self, res, cont_malware, cont_sospechosos):
        tree_destino = self.tree_malware if res["es_100_malware"] else self.tree_sospechosos
        item_id = tree_destino.insert(
            "", tk.END,
            values=(res["nombre"], res["veredicto"], res["resumen_ofuscacion_firmas"], res["resumen_conexiones"], res["ruta"])
        )
        self.archivos_detectados[item_id] = res
        self.actualizar_titulos_pestanas(cont_malware, cont_sospechosos)

    def actualizar_titulos_pestanas(self, cant_malware, cant_sospechosos):
        self.notebook.tab(self.tab_malware, text=f"☣️ 100% Virus o Malware ({cant_malware})")
        self.notebook.tab(self.tab_sospechosos, text=f"⚠️ Archivos Sospechosos / Riesgo Alto ({cant_sospechosos})")

    def mostrar_detalle_subscan(self, event):
        tree_actual = event.widget
        seleccion = tree_actual.selection()
        if not seleccion:
            return
        item_id = seleccion[0]
        datos = self.archivos_detectados.get(item_id)
        if not datos:
            return

        self.txt_detalles.config(state=tk.NORMAL)
        self.txt_detalles.delete("1.0", tk.END)
        self.txt_detalles.insert(tk.END, datos["reporte_detallado"])
        self.txt_detalles.config(state=tk.DISABLED)

    def finalizar_escaneo(self, total_revisados, total_subscan, cont_malware, cont_sospechosos):
        self.escaneando = False
        self.btn_escanear.config(state=tk.NORMAL)
        self.progreso["value"] = 100
        self.lbl_estado.config(
            text=f"Análisis finalizado: {total_revisados} archivos escaneados | {total_subscan} inspeccionados en SUB-Scan | "
                 f"☣️ 100% Malware: {cont_malware} | ⚠️ Sospechosos: {cont_sospechosos}"
        )
        if cont_malware > 0:
            self.notebook.select(self.tab_malware)
        elif cont_sospechosos > 0:
            self.notebook.select(self.tab_sospechosos)

    def obtener_tabla_activa(self):
        pestana_actual = self.notebook.index(self.notebook.select())
        return self.tree_malware if pestana_actual == 0 else self.tree_sospechosos

    def eliminar_seleccionados(self):
        tree_activo = self.obtener_tabla_activa()
        seleccion = tree_activo.selection()
        if not seleccion:
            messagebox.showwarning("Selección vacía", "Selecciona uno o más archivos en la pestaña actual para eliminarlos.")
            return

        confirmar = messagebox.askyesno(
            "Confirmar eliminación permanente",
            f"¿Estás seguro de que deseas cortar todas las conexiones y ELIMINAR permanentemente {len(seleccion)} archivo(s)?"
        )
        if not confirmar:
            return

        eliminados = 0
        errores = []

        for item_id in seleccion:
            datos = self.archivos_detectados.get(item_id)
            if not datos:
                continue

            ruta = datos["ruta"]
            nombre = datos["nombre"]

            try:
                subprocess.run(f'taskkill /F /IM "{nombre}" /T', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for pid in datos["pids"]:
                    subprocess.run(f'taskkill /F /PID {pid} /T', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                ctypes.windll.kernel32.SetFileAttributesW(ruta, 128)

                if os.path.exists(ruta):
                    os.remove(ruta)

                tree_activo.delete(item_id)
                del self.archivos_detectados[item_id]
                eliminados += 1
            except Exception as e:
                errores.append(f"{nombre}: {str(e)}")

        self.actualizar_contadores_actuales()
        mensaje = f"Se eliminaron {eliminados} archivo(s) y se cortaron sus procesos/conexiones."
        if errores:
            mensaje += "\n\nArchivos que requieren ejecutar como Administrador:\n" + "\n".join(errores[:5])
        messagebox.showinfo("Proceso completado", mensaje)

    def conservar_seleccionados(self):
        tree_activo = self.obtener_tabla_activa()
        seleccion = tree_activo.selection()
        if not seleccion:
            messagebox.showwarning("Selección vacía", "Selecciona uno o más archivos en la pestaña actual para conservar.")
            return

        for item_id in seleccion:
            tree_activo.delete(item_id)
            if item_id in self.archivos_detectados:
                del self.archivos_detectados[item_id]

        self.actualizar_contadores_actuales()
        self.lbl_estado.config(text=f"Se conservaron {len(seleccion)} archivo(s) intactos en tu PC.")

    def agregar_a_whitelist_seleccionados(self):
        tree_activo = self.obtener_tabla_activa()
        seleccion = tree_activo.selection()
        if not seleccion:
            messagebox.showwarning("Selección vacía", "Selecciona uno o más archivos para marcarlos como 100% seguros.")
            return

        agregados = 0
        for item_id in seleccion:
            datos = self.archivos_detectados.get(item_id)
            if datos:
                self.guardar_en_whitelist(datos["nombre"])
                self.guardar_en_whitelist(datos["ruta"])
                tree_activo.delete(item_id)
                del self.archivos_detectados[item_id]
                agregados += 1

        self.actualizar_contadores_actuales()
        messagebox.showinfo(
            "Agregado a Lista Blanca",
            f"Se marcaron {agregados} programa(s) como 100% Seguros en '{ARCHIVO_WHITELIST}'. No volverán a ser detectados en futuros escaneos."
        )

    def actualizar_contadores_actuales(self):
        cant_m = len(self.tree_malware.get_children())
        cant_s = len(self.tree_sospechosos.get_children())
        self.actualizar_titulos_pestanas(cant_m, cant_s)


if __name__ == "__main__":
    root = tk.Tk()
    app = AnalizadorSeguridadApp(root)
    root.mainloop()
