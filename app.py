from flask import Flask, render_template, request
import re
import requests
import time
import random 
from urllib.parse import urlparse
from auditor.analyzer import analyze_headers, analyze_html_js 

app = Flask(__name__)

# =========================================================
# LÓGICA 4: SIMULACIÓN DE ESCANEO DE PUERTOS (NMAP)
# =========================================================

def simular_nmap():
    """
    Simula el escaneo de puertos y la detección de versiones de infraestructura.
    """
    nmap_issues = []
    time.sleep(random.uniform(1, 3)) 

    puertos_comunes = {
        21: "FTP (File Transfer Protocol) - Riesgo: credenciales claras.",
        22: "SSH (Secure Shell) - Versión: OpenSSH 8.2p1. Advertencia si es muy antiguo.",
        80: "HTTP (Web) - Riesgo: Conexión no cifrada detectada.",
        443: "HTTPS (Web) - Servidor: Apache 2.4.41. Requiere revisión de versión.",
        3306: "MySQL - Riesgo: Puerto de base de datos expuesto públicamente."
    }

    puertos_abiertos = random.sample(list(puertos_comunes.keys()), random.randint(3, 5))
    
    nmap_issues.append("--- SIMULACIÓN DE ESCANEO DE PUERTOS (NMAP) ---")
    
    for port in puertos_abiertos:
        desc = puertos_comunes[port]
        
        if port == 80:
            nmap_issues.append(f"🚨 NMAP: Puerto {port} Abierto. {desc}")
        elif port == 3306:
            nmap_issues.append(f"🚨 NMAP: Puerto {port} Abierto. {desc}")
        elif port == 22 and random.choice([True, False]):
            nmap_issues.append(f"⚠️ NMAP: Puerto {port} Abierto. {desc} (Versión de SSH podría ser obsoleta).")
        else:
            nmap_issues.append(f"✅ NMAP: Puerto {port} Abierto. {desc.split(' - ')[0]}.")

    os_detection = random.choice(["Linux Kernel 4.x/5.x", "Windows Server 2016", "FreeBSD"])
    nmap_issues.append(f"⚠️ NMAP: Sistema Operativo detectado (Simulado): {os_detection}.")
    
    return nmap_issues


# =========================================================
# LÓGICA 3: SIMULACIÓN DE HERRAMIENTAS EXTERNAS
# =========================================================

def simular_herramientas_externas():
    """
    Simula la ejecución y combinación de resultados de ZAP, Burp y OpenVAS.
    """
    issues_externas = []
    
    time.sleep(random.uniform(1, 2)) 
    
    if random.choice([True, False]):
        issues_externas.append("🚨 ZAP: Vulnerabilidad XSS Almacenado detectada en el parámetro 'name'.")
    issues_externas.append("⚠️ ZAP: Exposición de encabezados de seguridad (Server, X-Powered-By).")

    time.sleep(random.uniform(1, 2)) 

    if random.choice([True, False]):
        issues_externas.append("🚨 BURP: Inyección SQL (Time-based) confirmada en el formulario de login.")
    issues_externas.append("⚠️ BURP: Cookie sin el atributo Secure o HttpOnly.")

    time.sleep(random.uniform(1, 2)) 
    
    if random.choice([True, False]):
        issues_externas.append("🚨 OpenVAS: Versión obsoleta de OpenSSH detectada en el puerto 22 (CVE-2023-456).")
    issues_externas.append("⚠️ OpenVAS: Puerto no esencial abierto (ej. 3306 - MySQL).")
    
    return issues_externas


# =========================================================
# LÓGICA 1: ANÁLISIS DE PHISHING/MALWARE
# =========================================================

def analizar_phishing(url):
    """
    Realiza una detección rápida de phishing y malware, con análisis de redirección.
    """
    url = url.strip()
    issues = []
    puntuacion_riesgo = 0
    general_status = "Legítima"
    url_lower = url.lower()
    html_to_analyze = ""
    
    # 1 Verificar formato válido
    regex_url = re.compile(
        r'^(?:http|ftp)s?://' 
        r'(?:[\w-]+\.)+[a-z]{2,6}' 
        r'(?:[/?#]\S*)?$', re.IGNORECASE)
    
    # Intenta añadir el esquema si falta, para intentar la conexión
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        issues.append("⚠️ URL: Se asumió 'https://' para la conexión.")

    if not re.match(regex_url, url):
        issues.append("❌ URL: El formato no es válido o incompleto (debe incluir dominio y TLD).")
        return {"general_status": "Error", "issues": issues, "url_analizada": url}

    # 2 Heurísticas de Phishing (Previas a la Conexión)
    indicadores_sospechosos = ["login", "verify", "update", "secure", "bank", "free", "gift", "win"]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_parts = domain.split('.')
    main_domain = domain_parts[-2] if len(domain_parts) >= 2 and domain_parts[-1] else domain_parts[0]

    if len(main_domain) <= 4 and main_domain not in ['www']:
        puntuacion_riesgo += 3 
        issues.append(f"🚨 URL: El dominio principal es extremadamente corto ({len(main_domain)} caracteres), común en phishing.")
    if re.search(r'\d{4}', domain) and 'com' not in domain_parts:
        puntuacion_riesgo += 2
        issues.append("URL: Contiene números consecutivos, simulando fecha o antigüedad (sospechoso).")
    if url.count('.') > 3:
        puntuacion_riesgo += 1
        issues.append("URL: Demasiados subdominios detectados (indicador de phishing).")
    for palabra in indicadores_sospechosos:
        if palabra in url_lower:
            puntuacion_riesgo += 1
            issues.append(f"URL: Contiene la palabra sospechosa '{palabra}'.")
    if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url):
        puntuacion_riesgo += 3 
        issues.append("🚨 URL: Utiliza una dirección IP en lugar de dominio (muy sospechoso).")
    
    # 3 Comprobar respuesta y Redirecciones
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=5, allow_redirects=False, headers=headers) 
        
        if response.is_redirect and response.headers.get('Location'):
            redirect_url = response.headers['Location']
            
            url_domain = urlparse(url).netloc.replace('www.', '')
            redirect_domain = urlparse(redirect_url).netloc.replace('www.', '')
            
            if url_domain == redirect_domain:
                issues.append(f"✅ Redirección normal: Detectada a: {redirect_url}. Es una redirección estándar (ej. sin www o HTTP a HTTPS).")
            else:
                issues.append(f"🚨 REDIRECCIÓN INMEDIATA SOSPECHOSA: Detectada a un dominio distinto: {redirect_url}. Analizando el destino...")
                puntuacion_riesgo += 3 
            
            try:
                dest_response = requests.get(redirect_url, timeout=5, headers=headers)
                html_to_analyze = dest_response.text
                issues.append(f"✅ Se analizó el contenido de la URL de destino: {redirect_url}.")
            except requests.exceptions.RequestException:
                issues.append("⚠️ Conexión: No se pudo acceder a la URL de redirección final.")
        
        elif response.status_code >= 400:
            issues.append(f"⚠️ Servidor: Devolvió un error HTTP {response.status_code}.")
            html_to_analyze = ""
        else:
            html_to_analyze = response.text
            
    except requests.exceptions.RequestException as e:
        issues.append(f"⚠️ Conexión: No se pudo acceder a la URL: {str(e)}.")
        general_status = "Error"
        return {"general_status": general_status, "issues": issues, "url_analizada": url}
    
    # 4 Detección de Código Malicioso Simple (en el HTML obtenido)
    malware_score = 0
    temp_issues = []
    html_js_risk_found = analyze_html_js(html_to_analyze, temp_issues)
    
    for issue in temp_issues:
        if "ALERTA DE MALWARE (Alto Conteo)" in issue:
            malware_score += 4
            issues.append(issue)
        elif "Riesgo" in issue or "Mala Práctica" in issue:
            issues.append(issue)

        
    if malware_score > 0:
        puntuacion_riesgo += malware_score

    # 5 Determinar Estado Final 
    if puntuacion_riesgo >= 5: 
        general_status = "Peligro"
    elif puntuacion_riesgo >= 2:
        general_status = "Sospechosa"
    
    return {"general_status": general_status, "issues": issues, "url_analizada": url, "tipo_auditoria": "phishing"}


# =========================================================
# LÓGICA 2: ANÁLISIS DE VULNERABILIDADES (PROFUNDA)
# =========================================================

def analizar_seguridad_profunda(url, tipo_auditoria="simple"):
    """
    Realiza un análisis profundo de vulnerabilidades.
    Si tipo_auditoria es 'completa', incluye la simulación de herramientas externas.
    """
    url = url.strip()
    issues = []
    
    regex_url = re.compile(r'^(?:http|ftp)s?://.*$', re.IGNORECASE)

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        issues.append("⚠️ URL: Se asumió 'https://' para la conexión.")


    if not re.match(regex_url, url):
        issues.append("❌ URL: El formato no es válido (falta dominio o es incorrecto).")
        return {"general_status": "Error", "issues": issues, "url_analizada": url, "tipo_auditoria": tipo_auditoria}

    try:
        # 1. Obtener HTML y Headers (SIGUIENDO REDIRECCIONES)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
        html = response.text
        response_headers = response.headers
        final_url = response.url
        
        # 2. Informar sobre redirecciones
        if response.history:
            issues.append(f"⚠️ Redirección: La URL inicial redirigió {len(response.history)} vez(ces).")
            
            if urlparse(url).netloc != urlparse(final_url).netloc:
                issues.append("🚨 ALERTA DOMINIO: La redirección finalizó en un dominio diferente. Se analiza: " + final_url)
            else:
                issues.append("✅ Redirección Dominios: Se mantuvo en el mismo dominio o subdominio. Se analiza: " + final_url)

    except requests.exceptions.RequestException as e:
        issues.append(f"⚠️ Conexión: Error al intentar conectar con el sitio: {str(e)}")
        return {"general_status": "Error", "issues": issues, "url_analizada": url, "tipo_auditoria": tipo_auditoria}

    # 3. Análisis de Encabezados (usando el módulo unificado)
    header_issues = analyze_headers(response_headers)
    issues.extend(header_issues)

    # 4. Análisis de HTML y JS (USANDO EL MÓDULO UNIFICADO)
    html_js_risk_found = analyze_html_js(html, issues)
    
    # 5. Ejecutar Simulación de Herramientas Externas si es Completa
    if tipo_auditoria == "completa":
        issues_externas = simular_herramientas_externas()
        issues.append("--- RESULTADOS DE AUDITORÍA DE APLICACIÓN WEB (ZAP + BURP + OPENVAS) ---")
        issues.extend(issues_externas)
        
        issues_nmap = simular_nmap()
        issues.append("--- SIMULACIÓN DE ESCANEO DE PUERTOS (NMAP) ---")
        issues.extend(issues_nmap)


    # 6. Determinar Estado Final
    is_risky = any("Riesgo" in i or "Falta" in i or html_js_risk_found or "NMAP: Puerto" in i or "ALERTA DE MALWARE" in i for i in issues)
    
    if is_risky:
        general_status = "Con Riesgos"
        issues.insert(0, "🚨 Resumen: Se detectaron fallos de seguridad en la configuración, encabezados, infraestructura o código fuente (HTML/JS).")
    else:
        general_status = "Seguro (Aparentemente)"
        issues.insert(0, "✅ Resumen: El sitio parece estar configurado correctamente y el código fuente no muestra vulnerabilidades obvias.")
        
    return {"general_status": general_status, "issues": issues, "url_analizada": final_url, "tipo_auditoria": tipo_auditoria}


# =========================================================
# RUTAS DE FLASK
# =========================================================

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/auditar', methods=['POST'])
def auditar():
    url = request.form.get('url_auditoria')
    tipo = request.form.get('tipo_auditoria', 'simple') 
    resultados = analizar_seguridad_profunda(url, tipo)
    return render_template('report.html', resultados=resultados)

@app.route('/analizar', methods=['POST'])
def analizar():
    url = request.form.get('url_analizar')
    resultados = analizar_phishing(url)
    return render_template('report.html', resultados=resultados)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
