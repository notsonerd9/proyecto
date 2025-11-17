import re

# =========================================================
# ANÁLISIS DE ENCABEZADOS DE SEGURIDAD
# =========================================================

def analyze_headers(headers):
    """
    Analiza los encabezados HTTP en busca de fallos de seguridad comunes.
    """
    issues = []
    
    # Encabezados requeridos (Security Headers)
    required_headers = {
        "Strict-Transport-Security": "HSTS (Fuerza HTTPS)",
        "Content-Security-Policy": "CSP (Mitigación de XSS)",
        "X-Content-Type-Options": "NoSniff (Protección contra MIME Sniffing)",
        "X-Frame-Options": "Clickjacking (Protección contra incrustación)",
        "Referrer-Policy": "RefererLeakage (Control de Referrers)"
    }

    # 1. Verificar encabezados de seguridad faltantes
    for header, purpose in required_headers.items():
        if header not in headers:
            issues.append(f"🚨 Falta el Encabezado: {header}. Riesgo de {purpose}.")
        elif header == "Content-Security-Policy":
            csp_value = headers.get(header, "").lower()
            if 'unsafe-inline' in csp_value or 'unsafe-eval' in csp_value or 'default-src *' in csp_value:
                issues.append("⚠️ CSP Permisivo: El encabezado CSP utiliza 'unsafe-inline', 'unsafe-eval' o 'default-src *', lo que reduce la protección.")
            else:
                issues.append(f"✅ CSP: Encabezado 'Content-Security-Policy' encontrado y configurado.")
    
    # 2. Verificar exposición de información (malas prácticas)
    exposed_headers = ["Server", "X-Powered-By", "Via"]
    for header in exposed_headers:
        if header in headers:
            value = headers[header].strip()
            issues.append(f"⚠️ Riesgo de Información: El encabezado '{header}' expone el software del servidor: {value}.")

    return issues

# =========================================================
# ANÁLISIS DE HTML/JS (MALWARE Y XSS DOM)
# =========================================================

def analyze_html_js(html_content, issues_list):
    """
    Analiza el contenido HTML y JS en busca de malas prácticas o malware simple.
    Modifica 'issues_list' in-place.
    """
    risk_found = False

    # 1. Detección de código malicioso/ofuscado (Malware/Skimming)
    # Patrones para detectar ofuscación o carga dinámica sospechosa
    malware_indicators = ['eval(', 'atob(', 'btoa(', 'fromCharCode(', 'unescape(', 'document.createElement("script")']
    malware_count = 0
    
    for indicator in malware_indicators:
        malware_count += html_content.lower().count(indicator.lower())
            
    if malware_count > 10:
        issues_list.append(f"🚨 ALERTA DE MALWARE (Alto Conteo): Se detectaron {malware_count} funciones de ofuscación de código ('eval', 'atob', etc.).")
        risk_found = True
    elif malware_count > 0:
        issues_list.append(f"⚠️ ALERTA DE MALWARE: Se detectaron {malware_count} funciones de ofuscación o carga dinámica sospechosa.")
    
    # 2. Detección de XSS DOM simple (Mala Práctica)
    # Sinks comunes para XSS basado en DOM.
    xss_sinks = ['innerHTML =', 'outerHTML =', 'document.write', '.href =']
    
    for sink in xss_sinks:
        if sink.lower() in html_content.lower():
            issues_list.append(f"⚠️ Mala Práctica (XSS): Se detectó el uso de '{sink}' o similar. Alto riesgo si no se sanea la entrada.")
            risk_found = True

    # 3. Exposición de información sensible
    comment_pattern = re.compile(r'<!--.*?debug.*?-->|<!--.*?password.*?-->|<!--.*?secret.*?-->', re.IGNORECASE | re.DOTALL)
    if comment_pattern.search(html_content):
        issues_list.append("⚠️ Información expuesta: Se detectaron posibles comentarios de depuración o datos sensibles en el código fuente.")
        
    return risk_found
