import re
import requests
from urllib.parse import urlparse

def analyze_html(content):
    issues = []

    if "error" in content:
        return [f"❌ Error al analizar: {content['error']}"]

    if "http://" in content.get('html', ''):
        issues.append("⚠️ Recursos cargados mediante HTTP (no seguro).")

    for script in content.get('scripts', []):
        if script.string and 'eval(' in script.string:
            issues.append("⚠️ Uso inseguro de 'eval()' en scripts.")

    pattern = r"(api[_\-]?key|token|secret)[\s:=]+['\"]?[A-Za-z0-9_\-]{10,}"
    if re.search(pattern, content.get('html', ''), re.IGNORECASE):
        issues.append("⚠️ Posible exposición de credenciales o API keys.")

    return issues if issues else ["✅ No se encontraron vulnerabilidades críticas."]


def analyze_headers(headers):
    issues = []
    if headers is None:
        issues.append("⚠️ No se pudo obtener las cabeceras HTTP.")
        return issues

    security_headers = {
        "Content-Security-Policy": "Ayuda a prevenir ataques XSS.",
        "Strict-Transport-Security": "Forza el uso de HTTPS.",
        "X-Content-Type-Options": "Previene la detección MIME insegura.",
        "X-Frame-Options": "Evita la carga en iframes (clickjacking).",
        "Referrer-Policy": "Controla la información enviada en Referer.",
        "Permissions-Policy": "Controla el acceso a APIs del navegador.",
        "Expect-CT": "Ayuda con problemas de certificados SSL."
    }

    for header, explanation in security_headers.items():
        if header not in headers:
            issues.append(f"⚠️ Cabecera '{header}' ausente. {explanation}")

    return issues


def analyze(html, headers):
    issues = []
    # Análisis HTML
    issues += analyze_html(html)
    # Análisis cabeceras
    issues += analyze_headers(headers)
    return issues


# -------------------------------
# 🔍 NUEVO MÉTODO: analyze_url()
# -------------------------------
def analyze_url(url):
    """
    Analiza una URL directamente:
    - Descarga HTML
    - Analiza cabeceras
    - Detecta patrones maliciosos
    """

    resultado = {
        "url": url,
        "dominio": None,
        "sospechoso": False,
        "detalles": [],
        "html_issues": [],
        "header_issues": []
    }

    parsed = urlparse(url)
    resultado["dominio"] = parsed.netloc

    try:
        response = requests.get(url, timeout=10)
        html = response.text
        headers = response.headers
    except Exception as e:
        resultado["detalles"].append(f"Error al acceder a la URL: {str(e)}")
        resultado["sospechoso"] = True
        return resultado

    # --- Análisis de contenido HTML (reutiliza tus funciones) ---
    html_data = {"html": html, "scripts": []}
    resultado["html_issues"] = analyze_html(html_data)

    # --- Análisis de cabeceras ---
    resultado["header_issues"] = analyze_headers(headers)

    # --- Detección de código malicioso básico ---
    malicious_patterns = [
        r"eval\(",
        r"document\.write\(unescape\(",
        r"atob\(",
        r"fromCharCode",
        r"window\.location\s*=",
        r"base64",
        r"iframe.*?src=.*?http",
        r"fetch\(.+http",
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
            resultado["detalles"].append(f"⚠️ Patrón sospechoso detectado: {pattern}")

    # Si hay hallazgos, marcamos como sospechoso
    if resultado["detalles"] or any("⚠️" in x for x in resultado["html_issues"]):
        resultado["sospechoso"] = True

    return resultado
