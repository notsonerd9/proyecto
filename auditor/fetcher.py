import requests

def fetch_site(url):
    """
    Realiza una petición HTTP GET simple y devuelve el contenido HTML y los encabezados.
    Si hay un error, devuelve None, {}.
    """
    try:
        # Petición con seguimiento de redirecciones activado por defecto
        # Se necesita un User-Agent para evitar ser bloqueado por algunos sitios.
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
        # Asegurarse de que la respuesta sea exitosa (código 200-399)
        response.raise_for_status() 
        return response.text, response.headers
    except requests.exceptions.RequestException as e:
        # En caso de error (timeout, 4xx, 5xx, etc.)
        print(f"Error fetching site: {e}")
        return None, {}
