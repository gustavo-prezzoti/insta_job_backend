from app.core.config import SOAX_USERNAME, SOAX_PASSWORD

def get_user_proxy_url(username=None):
    """
    Obtém uma URL de proxy específica para o usuário.
    
    Args:
        username: Nome de usuário do Instagram (opcional)
        
    Returns:
        URL do proxy formatada ou None
    """
    if not username or not SOAX_USERNAME or not SOAX_PASSWORD:
        return None

    # Substituir caracteres especiais no nome de usuário
    safe_username = username.replace(".", "_").replace("@", "_at_")
    
    # Formato de proxy com nome de usuário incorporado para manter sessão estável
    user_specific = f"{SOAX_USERNAME}-{safe_username}-session:{SOAX_PASSWORD}"
    proxy_url = f"http://{user_specific}@proxy.soax.com:9150"
    
    return proxy_url 