import json
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def clean_for_json(obj):
    """
    Recursively clean an object to make it JSON serializable.
    Handles datetime objects, nested dictionaries and lists.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: clean_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_for_json(i) for i in obj]
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        # For any other type, convert to string
        return str(obj)

def serialize_session_data(session_data):
    """
    Serializa os dados de sessão do Instagram para salvar no banco.
    
    Args:
        session_data: Os dados da sessão para serializar
        
    Returns:
        String JSON serializada
    """
    # Se já for string, retorna como está
    if isinstance(session_data, str):
        return session_data
    
    # Se for dicionário, converte para JSON
    if isinstance(session_data, dict):
        return json.dumps(session_data)
    
    # Outros tipos, tenta converter para string
    return str(session_data)

def deserialize_session_data(session_data):
    """
    Converte dados de sessão do formato armazenado para objeto Python.
    
    Args:
        session_data: Dados da sessão do banco
        
    Returns:
        Dicionário deserializado
    """
    # Se já for dicionário, retorna como está
    if isinstance(session_data, dict):
        return session_data
    
    # Se for string, tenta deserializar como JSON
    if isinstance(session_data, str):
        try:
            return json.loads(session_data)
        except:
            # Se falhar, tenta retornar como string
            return session_data
    
    # Outros tipos, retorna como está
    return session_data 