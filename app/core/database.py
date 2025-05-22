from datetime import datetime, timezone, timedelta
from app.core.postgres import execute_query
import json

def get_user_from_db(user_id: int):
    """
    Verifica se o usuário existe e está ativo no Supabase.
    
    Args:
        user_id: ID do usuário
        
    Returns:
        Dict com informações do usuário ou None se não existir
    """
    query = """
    SELECT * FROM kiwify_users
    WHERE id = %s
    """
    params = (user_id,)
    
    result = execute_query(query, params)
    
    if not result or not result[0].get("status", "active"):
        return None
        
    return result[0]

def get_instagram_session(user_id: int, username: str):
    """
    Busca sessão do Instagram para o user_id e usuário informado.
    
    Args:
        user_id: User ID to look up
        username: Instagram username
        
    Returns:
        Session data dict or None if not found
    """
    query = """
    SELECT * FROM instagram_sessions 
    WHERE user_id = %s AND username = %s AND is_active = TRUE
    """
    params = (user_id, username)
    
    result = execute_query(query, params)
    
    return result[0] if result else None

def get_instagram_sessions(user_id: int):
    """
    Busca todas as sessões do usuário.
    
    Args:
        user_id: User ID to look up
        
    Returns:
        List of session data dicts
    """
    query = """
    SELECT * FROM instagram_sessions 
    WHERE user_id = %s AND is_active = TRUE
    """
    params = (user_id,)
    
    return execute_query(query, params)

def create_instagram_session(user_id: int, username: str, session_data: dict, status="active"):
    """
    Create a new Instagram session
    
    Args:
        user_id: User ID
        username: Instagram username
        session_data: Session data to store
        status: Session status (default "active")
        
    Returns:
        Created session ID or None if error
    """
    try:
        # Converter session_data para string JSON se for dicionário
        if isinstance(session_data, dict):
            session_data_str = json.dumps(session_data)
        else:
            session_data_str = session_data
            
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        created_at = datetime.now(timezone.utc).isoformat()
        updated_at = created_at
        is_active = status == "active"
        
        query = """
        INSERT INTO instagram_sessions 
        (user_id, username, session_data, status, is_active, expires_at, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """
        params = (user_id, username, session_data_str, status, is_active, expires_at, created_at, updated_at)
        
        result = execute_query(query, params)
        
        return result[0] if result else None
    except Exception as e:
        print(f"Erro ao criar sessão: {str(e)}")
        return None

def update_instagram_session_status(sessao_id: int, status: str):
    """
    Update Instagram session status
    
    Args:
        sessao_id: Session ID to update
        status: New status
        
    Returns:
        Updated session data or None if error
    """
    try:
        updated_at = datetime.now(timezone.utc).isoformat()
        is_active = status == "active"
        
        query = """
        UPDATE instagram_sessions 
        SET status = %s, is_active = %s, updated_at = %s
        WHERE id = %s
        RETURNING *
        """
        params = (status, is_active, updated_at, sessao_id)
        
        result = execute_query(query, params)
        
        return result[0] if result else None
    except Exception as e:
        print(f"Erro ao atualizar sessão: {str(e)}")
        return None

def delete_instagram_session(sessao_id: int):
    """
    Remove a sessão do banco (soft delete).
    
    Args:
        sessao_id: Session ID to delete
        
    Returns:
        Deleted session data or None if error
    """
    query = """
    UPDATE instagram_sessions 
    SET is_active = FALSE, updated_at = %s
    WHERE id = %s
    RETURNING *
    """
    params = (datetime.now(timezone.utc).isoformat(), sessao_id)
    
    result = execute_query(query, params)
    
    return result[0] if result else None

def check_subscription(user, check_if_exists=False):
    """
    Verifica se o usuário tem inscrição ativa.
    
    Args:
        user: User data dict
        check_if_exists: If True, also check if subscription exists
        
    Returns:
        True if user has active subscription, False otherwise
    """
    try:
        # Se não é necessário verificar se existe e simplesmente não há plano atual, retorna False
        if check_if_exists and not user.get("current_plan_id"):
            return False

        # Se não há data de início, não há inscrição ativa
        current_plan_start_date = user.get("current_plan_start_date")
        if not current_plan_start_date:
            return False

        try:
            # Converte para date se for datetime
            if isinstance(current_plan_start_date, datetime):
                start_date = current_plan_start_date.date()
            else:
                # Tenta converter de string para datetime
                start_date = datetime.fromisoformat(str(current_plan_start_date)).date()
                
            now_date = datetime.now(timezone.utc).date()
            
            # Inscrição sem fim definido (recorrente) deve estar ativa se já começou
            current_plan_end_date = user.get("current_plan_end_date")
            if not current_plan_end_date:
                return now_date >= start_date
            
            # Caso contrário, a data atual deve estar entre início e fim
            try:
                # Converte para date se for datetime
                if isinstance(current_plan_end_date, datetime):
                    end_date = current_plan_end_date.date()
                else:
                    # Tenta converter de string para datetime
                    end_date = datetime.fromisoformat(str(current_plan_end_date)).date()
                    
                return (now_date <= end_date and now_date >= start_date)
            except (ValueError, TypeError):
                # Se end_date é inválida, consideramos apenas a start_date
                return now_date >= start_date
                
        except (ValueError, TypeError) as e:
            # Se houver erro ao converter datas, consideramos inscrição inválida
            print(f"Erro ao verificar datas de inscrição: {e}")
            return False
            
    except Exception as e:
        print(f"Erro ao verificar inscrição: {e}")
        return False 