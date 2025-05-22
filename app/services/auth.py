from datetime import datetime, timezone
from fastapi import HTTPException
from app.core.postgres import execute_query
from app.core.security import verify_password, hash_password, is_password_hashed, create_jwt_token
from app.core.database import get_user_from_db

def authenticate_user(email: str, password: str):
    """
    Autenticar usuário pelo email e senha
    
    Args:
        email: Email do usuário
        password: Senha do usuário
        
    Returns:
        Dict com informações do usuário e token JWT
        
    Raises:
        HTTPException: Em caso de credenciais inválidas
    """
    # Busca o usuário pelo email
    query = """
    SELECT * FROM kiwify_users
    WHERE email = %s
    """
    params = (email,)
    
    result = execute_query(query, params)

    if not result:
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")

    user = result[0]

    # Verifica se o usuário está ativo
    if not user.get("status", "active"):
         raise HTTPException(status_code=401, detail="Usuário inativo")

    # Verificar a senha
    stored_password = user.get("password", "")

    # Verificar se a senha está armazenada como hash ou texto plano
    if is_password_hashed(stored_password):
        # Senha já está em formato hash, verificar usando bcrypt
        if not verify_password(password, stored_password):
            raise HTTPException(status_code=401, detail="Email ou senha inválidos")
    else:
        # Senha ainda está em texto plano (sistema em migração)
        if password != stored_password:
            raise HTTPException(status_code=401, detail="Email ou senha inválidos")

        # Migrar a senha para formato hash automaticamente
        try:
            hashed_password = hash_password(stored_password)
            query = """
            UPDATE kiwify_users
            SET password = %s
            WHERE id = %s
            """
            params = (hashed_password, user["id"])
            
            execute_query(query, params, fetch=False)
            print(f"Senha migrada para formato hash para usuário ID: {user['id']}")
        except Exception as e:
            # Não interrompe o fluxo se falhar a migração
            print(f"Erro ao migrar senha para hash: {e}")

    # Gerar JWT
    # Verificar se current_plan_id existe antes de acessá-lo
    current_plan_id = user.get("current_plan_id")
    token = create_jwt_token(user["id"], current_plan_id)

    # Atualizar último login
    query = """
    UPDATE kiwify_users
    SET last_login = %s
    WHERE id = %s
    """
    params = (datetime.now(timezone.utc).isoformat(), user["id"])
    
    execute_query(query, params, fetch=False)

    # Verificar se o plano está ativo
    current_plan_start_date = user.get("current_plan_start_date")
    current_plan_end_date = user.get("current_plan_end_date")

    has_active_plan = False
    if current_plan_start_date:
        try:
            start_date = datetime.fromisoformat(str(current_plan_start_date)).date()
            has_active_plan = (datetime.now(timezone.utc).date() >= start_date)
            
            if current_plan_end_date:
                try:
                    end_date = datetime.fromisoformat(str(current_plan_end_date)).date()
                    has_active_plan = has_active_plan and (datetime.now(timezone.utc).date() <= end_date)
                except (ValueError, TypeError):
                    pass
        except (ValueError, TypeError):
            pass

    # get user sessions
    query = """
    SELECT * FROM instagram_sessions
    WHERE user_id = %s
    AND is_active = TRUE
    """
    params = (user["id"],)
    
    sessions = execute_query(query, params)

    return {
        "token": token, 
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("name", ""),
            "sessions": [session["username"] for session in sessions],
            "force_password_change": user.get("force_password_change", False),
            "is_active": user.get("status") == "active",
            "has_subscription": has_active_plan,
            "subscription_end_date": current_plan_end_date
        }
    }

def check_subscription(user, check_if_exists=False):
    """
    Verifica se o usuário tem inscrição ativa.
    
    Args:
        user: Dict com informações do usuário
        check_if_exists: Se True, verifica apenas se existe uma assinatura
        
    Returns:
        Boolean indicando se a assinatura está ativa
    """
    # Se não é necessário verificar se existe e simplesmente não há plano atual, retorna False
    if check_if_exists and not user.get("current_plan_id"):
        return False

    # Se não há data de início, não há inscrição ativa
    if not user.get("current_plan_start_date"):
        return False

    # Inscrição sem fim definido (recorrente) deve estar ativa se já começou
    if not user.get("current_plan_end_date"):
        return datetime.now(timezone.utc).date() >= datetime.fromisoformat(str(user["current_plan_start_date"])).date()

    # Caso contrário, a data atual deve estar entre início e fim
    return (datetime.now(timezone.utc).date() <= datetime.fromisoformat(str(user["current_plan_end_date"])).date() and
            datetime.now(timezone.utc).date() >= datetime.fromisoformat(str(user["current_plan_start_date"])).date()) 