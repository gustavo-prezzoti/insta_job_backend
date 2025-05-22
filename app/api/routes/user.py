from fastapi import APIRouter, Header, HTTPException
from datetime import datetime, timezone
from app.models.user import PasswordUpdateRequest, ForcePasswordUpdateRequest, UserUpdateRequest, UserResponse
from app.services.auth import get_user_from_db, check_subscription
from app.core.security import verify_jwt, verify_password, hash_password
from app.core.postgres import execute_query

router = APIRouter(prefix="/user", tags=["User"])

@router.get("", response_model=UserResponse)
def get_user(jwt_token: str = Header(...)):
    """
    Obter informações do usuário:
      - Recebe JWT (no header).
      - Verifica validade do JWT, existência/atividade do usuário no banco.
      - Retorna as informações do usuário.
    """
    try:
        payload = verify_jwt(jwt_token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Usuário inválido no token")

        user = get_user_from_db(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

        # get user session
        sessions_response = execute_query("SELECT username FROM instagram_sessions WHERE user_id = %s AND is_active = TRUE", [user_id])
        
        sessions = sessions_response if sessions_response else []

        # update last login date
        execute_query("UPDATE kiwify_users SET last_login = %s WHERE id = %s", [datetime.now(timezone.utc).isoformat(), user_id], fetch=False)

        # Verificar se tem assinatura ativa
        has_subscription = check_subscription(user)
        
        # Garantir que current_plan_end_date seja uma string
        subscription_end_date = user.get("current_plan_end_date")
        if subscription_end_date and not isinstance(subscription_end_date, str):
            try:
                subscription_end_date = subscription_end_date.isoformat()
            except AttributeError:
                # Se não puder converter para isoformat, converte para string
                subscription_end_date = str(subscription_end_date)

        return {
            "id": str(user["id"]),  # Converter para string para garantir compatibilidade com UUID
            "email": user.get("email", ""),
            "name": user.get("name", ""),
            "sessions": [session.get("username", "") for session in sessions],
            "force_password_change": user.get("force_password_change", False),
            "is_active": user.get("status") == "active",
            "has_subscription": has_subscription,
            "subscription_end_date": subscription_end_date
        }
    except Exception as e:
        print(f"Erro ao obter informações do usuário: {e}")
        raise HTTPException(status_code=500, detail="Erro ao obter informações do usuário")

@router.post("/update-password")
def update_password(request: PasswordUpdateRequest, jwt_token: str = Header(...)):
    """
    Atualizar senha do usuário:
      - Recebe JWT (no header) e body com {current_password, new_password, confirm_password}.
      - Verifica validade do JWT, existência/atividade do usuário no banco.
      - Valida a senha atual do usuário.
      - Verifica se a nova senha e a confirmação são iguais.
      - Atualiza a senha do usuário no banco de dados.
    """
    # Verificar JWT e obter user_id
    payload = verify_jwt(jwt_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuário inválido no token")

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Verificar a senha atual
    stored_password = user.get("password", "")

    if not verify_password(request.current_password, stored_password):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")

    # Verificar se a nova senha e a confirmação são iguais
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Nova senha e confirmação não conferem")

    # Verificar requisitos mínimos de segurança para a nova senha
    if len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 6 caracteres")

    try:
        # Criar hash da nova senha
        hashed_password = hash_password(request.new_password)

        update_data = {
            "password": hashed_password,
            "force_password_change": False,  # Resetar flag caso esteja ativa
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

        # Atualizar no banco de dados
        execute_query("UPDATE kiwify_users SET password = %s, force_password_change = %s, updated_at = %s WHERE id = %s", [update_data["password"], update_data["force_password_change"], update_data["updated_at"], user_id])

        return {"status": "success", "message": "Senha atualizada com sucesso"}
    except Exception as e:
        print(f"Erro ao atualizar senha: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao atualizar senha")

@router.post("/force-change-password")
def force_change_password(request: ForcePasswordUpdateRequest, jwt_token: str = Header(...)):
    """
    Atualizar senha do usuário quando a alteração é obrigatória:
      - Recebe JWT (no header) e body com {current_password, new_password}.
      - Verifica validade do JWT, existência/atividade do usuário no banco.
      - Verifica se o usuário possui a flag force_password_change=True.
      - Valida a senha atual do usuário.
      - Atualiza a senha do usuário no banco de dados e reseta a flag force_password_change.
    """
    # Verificar JWT e obter user_id
    payload = verify_jwt(jwt_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuário inválido no token")

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Verificar se o usuário está marcado para alteração obrigatória de senha
    if not user.get("force_password_change", False):
        raise HTTPException(status_code=403, detail="Alteração de senha não obrigatória para este usuário")

    # Verificar requisitos mínimos de segurança para a nova senha
    if len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 6 caracteres")

    stored_password = user.get("password", "")

    if not verify_password(request.current_password, stored_password):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")

    try:
        # Criar hash da nova senha
        hashed_password = hash_password(request.new_password)

        update_data = {
            "password": hashed_password,
            "force_password_change": False,  # Resetar a flag de alteração obrigatória
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

        # Atualizar no banco de dados
        execute_query("UPDATE kiwify_users SET password = %s, force_password_change = %s, updated_at = %s WHERE id = %s", [update_data["password"], update_data["force_password_change"], update_data["updated_at"], user_id])

        return {"status": "success", "message": "Senha atualizada com sucesso"}
    except Exception as e:
        print(f"Erro ao atualizar senha: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao atualizar senha")

@router.post("/update")
def update_user(request: UserUpdateRequest, jwt_token: str = Header(...)):
    """
    Atualizar informações do usuário:
      - Recebe JWT (no header) e body com {name, current_password, new_password}.
      - Verifica validade do JWT, existência/atividade do usuário no banco.
      - Atualiza o nome do usuário se fornecido.
      - Se current_password e new_password forem fornecidos, valida a senha atual
        e atualiza para a nova senha.
      - Atualiza as informações do usuário no banco de dados.
    """
    # Verificar JWT e obter user_id
    payload = verify_jwt(jwt_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuário inválido no token")

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Preparar dados para atualização
    update_data = {
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    # Atualizar nome se fornecido
    if request.name is not None:
        update_data["name"] = request.name

    # Processar atualização de senha se fornecida
    if request.new_password is not None and request.current_password != "":
        # Verificar se a senha atual foi fornecida
        if not request.current_password:
            raise HTTPException(
                status_code=400,
                detail="Senha atual é obrigatória para atualizar a senha"
            )

        # Verificar a senha atual
        stored_password = user.get("password", "")
        if not verify_password(request.current_password, stored_password):
            raise HTTPException(status_code=400, detail="Senha atual incorreta")

        # Verificar requisitos mínimos de segurança para a nova senha
        if len(request.new_password) < 6:
            raise HTTPException(
                status_code=400,
                detail="A nova senha deve ter pelo menos 6 caracteres"
            )

        # Criar hash da nova senha
        update_data["password"] = hash_password(request.new_password)

    # Se não há dados para atualizar, retornar erro
    if len(update_data) <= 1:  # Apenas updated_at está presente
        raise HTTPException(
            status_code=400,
            detail="Nenhum dado fornecido para atualização"
        )

    try:
        # Atualizar no banco de dados
        execute_query("UPDATE kiwify_users SET name = %s, password = %s, updated_at = %s WHERE id = %s", [update_data["name"], update_data["password"], update_data["updated_at"], user_id])

        # Obter usuário atualizado para resposta
        updated_user = get_user_from_db(user_id)

        return {
            "status": "success",
            "message": "Informações do usuário atualizadas com sucesso",
            "user": {
                "id": str(updated_user["id"]),
                "email": updated_user.get("email", ""),
                "name": updated_user.get("name", "")
            }
        }
    except Exception as e:
        print(f"Erro ao atualizar usuário: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao atualizar informações do usuário") 