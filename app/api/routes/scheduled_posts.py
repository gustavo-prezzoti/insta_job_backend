from fastapi import APIRouter, Header, HTTPException
from app.models.scheduled_post import UpdateScheduledPostRequest
from app.core.security import get_user_id_from_token
from app.services.auth import get_user_from_db
from app.services.scheduled_posts import (
    get_scheduled_posts, update_scheduled_post, delete_scheduled_post
)

router = APIRouter(prefix="/schedule", tags=["Scheduled Posts"])

@router.get("")
def list_scheduled_posts(jwt_token: str = Header(...)):
    """
    Lista os posts agendados do usuário:
      - Recebe JWT no header
      - Verifica validade do JWT, existência/atividade do usuário no banco
      - Retorna lista de posts agendados para o usuário
    """
    # Verificar JWT
    user_id = get_user_id_from_token(jwt_token)

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Buscar posts agendados do usuário
    return get_scheduled_posts(user_id)

@router.post("/update")
def update_post(request: UpdateScheduledPostRequest, jwt_token: str = Header(...)):
    """
    Atualiza um post agendado:
      - Recebe JWT no header e body com {id, type, schedule_date, caption, hashtags}
      - Verifica validade do JWT, existência/atividade do usuário no banco
      - Verifica se o post agendado pertence ao usuário
      - Atualiza o post agendado com os novos dados
    """
    # Verificar JWT
    user_id = get_user_id_from_token(jwt_token)

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    return update_scheduled_post(
        user_id=user_id,
        post_id=request.id,
        post_type=request.type,
        schedule_date=request.schedule_date,
        caption=request.caption,
        hashtags=request.hashtags
    )

@router.post("/delete")
def delete_post(request: dict, jwt_token: str = Header(...)):
    """
    Exclui um post agendado:
      - Recebe JWT no header e body com {id}
      - Verifica validade do JWT, existência/atividade do usuário no banco
      - Verifica se o post agendado pertence ao usuário
      - Exclui o post agendado
    """
    # Verificar JWT
    user_id = get_user_id_from_token(jwt_token)

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Verificar se o ID do post foi fornecido
    post_id = request.get("id")
    if not post_id:
        raise HTTPException(status_code=400, detail="ID do post não fornecido")

    return delete_scheduled_post(user_id, post_id) 