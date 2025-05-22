from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from app.core.postgres import execute_query
from app.services.instagram import publish_to_instagram
from app.services.instagram_graph import publish_to_instagram as graph_publish_to_instagram
from app.services.auth import get_user_from_db
from app.utils.serialization import clean_for_json

def get_scheduled_posts(user_id: int):
    """
    Obtém todos os posts agendados de um usuário.
    
    Args:
        user_id: ID do usuário
        
    Returns:
        Lista de posts agendados
    """
    query = """
    SELECT * FROM instagram_scheduled_posts
    WHERE user_id = %s
    ORDER BY schedule_for ASC
    """
    params = (user_id,)
    
    scheduled_posts = execute_query(query, params)

    # update hour to local time -3 utc (Brazil time)
    for post in scheduled_posts:
        post["schedule_for"] = datetime.fromisoformat(str(post["schedule_for"])) - timedelta(hours=3)
        # Format to display
        post["schedule_for"] = post["schedule_for"].isoformat()

    # Processar os posts para garantir que são JSON serializáveis
    clean_posts = []
    for post in scheduled_posts:
        clean_post = clean_for_json(post)
        clean_posts.append(clean_post)

    return clean_posts

def schedule_post(user_id: int, username: str, post_type: str, schedule_date: str, video_url: str, caption: str, hashtags: str):
    """
    Agenda um post para publicação futura.
    
    Args:
        user_id: ID do usuário
        username: Nome de usuário do Instagram
        post_type: Tipo de post (feed, reel, story)
        schedule_date: Data de agendamento no formato ISO
        video_url: URL do vídeo
        caption: Legenda do post
        hashtags: Hashtags do post
        
    Returns:
        Dict com o status da operação
        
    Raises:
        HTTPException: Em caso de erro no agendamento
    """
    # Verificar se o usuário existe
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Verificar se o usuário tem uma assinatura ativa
    if not user.get("current_plan_start_date"):
        raise HTTPException(status_code=403, detail="Usuário não possui assinatura ativa")

    # Verificar se a data agendada está dentro do período da assinatura
    if user.get("current_plan_end_date"):
        schedule_date_obj = datetime.fromisoformat(schedule_date)
        subscription_end_date = datetime.fromisoformat(str(user["current_plan_end_date"]))

        if schedule_date_obj.date() > subscription_end_date.date():
            raise HTTPException(
                status_code=403,
                detail="A data agendada está após o término da sua assinatura"
            )
    
    # Verificar se existe sessão para o username
    from app.services.instagram import get_instagram_session
    session = get_instagram_session(user_id, username)
    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão do Instagram não encontrada para o usuário {username}")

    # Criar o agendamento
    try:
        current_time = datetime.now(timezone.utc).isoformat()
        
        query = """
        INSERT INTO instagram_scheduled_posts 
        (user_id, caption, tags, schedule_for, type, video_url, status, created_at, updated_at, username)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        params = (
            user_id, caption, hashtags, schedule_date, post_type, video_url, 
            "pendente", current_time, current_time, username
        )
        
        result = execute_query(query, params)
        
        if not result:
            raise HTTPException(status_code=500, detail="Erro ao agendar postagem")
            
        return {"detail": f"Postagem agendada com sucesso para {username} no dia {schedule_date}"}
    except Exception as e:
        print(f"Erro ao agendar post: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao agendar postagem: {str(e)}")

def update_scheduled_post(user_id: int, post_id: str, post_type: str = None, schedule_date: str = None, 
                          caption: str = None, hashtags: str = None):
    """
    Atualiza um post agendado.
    
    Args:
        user_id: ID do usuário
        post_id: ID do post agendado
        post_type: Novo tipo do post (opcional)
        schedule_date: Nova data de agendamento (opcional)
        caption: Nova legenda (opcional)
        hashtags: Novas hashtags (opcional)
        
    Returns:
        Dict com o status da operação
        
    Raises:
        HTTPException: Em caso de erro na atualização
    """
    # Verificar se o post agendado existe e pertence ao usuário
    query = """
    SELECT * FROM instagram_scheduled_posts
    WHERE id = %s AND user_id = %s
    """
    params = (post_id, user_id)
    
    post_response = execute_query(query, params)

    if not post_response:
        raise HTTPException(status_code=404, detail="Post agendado não encontrado ou não pertence ao usuário")

    # Verificar se o usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Preparar dados e parâmetros para atualização
    update_fields = []
    params = []
    
    # Adicionar campos a serem atualizados, se fornecidos
    if post_type is not None:
        if post_type not in ["feed", "reel", "story"]:
            raise HTTPException(status_code=400, detail="Tipo de postagem inválido")
        update_fields.append("type = %s")
        params.append(post_type)

    if schedule_date is not None:
        try:
            # Validar formato da data
            schedule_date_obj = datetime.fromisoformat(schedule_date)

            # Verificar se a data agendada está dentro do período da assinatura
            if user.get("current_plan_end_date") and schedule_date:
                subscription_end_date = datetime.fromisoformat(str(user["current_plan_end_date"]))
                if schedule_date_obj.date() > subscription_end_date.date():
                    raise HTTPException(
                        status_code=403,
                        detail="A data agendada está após o término da sua assinatura"
                    )

            update_fields.append("schedule_for = %s")
            params.append(schedule_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Formato de data inválido. Use o formato ISO 8601")

    if caption is not None:
        update_fields.append("caption = %s")
        params.append(caption)

    if hashtags is not None:
        update_fields.append("tags = %s")
        params.append(hashtags)
    
    # Sempre atualizar updated_at
    update_fields.append("updated_at = %s")
    params.append(datetime.now(timezone.utc).isoformat())
    
    # Adicionar post_id e user_id ao final dos parâmetros para a cláusula WHERE
    params.append(post_id)
    params.append(user_id)

    # Atualizar o post agendado
    try:
        if update_fields:
            query = f"""
            UPDATE instagram_scheduled_posts
            SET {", ".join(update_fields)}
            WHERE id = %s AND user_id = %s
            RETURNING id
            """
            
            result = execute_query(query, params)

            if not result:
                raise HTTPException(status_code=500, detail="Falha ao atualizar o post agendado")

        return {"status": "success", "message": "Post agendado atualizado com sucesso"}
    except Exception as e:
        print(f"Erro ao atualizar post agendado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao atualizar post agendado: {str(e)}")

def delete_scheduled_post(user_id: int, post_id: str):
    """
    Exclui um post agendado.
    
    Args:
        user_id: ID do usuário
        post_id: ID do post agendado
        
    Returns:
        Dict com o status da operação
        
    Raises:
        HTTPException: Em caso de erro na exclusão
    """
    # Verificar se o post agendado existe e pertence ao usuário
    query = """
    SELECT * FROM instagram_scheduled_posts
    WHERE id = %s AND user_id = %s
    """
    params = (post_id, user_id)
    
    post_response = execute_query(query, params)

    if not post_response:
        raise HTTPException(status_code=404, detail="Post agendado não encontrado ou não pertence ao usuário")

    # Excluir o post agendado
    try:
        query = """
        DELETE FROM instagram_scheduled_posts
        WHERE id = %s AND user_id = %s
        RETURNING id
        """
        params = (post_id, user_id)
        
        result = execute_query(query, params)

        if not result:
            raise HTTPException(status_code=500, detail="Falha ao excluir o post agendado")

        return {"status": "success", "message": "Post agendado excluído com sucesso"}
    except Exception as e:
        print(f"Erro ao excluir post agendado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao excluir post agendado: {str(e)}")

def cron_posting():
    """
    A cada 10 minutos:
      - Verifica posts pendentes (status "pendente") agendados entre agora e 10 minutos atrás.
      - Se houver, chama o serviço de postagem e atualiza o status no banco.
    """
    print(f"[CRON] Iniciando rotina de postagem")
    now = datetime.now(timezone.utc)
    ten_minutes_ago = now - timedelta(minutes=11)

    print(f"[CRON] Verificando posts agendados até {now.isoformat()}")
    print(f"[CRON] Verificando posts agendados desde {ten_minutes_ago.isoformat()}")

    query = """
    SELECT * FROM instagram_scheduled_posts
    WHERE schedule_for <= %s
    AND schedule_for >= %s
    AND status = 'pendente'
    """
    params = (now.isoformat(), ten_minutes_ago.isoformat())
    
    posts = execute_query(query, params)

    # update status to "processing" of posts found
    if posts:
        post_ids = [post["id"] for post in posts]
        placeholders = ", ".join(["%s"] * len(post_ids))
        
        # Adicionar updated_at ao final dos parâmetros
        params = post_ids + [datetime.now(timezone.utc).isoformat()]
        
        query = f"""
        UPDATE instagram_scheduled_posts
        SET status = 'processing', updated_at = %s
        WHERE id IN ({placeholders})
        """
        
        execute_query(query, params, fetch=False)
        
        # Process posts
        for post in posts:
            process_post(post)

def process_post(post):
    """
    Processa um post agendado, publicando-o no Instagram.
    
    Args:
        post: Dados do post agendado
    """
    print(f"[CRON] Processando post agendado: {post['id']}")
    
    try:
        # Get session for the username
        from app.services.instagram import get_instagram_session
        session = get_instagram_session(post["user_id"], post["username"])
        
        if not session:
            print(f"[CRON] Sessão não encontrada para {post['username']}")
            update_post_status(post["id"], "error", "Sessão do Instagram não encontrada")
            return
        
        # Check account type to determine which publish method to use
        account_type = session.get("account_type", "instagrapi")
        
        if account_type == "graph_api":
            # Use Graph API publishing
            print(f"[CRON] Publicando com Graph API: {post['id']}")
            result = graph_publish_to_instagram(
                session_data=session["session_data"],
                post_type=post["type"],
                video_url=post["video_url"],
                caption=post["caption"],
                hashtags=post["tags"],
                user_id=post["user_id"],
                username=post["username"],
                schedule_type="schedule",
                session_id=session["id"]
            )
        else:
            # Use legacy instagrapi publishing
            print(f"[CRON] Publicando com instagrapi (deprecated): {post['id']}")
            result = publish_to_instagram(
                session_data=session["session_data"],
                post_type=post["type"],
                video_url=post["video_url"],
                caption=post["caption"],
                hashtags=post["tags"],
                user_id=post["user_id"],
                username=post["username"],
                schedule_type="schedule",
                session_id=session["id"]
            )
        
        # Update post status to published
        update_post_status(post["id"], "published", "Publicado com sucesso")
        print(f"[CRON] Post {post['id']} publicado com sucesso")
        
    except Exception as e:
        error_message = str(e)
        print(f"[CRON] Erro ao processar post {post['id']}: {error_message}")
        update_post_status(post["id"], "error", error_message[:255])  # Limit error message length

def update_post_status(post_id, status, message=None):
    """
    Atualiza o status de um post agendado.
    
    Args:
        post_id: ID do post
        status: Novo status (processing, published, error)
        message: Mensagem opcional (para erros)
    """
    if message:
        query = """
        UPDATE instagram_scheduled_posts
        SET status = %s, error_message = %s, updated_at = %s
        WHERE id = %s
        """
        params = (status, message, datetime.now(timezone.utc).isoformat(), post_id)
    else:
        query = """
        UPDATE instagram_scheduled_posts
        SET status = %s, updated_at = %s
        WHERE id = %s
        """
        params = (status, datetime.now(timezone.utc).isoformat(), post_id)
    
    execute_query(query, params, fetch=False) 