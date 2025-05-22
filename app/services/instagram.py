import json
import os
import tempfile
import uuid
import requests
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from instagrapi import Client
from app.core.postgres import execute_query
from app.core.config import TEMP_DIR
from app.utils.proxy import get_user_proxy_url
from app.utils.serialization import serialize_session_data

def get_instagram_session(user_id: int, username: str):
    """Busca sessão do Instagram para o user_id e usuário informado."""
    query = """
    SELECT * FROM instagram_sessions
    WHERE user_id = %s AND username = %s AND is_active = TRUE
    """
    params = (user_id, username)
    
    result = execute_query(query, params)
    return result[0] if result else None

def get_instagram_sessions(user_id: int):
    """Busca todas as sessões do usuário."""
    query = """
    SELECT * FROM instagram_sessions
    WHERE user_id = %s AND is_active = TRUE
    """
    params = (user_id,)
    
    return execute_query(query, params)

def create_instagram_session(user_id: int, username: str, session_data: dict, status="active"):
    """Cria uma nova sessão do Instagram no banco de dados."""
    try:
        query = """
        INSERT INTO instagram_sessions
        (user_id, username, session_data, status, is_active, expires_at, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """
        
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        created_at = datetime.now(timezone.utc).isoformat()
        updated_at = created_at
        is_active = status == "active"
        
        params = (
            user_id, 
            username, 
            session_data, 
            status, 
            is_active,
            expires_at, 
            created_at, 
            updated_at
        )
        
        result = execute_query(query, params)
        return result[0] if result else None
    except Exception as e:
        print(f"Erro ao criar sessão: {str(e)}")
        return None

def update_instagram_session_status(sessao_id: int, status: str):
    """Atualiza o status de uma sessão do Instagram."""
    try:
        query = """
        UPDATE instagram_sessions
        SET status = %s, is_active = %s, updated_at = %s
        WHERE id = %s
        RETURNING *
        """
        
        updated_at = datetime.now(timezone.utc).isoformat()
        is_active = status == "active"
        
        params = (status, is_active, updated_at, sessao_id)
        
        result = execute_query(query, params)
        return result[0] if result else None
    except Exception as e:
        print(f"Erro ao atualizar sessão: {str(e)}")
        return None

def delete_instagram_session(sessao_id: int):
    """Remove a sessão do banco."""
    query = """
    UPDATE instagram_sessions
    SET is_active = FALSE, updated_at = %s
    WHERE id = %s
    RETURNING *
    """
    
    updated_at = datetime.now(timezone.utc).isoformat()
    params = (updated_at, sessao_id)
    
    result = execute_query(query, params)
    return result[0] if result else None

def validate_instagram_session(session_data: dict, username=None):
    """Tenta carregar a sessão no instagrapi para validar se está ativa."""
    cl = Client()

    # Set proxy with user-specific session if username provided
    user_proxy_url = get_user_proxy_url(username)
    cl.set_proxy(user_proxy_url)
    print(f"Proxy set for session validation: {user_proxy_url}")

    try:
        # Garantir que temos uma sessão em formato string
        if isinstance(session_data, dict):
            # Se já é um dicionário, convertemos para string JSON
            session_str = json.dumps(session_data)
        else:
            # Assumimos que já é uma string
            session_str = session_data

        # Criar arquivo temporário com os dados da sessão
        # Garantir que o diretório TEMP_DIR existe
        os.makedirs(TEMP_DIR, exist_ok=True)

        # Usar um nome de arquivo único no diretório TEMP_DIR em vez do tempfile padrão
        session_filename = f"validate_session_{uuid.uuid4()}.json"
        session_temp_path = os.path.join(TEMP_DIR, session_filename)

        # Escrever os dados da sessão no arquivo temporário
        with open(session_temp_path, 'w') as temp:
            temp.write(session_str)
            temp_path = session_temp_path

        try:
            # Carregar a sessão a partir do arquivo
            cl.load_settings(temp_path)

            # Testar se a sessão é válida
            account = cl.account_info()
            print(f"Sessão validada para usuário: {account.username}")
            is_valid = True
        finally:
            # Garantir que o arquivo temporário seja removido
            if os.path.exists(temp_path):
                os.unlink(temp_path)

            # Reset proxy after use
            cl.set_proxy(None)
            print("Proxy reset after session validation")

        return is_valid

    except Exception as e:
        print(f"Erro ao validar sessão: {e}")
        # Reset proxy even on error
        cl.set_proxy(None)
        print("Proxy reset after session validation error")
        return False

def publish_to_instagram(session_data, post_type, video_url, caption, hashtags, user_id=None, username=None, schedule_type="now", session_id=None):
    """
    Publica conteúdo no Instagram usando uma sessão existente.

    Args:
        session_data: Dados da sessão do Instagram (JSON string ou dict)
        post_type: Tipo de postagem (feed, reel, story)
        video_url: URL do vídeo ou imagem
        caption: Legenda da postagem
        hashtags: Hashtags para a postagem
        user_id: ID do usuário (opcional, para registro da postagem)
        username: Nome de usuário do Instagram (opcional, para registro da postagem)
        schedule_type: Tipo de agendamento (now, schedule)
        session_id: ID da sessão (opcional, para registro da postagem)

    Returns:
        Dict com detalhes da postagem

    Raises:
        HTTPException: Em caso de erro na postagem
    """
    print(f"Publicando no Instagram: {post_type}, {video_url}")
    cl = Client()

    # Set proxy with user-specific session if username provided
    user_proxy_url = get_user_proxy_url(username)
    cl.set_proxy(user_proxy_url)
    print(f"Proxy set for publishing: {user_proxy_url}")

    # Debug para ver o tipo de dados recebido
    print(f"Tipo de session_data recebido: {type(session_data)}")

    try:
        # Garantir que temos uma sessão em formato string
        if isinstance(session_data, dict):
            # Se já é um dicionário, convertemos para string JSON
            session_str = json.dumps(session_data)
        else:
            # Assumimos que já é uma string
            session_str = session_data

        print(f"Carregando sessão a partir de string JSON")

        # Criar arquivo temporário com os dados da sessão
        # Criar diretório temporário se não existir
        os.makedirs(TEMP_DIR, exist_ok=True)

        # Usar um nome de arquivo único no diretório TEMP_DIR em vez do tempfile padrão
        session_filename = f"session_{uuid.uuid4()}.json"
        session_temp_path = os.path.join(TEMP_DIR, session_filename)

        # Escrever os dados da sessão no arquivo temporário
        with open(session_temp_path, 'w') as temp:
            temp.write(session_str)
            temp_path = session_temp_path

        try:
            # Carregar a sessão a partir do arquivo
            print(f"Carregando a partir do arquivo temporário: {temp_path}")
            cl.load_settings(temp_path)

            # Testar se a sessão é válida
            account = cl.account_info()
            print(f"Sessão válida para usuário: {account.username}")

            # Verificar se a URL é remota ou local
            if video_url.startswith(('http://', 'https://')):
                # Baixar o vídeo para um arquivo temporário no diretório 'temporary'
                print(f"Baixando vídeo de URL remota: {video_url}")
                video_temp_path = None
                try:
                    # Criar um nome de arquivo único no diretório 'temporary'
                    video_filename = f"{uuid.uuid4()}.mp4"
                    video_temp_path = os.path.join(TEMP_DIR, video_filename)

                    # Baixar o vídeo
                    response = requests.get(video_url, stream=True)
                    if response.status_code == 200:
                        with open(video_temp_path, 'wb') as video_file:
                            for chunk in response.iter_content(chunk_size=1024*1024):
                                if chunk:
                                    video_file.write(chunk)

                        print(f"Vídeo baixado para: {video_temp_path}")
                        file_size = os.path.getsize(video_temp_path)
                        print(f"Tamanho do arquivo: {file_size} bytes")

                        # Usar o caminho do arquivo baixado
                        video_path = video_temp_path
                    else:
                        raise Exception(f"Falha ao baixar vídeo. Status code: {response.status_code}")
                except Exception as download_err:
                    print(f"Erro ao baixar vídeo: {str(download_err)}")
                    if video_temp_path and os.path.exists(video_temp_path):
                        os.unlink(video_temp_path)
                        print(f"Arquivo temporário de vídeo removido: {video_temp_path}")
                    raise
            else:
                # URL local (caminho do arquivo)
                video_path = video_url
                print(f"Usando caminho de arquivo local: {video_path}")

            # Proceder com a postagem
            if post_type not in ["feed", "reel", "story"]:
                raise HTTPException(status_code=400, detail="Tipo de postagem inválido")

            try:
                print(f"Iniciando upload para {post_type} usando arquivo: {video_path}")

                if post_type == "feed":
                    # Use video_upload for feed videos instead of photo_upload
                    media = cl.video_upload(video_path, caption=caption + "\n\n" + hashtags)
                elif post_type == "reel":
                    # cl.clip_upload is the correct function for reel videos
                    media = cl.clip_upload(video_path, caption=caption + "\n\n" + hashtags)
                elif post_type == "story":
                    # Use video_upload_to_story for story videos
                    media = cl.video_upload_to_story(video_path)

                print(f"Upload concluído com sucesso para {post_type}")

                # Reset proxy after successful upload
                cl.set_proxy(None)
                print("Proxy reset after successful upload")

                # Registrar a postagem no banco de dados
                if user_id and username:
                    # Tenta extrair o ID do post ou URL
                    instagram_post_id = getattr(media, 'id', None)
                    instagram_url = None

                    # Se tivermos um ID, tenta obter a URL
                    if instagram_post_id:
                        if post_type in ["feed", "reel"]:
                            instagram_url = f"https://www.instagram.com/p/{media.code}/"
                        elif post_type == "story":
                            instagram_url = f"https://www.instagram.com/stories/{username}/{instagram_post_id}/"

                    # Salvar no banco de dados
                    post_data = {
                        "user_id": user_id,
                        "session_id": session_id,
                        "username": username,
                        "post_type": post_type,
                        "caption": caption,
                        "hashtags": hashtags,
                        "schedule_type": schedule_type,
                        "instagram_post_id": str(instagram_post_id) if instagram_post_id else None,
                        "instagram_url": instagram_url,
                        "video_url": video_url,
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }

                print(f"Salvando registro de postagem no banco de dados: {post_data}")

                try:
                    query = """
                    INSERT INTO instagram_posts
                    (user_id, session_id, username, post_type, caption, hashtags, schedule_type, instagram_post_id, instagram_url, video_url, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """
                    
                    params = (
                        user_id,
                        session_id,
                        username,
                        post_type,
                        caption,
                        hashtags,
                        schedule_type,
                        str(instagram_post_id) if instagram_post_id else None,
                        instagram_url,
                        video_url,
                        datetime.now(timezone.utc).isoformat()
                    )
                    
                    result = execute_query(query, params)
                    post_id = result[0]['id'] if result else None
                    print(f"Postagem registrada com ID: {post_id if post_id else 'N/A'}")
                except Exception as db_err:
                    print(f"Erro ao salvar postagem no banco de dados: {str(db_err)}")
                    # Não interrompemos o fluxo por causa de erro no registro

                return {"detail": "Post publicado com sucesso", "media": str(media)}
            finally:
                # Limpar arquivo temporário do vídeo se foi baixado
                if video_url.startswith(('http://', 'https://')) and video_path and os.path.exists(video_path):
                    os.unlink(video_path)
                    print(f"Arquivo temporário de vídeo removido: {video_path}")

        finally:
            # Garantir que o arquivo temporário seja removido
            if os.path.exists(session_temp_path):
                os.unlink(session_temp_path)
                print("Arquivo temporário de sessão removido")

            # Reset proxy even if an error occurred
            if hasattr(cl, 'set_proxy'):
                cl.set_proxy(None)
                print("Proxy reset after publishing operation")

    except Exception as e:
        # Reset proxy in case of error
        if hasattr(cl, 'set_proxy'):
            cl.set_proxy(None)
            print("Proxy reset after publishing error")

        print(f"Erro detalhado: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Erro ao processar Instagram: {str(e)}") 