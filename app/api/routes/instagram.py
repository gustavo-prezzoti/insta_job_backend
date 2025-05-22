from fastapi import APIRouter, Header, HTTPException, WebSocket, WebSocketDisconnect, Request, File, UploadFile, Form, BackgroundTasks
from app.models.instagram import ConnectRequest, PostRequest, DisconnectRequest
from app.services.instagram import (
    get_instagram_session, get_instagram_sessions, create_instagram_session,
    update_instagram_session_status, delete_instagram_session,
    validate_instagram_session
)
# Import the new publish function from instagram_graph
from app.services.instagram_graph import publish_to_instagram as graph_publish_to_instagram
from app.services.auth import get_user_from_db
from app.core.security import verify_jwt, get_user_id_from_token
from instagrapi import Client
from app.utils.proxy import get_user_proxy_url
from app.utils.serialization import serialize_session_data
from datetime import datetime
import os
import uuid
from typing import Optional

router = APIRouter(prefix="/instagram", tags=["Instagram"])

@router.get("/check-credentials")
def check_instagram_credentials(jwt_token: str = Header(...)):
    """
    Verificar credenciais do Instagram:
      - Recebe apenas o JWT token
      - Verifica validade do JWT, existência/atividade do usuário no banco
      - Busca se existem sessões ativas do Instagram para o usuário
      - Retorna informações sobre as sessões encontradas
    """
    # Verificar JWT
    user_id = get_user_id_from_token(jwt_token)

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Buscar sessões ativas do Instagram
    sessions = get_instagram_sessions(user_id)

    return {
        "has_credentials": len(sessions) > 0,
        "sessions_count": len(sessions),
        "usernames": [session["username"] for session in sessions]
    }

@router.websocket("/connect-ws")
async def connect_instagram_ws(websocket: WebSocket):
    """
    Conexão WebSocket para autenticar no Instagram com suporte a 2FA em tempo real:
      - Estabelece uma conexão WebSocket com o frontend
      - Recebe credenciais do Instagram (username, password, token JWT)
      - Tenta login e se 2FA for necessário, mantém a conexão aberta
      - Solicita código 2FA do frontend e completa a autenticação na mesma sessão
    """
    await websocket.accept()

    cl = Client()
    cl.delay_range = [1, 3]

    try:
        # Recebe as credenciais iniciais
        credentials = await websocket.receive_json()
        username = credentials.get("username")
        password = credentials.get("password")
        jwt_token = credentials.get("token")

        # Set proxy with user-specific session
        user_proxy_url = get_user_proxy_url(username)
        cl.set_proxy(user_proxy_url)
        print(f"Proxy set for WebSocket connection: {user_proxy_url}")

        # Verifica o JWT
        try:
            payload = verify_jwt(jwt_token)
            user_id = payload.get("user_id")
            if not user_id:
                await websocket.send_json({"status": "error", "message": "Usuário inválido no token"})
                cl.set_proxy(None)  # Reset proxy
                return

            user = get_user_from_db(user_id)
            if not user:
                await websocket.send_json({"status": "error", "message": "Usuário não encontrado ou inativo"})
                cl.set_proxy(None)  # Reset proxy
                return
        except Exception as e:
            # Garantir que a mensagem de erro seja segura para JSON
            try:
                error_message = str(e)
                await websocket.send_json({"status": "error", "message": f"Erro de autenticação: {error_message}"})
            except Exception:
                await websocket.send_json({"status": "error", "message": "Erro de autenticação interno"})

            cl.set_proxy(None)  # Reset proxy
            return

        # Verifica se já existe uma sessão ativa
        sessao = get_instagram_session(user_id, username)
        if sessao:
            print(f"Sessão encontrada: {sessao['id']}")
            if validate_instagram_session(sessao["session_data"], username):
                await websocket.send_json({
                    "status": "success",
                    "message": "Sessão válida. Login realizado com sucesso.",
                    "sessao_id": sessao["id"],
                    "username": username
                })
                cl.set_proxy(None)  # Reset proxy
                return
            else:
                delete_instagram_session(sessao["id"])

        # Tenta login no Instagram - Abordagem não bloqueante para 2FA
        try:
            # Iniciar login normal (isso pode lançar ChallengeRequired)
            try:
                # Tentativa inicial de login - pode gerar exceção se 2FA for necessário
                cl.login(username, password)

                # Se chegou aqui, o login foi bem-sucedido sem 2FA
                try:
                    # Obter dados da sessão
                    session_data = cl.get_settings()

                    # Serializá-los de forma segura
                    session_data_safe = serialize_session_data(session_data)

                    # Criar a sessão no banco de dados
                    nova_sessao = create_instagram_session(user_id, username, session_data_safe, status="active")

                    # Informar sucesso ao cliente
                    await websocket.send_json({
                        "status": "success",
                        "message": "Login realizado com sucesso.",
                        "sessao_id": nova_sessao["id"],
                        "username": username
                    })
                except Exception as session_err:
                    print(f"Erro ao processar sessão: {str(session_err)}")
                    await websocket.send_json({"status": "error", "message": "Erro ao salvar sessão do Instagram"})

                cl.set_proxy(None)  # Reset proxy
                return

            except Exception as e:
                # Tentamos extrair informações da exceção com segurança
                error_message = str(e)
                print(f"Exceção no login: {error_message}")

                # Verifica se a exceção é devido à necessidade de 2FA
                if 'challenge_required' in error_message or getattr(cl, 'challenge_required', False):
                    # Informa ao frontend que 2FA é necessário
                    try:
                        challenge_url = getattr(cl, 'challenge_url', None)
                        challenge_info = {"api_path": challenge_url}

                        await websocket.send_json({
                            "status": "2fa_required",
                            "message": "Verificação em duas etapas necessária",
                            "challenge_info": challenge_info
                        })
                    except Exception as ce:
                        print(f"Erro ao enviar challenge info: {str(ce)}")
                        await websocket.send_json({"status": "error", "message": "Erro no processamento de 2FA"})
                        cl.set_proxy(None)  # Reset proxy
                        return

                    # Tentar obter o código de verificação
                    try:
                        cl.challenge_send_code(1)  # 1 = SMS, 0 = Email
                    except Exception as e2:
                        print(f"Erro ao solicitar código 2FA: {str(e2)}")
                        await websocket.send_json({"status": "error", "message": "Erro ao solicitar código 2FA"})
                        cl.set_proxy(None)  # Reset proxy
                        return

                    # Aguarda o código 2FA do frontend
                    try:
                        twofa_data = await websocket.receive_json()
                        twofa_code = twofa_data.get("code")

                        if not twofa_code:
                            await websocket.send_json({"status": "error", "message": "Código 2FA não fornecido"})
                            cl.set_proxy(None)  # Reset proxy
                            return
                    except Exception as re:
                        print(f"Erro ao receber código 2FA: {str(re)}")
                        await websocket.send_json({"status": "error", "message": "Erro ao processar código 2FA"})
                        cl.set_proxy(None)  # Reset proxy
                        return

                    # Tenta resolver o desafio 2FA
                    try:
                        cl.challenge_resolve(twofa_code)

                        if cl.logged_in:
                            # 2FA bem-sucedido
                            try:
                                session_data = cl.get_settings()
                                # Usar nossa nova função para serialização segura
                                session_data_safe = serialize_session_data(session_data)

                                nova_sessao = create_instagram_session(user_id, username, session_data_safe, status="active")
                                await websocket.send_json({
                                    "status": "success",
                                    "message": "Login com 2FA realizado com sucesso.",
                                    "sessao_id": nova_sessao["id"],
                                    "username": username
                                })
                            except Exception as se:
                                print(f"Erro ao salvar sessão após 2FA: {str(se)}")
                                await websocket.send_json({"status": "error", "message": "Erro ao finalizar autenticação 2FA"})
                        else:
                            await websocket.send_json({"status": "error", "message": "Falha na verificação 2FA. Código incorreto ou expirado."})

                        cl.set_proxy(None)  # Reset proxy
                    except Exception as e3:
                        print(f"Erro ao processar 2FA: {str(e3)}")
                        await websocket.send_json({"status": "error", "message": "Erro ao processar a verificação 2FA"})
                        cl.set_proxy(None)  # Reset proxy
                else:
                    # Outro tipo de erro no login
                    try:
                        await websocket.send_json({"status": "error", "message": f"Erro no login: {error_message}"})
                    except Exception:
                        await websocket.send_json({"status": "error", "message": "Erro no login"})

                    cl.set_proxy(None)  # Reset proxy
        except Exception as e:
            print(f"Erro geral no login: {str(e)}")
            await websocket.send_json({"status": "error", "message": "Erro ao processar login"})
            cl.set_proxy(None)  # Reset proxy
    except WebSocketDisconnect:
        print(f"Cliente desconectado")
        cl.set_proxy(None)  # Reset proxy
    except Exception as e:
        print(f"Erro não tratado: {str(e)}")
        try:
            await websocket.send_json({"status": "error", "message": "Erro interno do servidor"})
        except:
            print(f"Erro ao enviar mensagem de erro final")

        cl.set_proxy(None)  # Reset proxy

@router.post("/post")
def post_instagram(request: PostRequest, jwt_token: str = Header(...)):
    """
    Postar no Instagram:
      - Recebe JWT e body com {username, type, when, schedule_date, video_url, caption, hashtags}.
      - Verifica JWT, usuário e existência de sessão ativa.
      - Se when='now', publica imediatamente.
      - Se when='schedule', agenda para postagem futura.
    """
    user_id = get_user_id_from_token(jwt_token)

    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Procurar sessão ativa do usuário
    resp = get_instagram_session(user_id, request.username)
    if not resp:
        raise HTTPException(status_code=404, detail="Sessão ativa não encontrada")
    sessao = resp

    print(f"Sessão ID: {sessao['id']}")
    print(f"Request type: {request.type}, quando: {request.when}")

    if request.when == "schedule":
        # Verificar se o usuário tem uma assinatura ativa
        if not user.get("current_plan_start_date"):
            raise HTTPException(status_code=403, detail="Usuário não possui assinatura ativa")

        # Verificar se a data agendada está dentro do período da assinatura
        if user.get("current_plan_end_date"):
            schedule_date_obj = datetime.fromisoformat(request.schedule_date)
            subscription_end_date = datetime.fromisoformat(user["current_plan_end_date"])

            if schedule_date_obj.date() > subscription_end_date.date():
                raise HTTPException(
                    status_code=403,
                    detail="A data agendada está após o término da sua assinatura"
                )

        # Criar agendamento no banco de dados
        from app.services.scheduled_posts import schedule_post
        return schedule_post(
            user_id=user_id,
            username=request.username,
            post_type=request.type,
            schedule_date=request.schedule_date,
            video_url=request.video_url,
            caption=request.caption,
            hashtags=request.hashtags
        )

    # Caso contrário, publicar imediatamente usando a Graph API
    # Obter os dados da sessão
    session_data = sessao["session_data"]
    account_type = sessao.get("account_type", "instagrapi")

    try:
        # Verificar se é uma sessão da Graph API ou instagrapi
        if account_type == "graph_api":
            # Usar o novo serviço de publicação com Graph API
            result = graph_publish_to_instagram(
                session_data=session_data,
                post_type=request.type,
                video_url=request.video_url,
                caption=request.caption,
                hashtags=request.hashtags,
                user_id=user_id,
                username=request.username,
                schedule_type="now",
                session_id=sessao['id']
            )
        else:
            # Fallback para a implementação antiga com instagrapi (deprecated)
            from app.services.instagram import publish_to_instagram
            print("AVISO: Usando método deprecated de publicação com instagrapi.")
            result = publish_to_instagram(
                session_data=session_data,
                post_type=request.type,
                video_url=request.video_url,
                caption=request.caption,
                hashtags=request.hashtags,
                user_id=user_id,
                username=request.username,
                schedule_type="now",
                session_id=sessao['id']
            )
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao postar: {e}")

@router.post("/disconnect")
def disconnect_instagram(request: DisconnectRequest, jwt_token: str = Header(...)):
    """
    Desconectar do Instagram:
      - Recebe JWT (no header) e body com {username}.
      - Verifica validade do JWT, existência/atividade do usuário no banco.
      - Busca a sessão do Instagram associada ao usuário e username.
      - Marca a sessão como inativa.
      - Retorna confirmação de desconexão.
    """
    # Verificar JWT e obter user_id
    user_id = get_user_id_from_token(jwt_token)

    # Verificar se usuário existe e está ativo
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário não encontrado ou inativo")

    # Buscar sessão ativa do Instagram para o usuário e username
    session = get_instagram_session(user_id, request.username)
    if not session:
        raise HTTPException(
            status_code=400,
            detail=f"Sessão para o usuário Instagram '{request.username}' não encontrada"
        )

    try:
        # Desativar a sessão
        deleted_session = delete_instagram_session(session["id"])

        if not deleted_session:
            raise HTTPException(
                status_code=500,
                detail="Falha ao desconectar conta do Instagram"
            )

        return {
            "status": "success",
            "message": f"Conta do Instagram '{request.username}' desconectada com sucesso",
            "username": request.username
        }
    except Exception as e:
        print(f"Erro ao desconectar Instagram: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao desconectar conta do Instagram: {str(e)}"
        )

@router.post("/publish")
async def publish_to_instagram(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    username: str = Form(...),
    post_type: str = Form(...),  # "feed", "reel", "story"
    when: str = Form(...),  # "now", "schedule"
    caption: str = Form(""),
    hashtags: str = Form(""),
    schedule_date: Optional[str] = Form(None),  # Required if when=schedule
    jwt_token: str = Header(...)
):
    """
    Endpoint unificado para publicar conteúdo no Instagram.
    Aceita o upload de vídeo e todos os metadados da postagem em um único pedido.
    Suporta publicação imediata ou agendada.
    
    Args:
        file: Arquivo de vídeo
        username: Nome de usuário do Instagram
        post_type: Tipo de postagem (feed, reel, story)
        when: Quando publicar (now, schedule)
        caption: Legenda da postagem
        hashtags: Hashtags para a postagem
        schedule_date: Data de agendamento (ISO format, ex: "2023-06-01T10:00:00Z")
        jwt_token: Token JWT do usuário
        
    Returns:
        Status da operação e detalhes
    """
    # Verificar JWT
    user_id = get_user_id_from_token(jwt_token)
    user = get_user_from_db(user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Validar tipo de postagem
    if post_type not in ["feed", "reel", "story"]:
        raise HTTPException(status_code=400, detail="Tipo de postagem inválido. Use feed, reel ou story")
    
    # Validar quando publicar
    if when not in ["now", "schedule"]:
        raise HTTPException(status_code=400, detail="Opção 'when' inválida. Use now ou schedule")
    
    # Se for agendado, validar data
    if when == "schedule" and not schedule_date:
        raise HTTPException(status_code=400, detail="Data de agendamento obrigatória para publicações agendadas")
    
    # Validar formato do arquivo
    if not file.filename.endswith(('.mp4', '.mov', '.avi')):
        raise HTTPException(status_code=400, detail="Formato de arquivo inválido. Use MP4, MOV ou AVI")
    
    # Salvar o arquivo temporariamente
    temp_dir = os.environ.get("TEMP_DIR", "temporary")
    os.makedirs(temp_dir, exist_ok=True)
    
    file_extension = os.path.splitext(file.filename)[1]
    temp_file_name = f"{uuid.uuid4()}{file_extension}"
    temp_file_path = os.path.join(temp_dir, temp_file_name)
    
    try:
        # Salvar o arquivo
        with open(temp_file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Função para excluir o arquivo após o uso
        def remove_temp_file():
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                print(f"Arquivo temporário removido: {temp_file_path}")
        
        # Agendar remoção do arquivo para depois
        background_tasks.add_task(remove_temp_file)
        
        # Criar requisição para o endpoint existente
        post_request = {
            "username": username,
            "type": post_type,
            "when": when,
            "video_url": temp_file_path,
            "caption": caption,
            "hashtags": hashtags
        }
        
        if when == "schedule":
            post_request["schedule_date"] = schedule_date
        
        # Procurar sessão ativa do usuário para o Instagram
        session = get_instagram_session(user_id, username)
        if not session:
            raise HTTPException(status_code=404, detail=f"Sessão ativa não encontrada para {username}")
        
        # Reutilizar lógica existente para publicação
        if when == "now":
            # Publicação imediata
            from app.services.instagram import publish_to_instagram
            account_type = session.get("account_type", "instagrapi")
            
            try:
                if account_type == "graph_api":
                    from app.services.instagram_graph import publish_to_instagram as graph_publish
                    result = graph_publish(
                        session_data=session["session_data"],
                        post_type=post_type,
                        video_url=temp_file_path,
                        caption=caption,
                        hashtags=hashtags,
                        user_id=user_id,
                        username=username,
                        schedule_type="now",
                        session_id=session["id"]
                    )
                else:
                    result = publish_to_instagram(
                        session_data=session["session_data"],
                        post_type=post_type,
                        video_url=temp_file_path,
                        caption=caption,
                        hashtags=hashtags,
                        user_id=user_id,
                        username=username,
                        schedule_type="now",
                        session_id=session["id"]
                    )
                return {
                    "status": "success",
                    "message": "Conteúdo publicado com sucesso",
                    "details": result
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Erro ao publicar: {str(e)}")
        else:
            # Agendamento
            from app.services.scheduled_posts import schedule_post
            try:
                result = schedule_post(
                    user_id=user_id,
                    username=username,
                    post_type=post_type,
                    schedule_date=schedule_date,
                    video_url=temp_file_path,  # Será necessário mover este arquivo para um storage permanente
                    caption=caption,
                    hashtags=hashtags
                )
                return {
                    "status": "success",
                    "message": f"Postagem agendada com sucesso para {schedule_date}",
                    "details": result
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Erro ao agendar: {str(e)}")
    
    except Exception as e:
        # Limpar o arquivo em caso de erro
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        raise HTTPException(status_code=500, detail=f"Erro no processamento: {str(e)}") 