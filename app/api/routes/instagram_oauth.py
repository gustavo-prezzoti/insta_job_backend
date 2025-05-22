from fastapi import APIRouter, Header, HTTPException, Request, Depends, Response
from fastapi.responses import RedirectResponse, PlainTextResponse
import os
import requests
from datetime import datetime, timezone
import json
import time

from app.core.security import get_user_id_from_token, get_current_user
from app.models.instagram_graph import InstagramAuthRequest, InstagramAuthResponse
from app.services.instagram_graph import (
    generate_instagram_auth_url, 
    exchange_code_for_token, 
    get_user_accounts,
    create_instagram_session,
    exchange_code_for_token_instagram
)
from app.core.postgres import execute_query
from app.core.config import WEBHOOK_SECRET_TOKEN, DOMAIN, INSTAGRAM_REDIRECT_URI
from app.core.logger import instagram_logger

router = APIRouter(prefix="/instagram/oauth", tags=["Instagram OAuth"])

# Define a constant for verification or use the one from config
INSTAGRAM_VERIFY_TOKEN = "meatyhamhock"  # You should replace this with your actual verify token

def get_instagram_user_info(access_token: str) -> dict:
    """
    Get Instagram user information using the access token.
    
    Args:
        access_token: Instagram access token
        
    Returns:
        Dictionary with user information including username
    """
    try:
        # Make request to Instagram API to get user info
        url = "https://graph.instagram.com/me"
        params = {
            "fields": "id,username",
            "access_token": access_token
        }
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[INSTAGRAM_OAUTH] Error getting user info: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"[INSTAGRAM_OAUTH] Response content: {e.response.text}")
        raise HTTPException(status_code=400, detail=f"Failed to get user info: {str(e)}")

@router.post("/auth", response_model=InstagramAuthResponse)
def authorize_instagram(request: InstagramAuthRequest, req: Request, jwt_token: str = Header(None, alias="jwt_token")):
    """
    Inicia o fluxo de autorização OAuth para o Instagram Graph API
    Gera uma URL para redirecionamento do usuário para autorização
    """
    # Verificar JWT
    user_id = get_user_id_from_token(req, jwt_token)
    user = get_current_user(req, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Gerar URL de autorização
    try:
        # Usar o redirect_uri informado pelo frontend ou o padrão
        redirect_uri = request.redirect_uri or INSTAGRAM_REDIRECT_URI
        auth_url = generate_instagram_auth_url(redirect_uri)
        
        # Retornar tanto a URL quanto o redirect_uri para o frontend poder enviar de volta depois
        return {"auth_url": auth_url, "redirect_uri": redirect_uri}
    except Exception as e: 
        raise HTTPException(status_code=500, detail=f"Erro ao iniciar autorização: {str(e)}")

@router.get("/auth-url", response_model=InstagramAuthResponse)
def get_instagram_auth_url(): 
    """
    Retorna a URL de autorização do Instagram Business Login (novo fluxo).
    """
    auth_url = generate_instagram_auth_url()
    return {"auth_url": auth_url}

@router.get("/callback")
async def oauth_callback(request: Request):
    """
    Callback para OAuth do Instagram que recebe o código de autorização.
    Suporta o novo fluxo Instagram Business Login.
    """
    params = dict(request.query_params)
    hub_mode = params.get('hub.mode')
    hub_challenge = params.get('hub.challenge')
    hub_verify_token = params.get('hub.verify_token')

    if hub_mode and hub_challenge:
        print(f"Recebendo verificação de webhook: mode={hub_mode}, challenge={hub_challenge}, token={hub_verify_token}")
        if hub_verify_token == INSTAGRAM_VERIFY_TOKEN:
            print(f"Token verificado com sucesso. Retornando challenge: {hub_challenge}")
            return PlainTextResponse(content=hub_challenge)
        else:
            print(f"Aviso: token recebido ({hub_verify_token}) diferente do esperado, mas aceitando mesmo assim")
            return PlainTextResponse(content=hub_challenge)

    code = params.get('code')
    state = params.get('state')

    if not code:
        return RedirectResponse(url="/error?message=No authorization code received")

    try:
        # Novo fluxo: trocar code por access_token usando endpoint oficial Instagram
        token_data = exchange_code_for_token_instagram(code)
        # Para teste, retornar o token JSON diretamente
        return token_data
        # Em produção, redirecione para o frontend:
        # frontend_url = os.environ.get("FRONTEND_URL", "https://viralyx.ai")
        # return RedirectResponse(url=f"{frontend_url}/instagram/callback?code={code}")
    except Exception as e:
        print(f"Error in OAuth callback: {str(e)}")
        return RedirectResponse(url=f"/error?message=Authentication failed: {str(e)}")

@router.post("/complete")
@router.get("/complete")
async def complete_oauth(request: Request, jwt_token: str = Header(None, alias="jwt_token"), data: dict = None):
    """
    Completa o fluxo OAuth com o código temporário recebido.
    Aceita tanto requisições GET quanto POST.
    No GET, o temp_code vem da query string.
    No POST, o temp_code vem do corpo da requisição.
    """
    print(f"[INSTAGRAM_OAUTH] Recebida requisição para /complete - Método: {request.method}")
    
    # Verificar JWT
    try:
        user_id = get_user_id_from_token(request, jwt_token)
        user = get_current_user(request, jwt_token)
        print(f"[INSTAGRAM_OAUTH] JWT válido, user_id: {user_id}")
    except Exception as e:
        print(f"[INSTAGRAM_OAUTH] ERRO na validação do JWT: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Erro de autenticação: {str(e)}")
    
    if not user:
        print(f"[INSTAGRAM_OAUTH] Usuário não encontrado ou inativo: {user_id}")
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Extrair dados baseados no método da requisição
    temp_code = None
    redirect_uri = None
    
    # Se for GET, pegar da query string
    if request.method == "GET":
        temp_code = request.query_params.get("temp_code")
        redirect_uri = request.query_params.get("redirect_uri")
        print(f"[INSTAGRAM_OAUTH] Método GET, temp_code da query string: {temp_code}")
        print(f"[INSTAGRAM_OAUTH] Método GET, redirect_uri da query string: {redirect_uri}")
    # Se for POST, pegar do corpo da requisição
    elif data:
        temp_code = data.get("temp_code")
        redirect_uri = data.get("redirect_uri")
        print(f"[INSTAGRAM_OAUTH] Método POST, temp_code do corpo: {temp_code}")
        print(f"[INSTAGRAM_OAUTH] Método POST, redirect_uri do corpo: {redirect_uri}")
        print(f"[INSTAGRAM_OAUTH] Dados completos recebidos: {data}")
    
    if not temp_code:
        print(f"[INSTAGRAM_OAUTH] ERRO: temp_code não fornecido")
        raise HTTPException(status_code=400, detail="Código de autorização temporário não fornecido")
    
    # Se não for fornecido um redirect_uri, usar o padrão
    if not redirect_uri:
        try:
            from app.core.config import INSTAGRAM_REDIRECT_URI as default_redirect
            redirect_uri = default_redirect
        except ImportError:
            # Valor padrão como fallback se não conseguir importar
            redirect_uri = "http://localhost:8081/instagram/oauth/callback"
        print(f"[INSTAGRAM_OAUTH] Nenhum redirect_uri fornecido, usando o padrão: {redirect_uri}")
    
    try:
        print(f"[INSTAGRAM_OAUTH] Trocando código por token de acesso usando redirect_uri: {redirect_uri}")
        # Obter token de acesso, passando o mesmo redirect_uri usado na autorização
        token_data = exchange_code_for_token(temp_code, redirect_uri)
        
        # Verificar se temos access_token no formato esperado
        if "access_token" not in token_data:
            print(f"[INSTAGRAM_OAUTH] ERRO: Formato inesperado de token_data: {token_data}")
            raise HTTPException(status_code=400, detail="Formato de token inesperado na resposta do Instagram")
            
        # Usar o token para obter contas do Instagram
        access_token = token_data["access_token"]
        
        # Get user info including username
        user_info = get_instagram_user_info(access_token)
        user_id_instagram = user_info.get("id")
        username = user_info.get("username")
        
        if not username:
            print(f"[INSTAGRAM_OAUTH] ERRO: Não foi possível obter o username do Instagram")
            raise HTTPException(status_code=400, detail="Não foi possível obter o username do Instagram")
            
        print(f"[INSTAGRAM_OAUTH] Buscando contas do Instagram usando token...")
        # Como é o endpoint básico do Instagram, devemos usar apenas uma conta - a do usuário que autorizou
        instagram_accounts = [{
            "id": user_id_instagram,
            "username": username,
            "page_id": user_id_instagram,  # Usar o mesmo ID como page_id (simplificação)
            "page_access_token": access_token
        }]
        print(f"[INSTAGRAM_OAUTH] Conta Instagram encontrada: {instagram_accounts}")
        
        # Para cada conta, criar uma sessão no banco de dados
        print(f"[INSTAGRAM_OAUTH] Criando sessões para as contas...")
        sessions = []
        for i, account in enumerate(instagram_accounts):
            print(f"[INSTAGRAM_OAUTH] Processando conta {i+1}/{len(instagram_accounts)}: {account.get('username', 'desconhecido')}")
            session = create_instagram_session(user_id, account, token_data)
            if session:
                sessions.append({
                    "id": session["id"],
                    "username": session["username"]
                })
                print(f"[INSTAGRAM_OAUTH] Sessão criada com sucesso para: {session['username']}")
        
        print(f"[INSTAGRAM_OAUTH] Processo concluído com sucesso. Total de sessões: {len(sessions)}")
        return {
            "status": "success",
            "message": "Instagram connected successfully",
            "accounts": sessions
        }
        
    except Exception as e:
        import traceback
        print(f"[INSTAGRAM_OAUTH] ERRO ao processar código: {str(e)}")
        print(f"[INSTAGRAM_OAUTH] Traceback completo: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"Erro ao conectar Instagram: {str(e)}")

@router.post("/webhook")
async def instagram_webhook(request: Request):
    """
    Endpoint para receber webhooks do Instagram
    """
    # Obter corpo da requisição como JSON ou texto
    try:
        body = await request.json()
    except:
        body = await request.body()
    
    print(f"Recebido webhook do Instagram: {body}")
    
    # Processar o webhook aqui...
    
    # Resposta de sucesso para o Instagram
    return Response(status_code=200)

@router.post("/process-code")
async def process_auth_code(request: Request, body: dict = None, jwt_token: str = Header(None, alias="jwt_token")):
    """
    Endpoint para processar o código de autorização após o redirecionamento do Instagram.
    O frontend deve chamar este endpoint com o código temporário recebido na página de sucesso.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Obter o código temporário do corpo da requisição
    temp_code = (body or {}).get("code") if body else None
    if not temp_code:
        raise HTTPException(status_code=400, detail="Código de autorização não fornecido")
    
    try:
        # Obter token de acesso
        token_data = exchange_code_for_token(temp_code)
        
        # Obter contas do Instagram
        instagram_accounts = get_user_accounts(token_data["access_token"])
        
        # Se não houver contas, retornar erro
        if not instagram_accounts:
            raise HTTPException(
                status_code=400, 
                detail="Nenhuma conta de Instagram Business encontrada. Certifique-se de que sua conta está conectada a uma página do Facebook e configurada como conta comercial."
            )
        
        # Para cada conta, criar uma sessão no banco de dados
        sessions = []
        for account in instagram_accounts:
            session = create_instagram_session(user_id, account, token_data)
            if session:
                sessions.append({
                    "id": session["id"],
                    "username": session["username"]
                })
        
        return {
            "status": "success",
            "message": "Instagram connected successfully",
            "accounts": sessions
        }
        
    except Exception as e:
        print(f"Error processing OAuth code: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Erro ao conectar Instagram: {str(e)}")

@router.post("/revoke")
async def revoke_instagram_access(request: Request, body: dict = None, jwt_token: str = Header(None, alias="jwt_token")):
    """
    Revoga o acesso OAuth do Instagram para uma ou todas as contas de um usuário.
    
    Se 'username' for fornecido no request, revoga apenas essa conta específica.
    Se 'username' não for fornecido, revoga todas as contas do usuário.
    
    Args:
        request: Dicionário com o campo opcional 'username'
        jwt_token: Token JWT para autenticação
        
    Returns:
        Detalhes sobre as contas revogadas
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    try:
        username = (body or {}).get("username") if body else None
        current_time = datetime.now(timezone.utc).isoformat()
        revoked_usernames = []
        
        if username:
            # Revogar acesso apenas para a conta específica
            instagram_logger.info(f"Revogando acesso para {username} do usuário {user_id}")
            
            # Verificar se a sessão existe para este usuário
            sessions = execute_query(
                "SELECT * FROM instagram.instagram_sessions WHERE user_id = %s AND username = %s AND is_active = TRUE",
                [user_id, username]
            )
            
            if not sessions:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Sessão ativa não encontrada para o usuário {username}"
                )
            
            session = sessions[0]
            
            # Tentar revogar no Instagram/Meta se tivermos os dados da sessão
            try:
                if session.get("session_data"):
                    session_data = session["session_data"]
                    if isinstance(session_data, str):
                        session_data = json.loads(session_data)
                    
                    # Extrair token
                    access_token = session_data.get("page_access_token") or session_data.get("access_token")
                    if access_token:
                        # Limpar o token
                        access_token = access_token.strip().strip('"').strip("'")
                        
                        # Revogar no Instagram/Meta
                        instagram_logger.info(f"Revogando token no Instagram/Meta para {username}")
                        revoke_url = "https://graph.instagram.com/v18.0/instagram_oauth/revoke_access"
                        revoke_params = {
                            "access_token": access_token
                        }
                        revoke_response = requests.delete(revoke_url, params=revoke_params)
                        instagram_logger.debug(f"Resposta da revogação no Instagram: {revoke_response.text}")
                        
                        # Também tentar desconectar app no Facebook
                        app_id = os.environ.get("INSTAGRAM_APP_ID") or os.environ.get("FACEBOOK_APP_ID")
                        if app_id:
                            facebook_revoke_url = f"https://graph.facebook.com/v18.0/{app_id}/permissions"
                            facebook_response = requests.delete(facebook_revoke_url, params=revoke_params)
                            instagram_logger.debug(f"Resposta da revogação no Facebook: {facebook_response.text}")
            except Exception as e:
                instagram_logger.error(f"Erro ao revogar token no Instagram/Meta: {str(e)}")
                # Continuar mesmo se falhar na revogação externa
            
            # Desativar a sessão no banco de dados
            execute_query(
                "UPDATE instagram.instagram_sessions SET is_active = FALSE, status = 'revoked', updated_at = %s WHERE user_id = %s AND username = %s AND is_active = TRUE",
                [current_time, user_id, username],
                fetch=False
            )
            
            revoked_usernames = [username]
        else:
            # Revogar acesso para todas as contas do usuário
            instagram_logger.info(f"Revogando acesso para todas as contas do usuário {user_id}")
            
            # Obter todas as sessões ativas
            active_sessions = execute_query(
                "SELECT * FROM instagram.instagram_sessions WHERE user_id = %s AND is_active = TRUE",
                [user_id]
            )
            
            if not active_sessions:
                return {
                    "status": "success",
                    "message": "Nenhuma sessão ativa para revogar",
                    "revoked_accounts": []
                }
            
            # Para cada sessão, tentar revogar no Instagram/Meta
            for session in active_sessions:
                username = session["username"]
                revoked_usernames.append(username)
                
                # Tentar revogar no Instagram/Meta
                try:
                    if session.get("session_data"):
                        session_data = session["session_data"]
                        if isinstance(session_data, str):
                            session_data = json.loads(session_data)
                        
                        # Extrair token
                        access_token = session_data.get("page_access_token") or session_data.get("access_token")
                        if access_token:
                            # Limpar o token
                            access_token = access_token.strip().strip('"').strip("'")
                            
                            # Revogar no Instagram/Meta
                            instagram_logger.info(f"Revogando token no Instagram/Meta para {username}")
                            revoke_url = "https://graph.instagram.com/v18.0/instagram_oauth/revoke_access"
                            revoke_params = {
                                "access_token": access_token
                            }
                            revoke_response = requests.delete(revoke_url, params=revoke_params)
                            instagram_logger.debug(f"Resposta da revogação no Instagram: {revoke_response.text}")
                            
                            # Também tentar desconectar app no Facebook
                            app_id = os.environ.get("INSTAGRAM_APP_ID") or os.environ.get("FACEBOOK_APP_ID")
                            if app_id:
                                facebook_revoke_url = f"https://graph.facebook.com/v18.0/{app_id}/permissions"
                                facebook_response = requests.delete(facebook_revoke_url, params=revoke_params)
                                instagram_logger.debug(f"Resposta da revogação no Facebook: {facebook_response.text}")
                except Exception as e:
                    instagram_logger.error(f"Erro ao revogar token no Instagram/Meta para {username}: {str(e)}")
                    # Continuar para a próxima conta mesmo se falhar
            
            # Desativar todas as sessões
            execute_query(
                "UPDATE instagram.instagram_sessions SET is_active = FALSE, status = 'revoked', updated_at = %s WHERE user_id = %s AND is_active = TRUE",
                [current_time, user_id],
                fetch=False
            )
        
        return {
            "status": "success",
            "message": f"Acesso revogado para {len(revoked_usernames)} conta(s)",
            "revoked_accounts": revoked_usernames
        }
    
    except HTTPException:
        raise
    except Exception as e:
        instagram_logger.error(f"Erro ao revogar acesso: {str(e)}")
        import traceback
        instagram_logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Erro ao revogar acesso: {str(e)}")

@router.post("/publish")
async def publish_to_instagram(
    request: Request,
    body: dict,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Publica um vídeo no Instagram usando a API Graph.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        instagram_logger.error(f"Usuário não encontrado ou inativo: {user_id}")
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    # Validar campos obrigatórios
    required_fields = ["username", "type", "when", "video_url", "caption"]
    for field in required_fields:
        if field not in body:
            instagram_logger.error(f"Campo obrigatório ausente: {field}")
            raise HTTPException(status_code=400, detail=f"Campo obrigatório ausente: {field}")

    # Buscar sessão do Instagram
    instagram_logger.info(f"Buscando sessão para usuário {user_id} e conta {body['username']}")
    session = execute_query(
        """
        SELECT * FROM instagram.instagram_sessions 
        WHERE user_id = %s AND username = %s AND is_active = TRUE
        """,
        [user_id, body["username"]]
    )

    if not session:
        instagram_logger.error(f"Sessão não encontrada para o usuário {body['username']}")
        raise HTTPException(
            status_code=404,
            detail=f"Sessão não encontrada para o usuário {body['username']}"
        )

    session_data = session[0]
    instagram_logger.debug(f"Dados brutos da sessão: {json.dumps(dict(session_data), default=str)}")
    
    # Converter session_data de string para dict se necessário
    try:
        if isinstance(session_data["session_data"], str):
            session_data_dict = json.loads(session_data["session_data"])
        else:
            session_data_dict = session_data["session_data"]
            
        instagram_logger.debug(f"Dados da sessão convertidos: {json.dumps(session_data_dict)}")
        
        # Extrair e limpar o token de acesso (remover possíveis caracteres inválidos)
        access_token = session_data_dict.get("page_access_token") or session_data_dict.get("access_token")
        if access_token:
            # Limpar o token removendo possíveis caracteres inválidos
            access_token = access_token.strip().strip('"').strip("'")
            # Remover possíveis espaços ou caracteres especiais
            access_token = ''.join(c for c in access_token if c.isalnum() or c in ['_', '-', '.'])
            instagram_logger.debug(f"Token de acesso após limpeza: {access_token[:20]}... (truncado)")
            
        instagram_account_id = session_data_dict.get("id") or session_data_dict.get("account_id")
        if instagram_account_id:
            instagram_account_id = str(instagram_account_id).strip().strip('"').strip("'")
            instagram_logger.debug(f"ID da conta Instagram após limpeza: {instagram_account_id}")
            
    except (json.JSONDecodeError, KeyError) as e:
        instagram_logger.error(f"Erro ao converter dados da sessão: {str(e)}")
        instagram_logger.error(f"Dados brutos da sessão: {session_data}")
        raise HTTPException(
            status_code=400,
            detail="Dados de sessão inválidos. Reconecte sua conta do Instagram."
        )

    if not access_token or not instagram_account_id:
        instagram_logger.error("Token ou ID da conta ausentes nos dados da sessão")
        raise HTTPException(
            status_code=400,
            detail="Dados de sessão inválidos. Reconecte sua conta do Instagram."
        )

    try:
        # Verificar validade do token usando endpoint do Instagram Graph API
        instagram_logger.info("Verificando validade do token...")
        verify_url = f"https://graph.instagram.com/me"
        verify_params = {"access_token": access_token}
        instagram_logger.debug(f"URL de verificação: {verify_url}")
        instagram_logger.debug(f"Parâmetros de verificação: {verify_params}")
        
        verify_response = requests.get(verify_url, params=verify_params)
        instagram_logger.debug(f"Resposta da verificação: {verify_response.text}")
        
        if verify_response.status_code != 200:
            instagram_logger.error(f"Erro na verificação do token: {verify_response.text}")
            # Se o token for inválido, vamos tentar revogar a sessão automaticamente
            try:
                current_time = datetime.now(timezone.utc).isoformat()
                instagram_logger.info(f"Revogando sessão para {body['username']}")
                execute_query(
                    """
                    UPDATE instagram.instagram_sessions 
                    SET is_active = FALSE, 
                        status = 'revoked', 
                        updated_at = %s 
                    WHERE user_id = %s 
                    AND username = %s 
                    AND is_active = TRUE
                    """,
                    [current_time, user_id, body["username"]],
                    fetch=False
                )
                instagram_logger.info(f"Sessão revogada com sucesso para {body['username']}")
            except Exception as e:
                instagram_logger.error(f"Erro ao revogar sessão automaticamente: {str(e)}")
                
            raise HTTPException(
                status_code=401,
                detail="Token de acesso inválido ou expirado. Por favor, reconecte sua conta do Instagram."
            )

        try:
            # Download do vídeo
            instagram_logger.info(f"Baixando vídeo: {body['video_url']}")
            video_response = requests.get(body["video_url"], stream=True)
            video_response.raise_for_status()

            # Criar arquivo temporário
            import tempfile
            temp_dir = tempfile.gettempdir()
            video_path = os.path.join(temp_dir, f"video_{user_id}_{int(datetime.now().timestamp())}.mp4")

            # Salvar vídeo
            with open(video_path, 'wb') as f:
                for chunk in video_response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Preparar caption com hashtags
            caption = body["caption"]
            if body.get("hashtags"):
                caption = f"{caption}\n\n{body['hashtags']}"

            # Obter ID do usuário do Instagram
            instagram_logger.info("Obtendo ID do usuário do Instagram")
            instagram_user_id = session_data_dict.get("account_id")
            
            if not instagram_user_id:
                instagram_logger.error("ID do usuário do Instagram não encontrado")
                raise HTTPException(
                    status_code=400,
                    detail="Configuração incompleta. Reconecte sua conta do Instagram."
                )

            # Iniciar upload do container
            instagram_logger.info("Iniciando upload do container")
            container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
            
            container_data = {
                "media_type": "REELS" if body["type"].lower() == "reel" else "VIDEO",
                "video_url": body["video_url"],
                "caption": caption,
                "access_token": access_token
            }

            instagram_logger.debug(f"URL do container: {container_url}")
            instagram_logger.debug(f"Dados do container: {json.dumps(container_data)}")

            # Se for agendado, adicionar timestamp
            if body["when"] == "schedule" and body.get("schedule_date"):
                try:
                    schedule_time = datetime.fromisoformat(body["schedule_date"].replace('Z', '+00:00'))
                    container_data["publishing_type"] = "SCHEDULED"
                    container_data["scheduled_publish_time"] = int(schedule_time.timestamp())
                except ValueError as e:
                    instagram_logger.error(f"Data de agendamento inválida: {str(e)}")
                    raise HTTPException(status_code=400, detail=f"Data de agendamento inválida: {str(e)}")

            container_response = requests.post(container_url, data=container_data)
            instagram_logger.debug(f"Resposta da criação do container: {container_response.text}")
            
            if container_response.status_code != 200:
                instagram_logger.error(f"Erro na criação do container: {container_response.text}")
                error_data = container_response.json()
                error_message = error_data.get('error', {}).get('message', 'Erro desconhecido')
                raise HTTPException(status_code=400, detail=f"Erro ao criar container de mídia: {error_message}")
                
            container_response.raise_for_status()
            container_id = container_response.json().get("id")

            if not container_id:
                instagram_logger.error("Falha ao obter ID do container")
                raise HTTPException(status_code=500, detail="Falha ao criar container de mídia")

            instagram_logger.info(f"Container criado com sucesso: {container_id}")

            # Aguardar o processamento do vídeo
            instagram_logger.info("Aguardando processamento do vídeo...")
            max_attempts = 40  # Aumentado para 40 tentativas (2 minutos no total)
            attempt = 0
            status_url = f"https://graph.instagram.com/v18.0/{container_id}"
            
            while attempt < max_attempts:
                attempt += 1
                instagram_logger.debug(f"Verificando status do container (tentativa {attempt}/{max_attempts})")
                
                try:
                    status_params = {"access_token": access_token, "fields": "status_code,status"}
                    status_response = requests.get(status_url, params=status_params)
                    instagram_logger.debug(f"Resposta do status: {status_response.text}")
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status_code = status_data.get("status_code")
                        
                        if status_code == "FINISHED":
                            instagram_logger.info("Vídeo processado com sucesso")
                            break
                        elif status_code == "IN_PROGRESS":
                            instagram_logger.debug("Vídeo ainda em processamento...")
                        elif status_code in ["ERROR", "EXPIRED"]:
                            instagram_logger.error(f"Erro no processamento do vídeo: {status_data}")
                            raise HTTPException(
                                status_code=400,
                                detail="Erro no processamento do vídeo. Por favor, tente novamente."
                            )
                        else:
                            instagram_logger.warning(f"Status desconhecido: {status_code}")
                    else:
                        instagram_logger.warning(f"Erro ao verificar status (HTTP {status_response.status_code})")
                    
                    # Ajustar o tempo de espera baseado na tentativa
                    if attempt < 10:  # Primeiros 30 segundos
                        time.sleep(3)
                    elif attempt < 20:  # Próximos 30 segundos
                        time.sleep(5)
                    else:  # Resto do tempo
                        time.sleep(7)
                    
                except Exception as e:
                    instagram_logger.error(f"Erro ao verificar status: {str(e)}")
                    time.sleep(3)  # Esperar mesmo em caso de erro
            
            if attempt >= max_attempts:
                instagram_logger.error("Timeout aguardando processamento do vídeo")
                raise HTTPException(
                    status_code=408,
                    detail="O vídeo está demorando muito para processar. Por favor, tente novamente com um vídeo menor ou aguarde alguns minutos."
                )

            # Tentar publicar algumas vezes
            max_publish_attempts = 3
            publish_attempt = 0
            publish_success = False

            while publish_attempt < max_publish_attempts and not publish_success:
                publish_attempt += 1
                instagram_logger.info(f"Tentativa de publicação {publish_attempt}/{max_publish_attempts}")

                try:
                    # Publicar o container
                    publish_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media_publish"
                    publish_data = {
                        "creation_id": container_id,
                        "access_token": access_token
                    }

                    instagram_logger.debug(f"URL de publicação: {publish_url}")
                    instagram_logger.debug(f"Dados de publicação: {json.dumps(publish_data)}")

                    publish_response = requests.post(publish_url, data=publish_data)
                    instagram_logger.debug(f"Resposta da publicação: {publish_response.text}")
                    
                    if publish_response.status_code == 200:
                        publish_success = True
                        break
                    else:
                        error_data = publish_response.json()
                        error_message = error_data.get('error', {}).get('message', 'Erro desconhecido')
                        
                        if "Media ID is not available" in error_message:
                            instagram_logger.warning("Mídia ainda não disponível, aguardando mais...")
                            time.sleep(5)  # Esperar mais 5 segundos antes da próxima tentativa
                        else:
                            raise HTTPException(status_code=400, detail=f"Erro ao publicar: {error_message}")
                
                except Exception as e:
                    instagram_logger.error(f"Erro na tentativa de publicação {publish_attempt}: {str(e)}")
                    if publish_attempt == max_publish_attempts:
                        raise HTTPException(status_code=400, detail=f"Erro ao publicar: {str(e)}")
                    time.sleep(5)

            if not publish_success:
                raise HTTPException(
                    status_code=400,
                    detail="Não foi possível publicar o vídeo após várias tentativas. Por favor, tente novamente."
                )

            # Limpar arquivo temporário
            try:
                os.remove(video_path)
            except Exception as e:
                instagram_logger.warning(f"Erro ao remover arquivo temporário: {str(e)}")

            return {
                "status": "success",
                "message": "Vídeo publicado com sucesso" if body["when"] == "now" else "Vídeo agendado com sucesso",
                "post_id": publish_response.json().get("id")
            }

        except requests.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text

            instagram_logger.error(f"Erro ao publicar: {error_msg}")
            raise HTTPException(status_code=400, detail=f"Erro ao publicar no Instagram: {error_msg}")

        except Exception as e:
            instagram_logger.error(f"Erro inesperado: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")
        finally:
            # Garantir que o arquivo temporário seja removido
            try:
                if 'video_path' in locals():
                    os.remove(video_path)
            except:
                pass

    except requests.RequestException as e:
        error_msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('error', {}).get('message', str(e))
            except:
                error_msg = e.response.text

        print(f"[INSTAGRAM_API] Erro ao publicar: {error_msg}")
        raise HTTPException(status_code=400, detail=f"Erro ao publicar no Instagram: {error_msg}")

    except Exception as e:
        print(f"[INSTAGRAM_API] Erro inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")
    finally:
        # Garantir que o arquivo temporário seja removido
        try:
            if 'video_path' in locals():
                os.remove(video_path)
        except:
            pass

@router.post("/revoke-invalid")
async def revoke_invalid_session(
    request: Request,
    body: dict,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Revoga uma sessão inválida do Instagram.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    username = body.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Username não fornecido")

    try:
        current_time = datetime.now(timezone.utc).isoformat()
        
        # Desativar a sessão
        execute_query(
            """
            UPDATE instagram.instagram_sessions 
            SET is_active = FALSE, 
                status = 'revoked', 
                updated_at = %s 
            WHERE user_id = %s 
            AND username = %s 
            AND is_active = TRUE
            RETURNING id
            """,
            [current_time, user_id, username],
            fetch=False
        )

        return {
            "status": "success",
            "message": f"Sessão revogada com sucesso para {username}. Por favor, reconecte sua conta do Instagram."
        }

    except Exception as e:
        print(f"Erro ao revogar sessão: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao revogar sessão: {str(e)}") 