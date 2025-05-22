from fastapi import APIRouter, Header, HTTPException, Request, Depends, Response
from fastapi.responses import RedirectResponse, PlainTextResponse
import os
import requests
from datetime import datetime, timezone
import json
import time
import subprocess
import shutil
import uuid
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

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
                        
                        # Primeiro revogar o token
                        revoke_url = "https://graph.instagram.com/v18.0/instagram_oauth/revoke_access"
                        revoke_params = {
                            "access_token": access_token
                        }
                        revoke_response = requests.delete(revoke_url, params=revoke_params)
                        instagram_logger.debug(f"Resposta da revogação do token no Instagram: {revoke_response.text}")
                        
                        # Depois revogar TODAS as permissões (desconecta completamente o app)
                        # Esta é a chamada mais importante para desconectar o app
                        disconnect_url = "https://graph.facebook.com/v18.0/me/permissions"
                        disconnect_response = requests.delete(disconnect_url, params=revoke_params)
                        instagram_logger.debug(f"Resposta da revogação de permissões: {disconnect_response.text}")
                        
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
                "DELETE FROM instagram.instagram_sessions WHERE user_id = %s AND username = %s",
                [user_id, username],
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
                            
                            # Primeiro revogar o token
                            revoke_url = "https://graph.instagram.com/v18.0/instagram_oauth/revoke_access"
                            revoke_params = {
                                "access_token": access_token
                            }
                            revoke_response = requests.delete(revoke_url, params=revoke_params)
                            instagram_logger.debug(f"Resposta da revogação do token no Instagram: {revoke_response.text}")
                            
                            # Depois revogar TODAS as permissões (desconecta completamente o app)
                            # Esta é a chamada mais importante para desconectar o app
                            disconnect_url = "https://graph.facebook.com/v18.0/me/permissions"
                            disconnect_response = requests.delete(disconnect_url, params=revoke_params)
                            instagram_logger.debug(f"Resposta da revogação de permissões: {disconnect_response.text}")
                            
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
                "DELETE FROM instagram.instagram_sessions WHERE user_id = %s",
                [user_id],
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

def interpret_instagram_error(error_data):
    """
    Interpreta códigos de erro da API do Instagram e retorna mensagens mais amigáveis.
    
    Args:
        error_data: Dados de erro da API do Instagram
        
    Returns:
        Mensagem de erro interpretada
    """
    if not error_data or not isinstance(error_data, dict):
        return "Erro desconhecido da API do Instagram"
    
    # Garantir que temos a estrutura correta de erro
    if 'error' not in error_data:
        return str(error_data)
    
    error = error_data.get('error', {})
    code = error.get('code')
    subcode = error.get('error_subcode')
    message = error.get('message', '')
    user_title = error.get('error_user_title', '')
    user_msg = error.get('error_user_msg', '')
    
    # Logar todos os detalhes do erro para diagnóstico
    import logging
    logging.getLogger('instagram_logger').debug(f"Erro completo: Código {code}, Subcódigo {subcode}, Mensagem: {message}, Título: {user_title}, Msg: {user_msg}")
    
    # Usar a mensagem específica para o usuário se disponível
    if user_msg:
        return f"{user_title}: {user_msg}"
    
    # Mensagens específicas baseadas nos códigos de erro
    error_map = {
        # Códigos principais
        -2: "Tempo limite excedido ou mídia expirada",
        -1: "Erro do servidor do Instagram",
        1: "Restrição de atividade para proteger a comunidade",
        4: "Ação considerada spam",
        9: "Limite diário de publicações atingido (máximo 50 em 24h)",
        24: "Mídia não encontrada ou token expirado",
        25: "Conta do Instagram restrita",
        100: "Parâmetro inválido ou problema com marcações/carrossel",
        352: "Formato de vídeo não suportado (use MP4 ou MOV)",
        9004: "Não foi possível obter a mídia do URI fornecido",
        9007: "Mídia não está pronta para publicação",
        36000: "Imagem/vídeo muito grande (máximo 8MB)",
        36001: "Formato de imagem não suportado (use JPEG)",
        36003: "Proporção da imagem inválida (use entre 4:5 e 1,91:1)",
        36004: "Legenda muito longa (máximo 2.200 caracteres)",
        
        # Subcódigos mais comuns
        2207001: "Erro do servidor do Instagram. Tente novamente.",
        2207003: "Download da mídia atingiu o tempo limite. Tente novamente.",
        2207004: "Imagem/vídeo muito grande (deve ser menor que 8MB).",
        2207005: "Formato de imagem não suportado. Use apenas JPEG.",
        2207006: "Mídia não encontrada (possível erro de permissão).",
        2207008: "Container expirado. Crie um novo.",
        2207009: "Proporção de imagem inválida (use entre 4:5 e 1,91:1).",
        2207010: "Legenda muito longa (máximo 2.200 caracteres).",
        2207020: "Mídia expirada. Tente fazer upload novamente.",
        2207023: "Tipo de mídia desconhecido.",
        2207026: "Formato de vídeo não suportado. Use MP4 ou MOV (MPEG-4 Part 14). O Instagram não aceita outros formatos de vídeo.",
        2207027: "Mídia não está pronta para publicação. Aguarde.",
        2207028: "Carrossel precisa ter entre 2 e 10 fotos/vídeos.",
        2207032: "Falha ao criar mídia. Tente novamente.",
        2207042: "Limite diário de publicações atingido (máximo 50 em 24h).",
        2207050: "Conta do Instagram restrita.",
        2207051: "Ação considerada spam pela proteção da comunidade.",
        2207052: "Não foi possível obter mídia do URI fornecido.",
        2207053: "Erro desconhecido no upload. Tente novamente.",
        2207057: "Deslocamento da miniatura do vídeo inválido.",
        2207067: "Tipo de mídia VIDEO foi descontinuado. Use REELS para publicar vídeos."
    }
    
    # Verificar subcódigo primeiro (mais específico)
    if subcode and subcode in error_map:
        return f"{error_map[subcode]} (Código {code}, Subcódigo {subcode})"
    
    # Verificar código principal
    if code and code in error_map:
        return f"{error_map[code]} (Código {code})"
    
    # Retornar mensagem original e códigos se não encontrar correspondência
    if code or subcode:
        return f"{message} (Código {code}, Subcódigo {subcode})"
    
    # Fallback para mensagem original
    return message or "Erro desconhecido da API do Instagram"

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
                    DELETE FROM instagram.instagram_sessions 
                    WHERE user_id = %s 
                    AND username = %s 
                    AND is_active = TRUE
                    """,
                    [user_id, body["username"]],
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
            try:
                # Verificar se é URL do TikTok
                is_tiktok = "tiktok" in body["video_url"].lower()
                if is_tiktok:
                    instagram_logger.info("Detectada URL do TikTok, usando tratamento especial")
                
                # Verificar se a URL é acessível
                head_response = requests.head(body["video_url"], allow_redirects=True, timeout=10)
                head_response.raise_for_status()
                
                # Verificar o tipo de conteúdo
                content_type = head_response.headers.get('Content-Type', '')
                instagram_logger.debug(f"Tipo de conteúdo do vídeo: {content_type}")
                
                if not content_type.startswith('video/'):
                    instagram_logger.warning(f"URL pode não ser um vídeo direto. Content-Type: {content_type}")
                
                # Tentar obter o tamanho do vídeo
                content_length = head_response.headers.get('Content-Length')
                if content_length:
                    size_mb = int(content_length) / (1024 * 1024)
                    instagram_logger.debug(f"Tamanho do vídeo: {size_mb:.2f} MB")
                    
                    # Stories têm limite de tamanho
                    if body["type"].lower() == "story" and size_mb > 15:
                        instagram_logger.warning(f"Vídeo pode ser muito grande para story: {size_mb:.2f} MB (limite ~15MB)")
                
                # Baixar o vídeo com streaming
                video_response = requests.get(body["video_url"], stream=True, timeout=30)
                video_response.raise_for_status()
                
                # Criar arquivo temporário
                import tempfile
                temp_dir = tempfile.gettempdir()
                
                # Em ambientes de produção Linux/Ubuntu, usar um diretório mais adequado se possível
                if os.name != 'nt' and os.access('/var/tmp', os.W_OK):
                    temp_dir = '/var/tmp'  # Diretório mais adequado para arquivos temporários grandes no Linux
                
                video_path = os.path.join(temp_dir, f"video_{user_id}_{int(datetime.now().timestamp())}.mp4")
                
                # Salvar vídeo
                with open(video_path, 'wb') as f:
                    for chunk in video_response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                # Verificar se o arquivo foi criado corretamente
                if not os.path.exists(video_path) or os.path.getsize(video_path) == 0:
                    instagram_logger.error("Arquivo de vídeo vazio ou não criado")
                    raise HTTPException(status_code=400, detail="Erro ao baixar vídeo - arquivo inválido")
                
                video_size_mb = os.path.getsize(video_path) / (1024 * 1024)
                instagram_logger.debug(f"Vídeo baixado para: {video_path} ({video_size_mb:.2f} MB)")
                
                # Converter o vídeo para formato compatível com Instagram usando FFmpeg
                instagram_logger.info("Convertendo vídeo para formato compatível com Instagram...")
                try:
                    # Criar diretório temporário para vídeos convertidos
                    temp_converted_dir = os.path.join(temp_dir, "instagram_converted")
                    try:
                        os.makedirs(temp_converted_dir, exist_ok=True)
                        # Verificar se o diretório foi criado e tem permissões de escrita
                        if not os.path.exists(temp_converted_dir) or not os.access(temp_converted_dir, os.W_OK):
                            # Tentar diretório alternativo
                            instagram_logger.warning(f"Diretório {temp_converted_dir} não tem permissões de escrita, usando alternativa")
                            temp_converted_dir = os.path.join(tempfile.gettempdir(), f"instagram_conv_{uuid.uuid4().hex[:8]}")
                            os.makedirs(temp_converted_dir, exist_ok=True)
                    except Exception as dir_err:
                        # Se falhar em criar o diretório, usar um alternativo
                        instagram_logger.error(f"Erro ao criar diretório temporário: {str(dir_err)}")
                        temp_converted_dir = os.path.join(tempfile.gettempdir(), f"instagram_conv_{uuid.uuid4().hex[:8]}")
                        os.makedirs(temp_converted_dir, exist_ok=True)
                    
                    instagram_logger.debug(f"Diretório temporário para conversão: {temp_converted_dir}")
                    
                    # Converter o vídeo
                    converted_video_path = convert_video_for_instagram(video_path, temp_converted_dir)
                    
                    if converted_video_path and os.path.exists(converted_video_path):
                        instagram_logger.info(f"Vídeo convertido com sucesso: {converted_video_path}")
                        
                        # Substituir o caminho do vídeo original pelo convertido
                        video_path = converted_video_path
                        
                        # Fazer upload do vídeo convertido para o S3
                        instagram_logger.info("Enviando vídeo convertido para o S3...")
                        s3_video_url = upload_to_s3(video_path)
                        
                        if s3_video_url:
                            instagram_logger.info(f"Vídeo enviado com sucesso para o S3: {s3_video_url}")
                            # Substituir a URL original pelo link do S3
                            body["video_url"] = s3_video_url
                        else:
                            instagram_logger.warning("Falha ao enviar vídeo para S3, usando URL original")
                        
                        # Atualizar informações de tamanho
                        video_size_mb = os.path.getsize(video_path) / (1024 * 1024)
                        instagram_logger.debug(f"Vídeo convertido: {video_path} ({video_size_mb:.2f} MB)")
                    else:
                        instagram_logger.warning("Conversão de vídeo falhou, continuando com o vídeo original")
                except Exception as conv_err:
                    instagram_logger.error(f"Erro na conversão do vídeo: {str(conv_err)}")
                    instagram_logger.warning("Continuando com o vídeo original sem conversão")
                
                # Para TikTok, tentar fazer upload direto para o Instagram
                if is_tiktok and body["type"].lower() == "story":
                    instagram_logger.info("Para vídeos de TikTok, usando URL direta em vez de download")
                    # Continuar usando a URL direta neste caso
                
            except requests.RequestException as e:
                instagram_logger.error(f"Erro ao baixar vídeo: {str(e)}")
                if hasattr(e, 'response') and e.response:
                    instagram_logger.error(f"Status: {e.response.status_code}, Resposta: {e.response.text[:200]}")
                raise HTTPException(status_code=400, detail=f"Erro ao baixar vídeo: {str(e)}")
                
            except Exception as e:
                instagram_logger.error(f"Erro inesperado ao baixar vídeo: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Erro ao processar vídeo: {str(e)}")

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
            instagram_logger.info(f"Iniciando upload de {body['type'].lower()}")
            
            # Definir tipo de mídia e endpoint correto baseado no tipo de post
            if body["type"].lower() == "story":
                # Para stories, usar STORIES conforme documentação oficial
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "STORIES",  # Tipo correto para stories
                    "video_url": body["video_url"],
                    "access_token": access_token
                }
            elif body["type"].lower() == "reel":
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "REELS",  # Tipo específico para reels
                    "video_url": body["video_url"],
                    "caption": caption,
                    "access_token": access_token
                }
            else:  # feed
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "REELS",  # Usar REELS para vídeos de feed (conforme erro anterior)
                    "video_url": body["video_url"],
                    "caption": caption,
                    "access_token": access_token
                }

            # Postar com arquivo anexado
            try:
                container_response = requests.post(container_url, data=container_data)
                instagram_logger.debug(f"Resposta com upload direto: {container_response.text}")
            except Exception as upload_err:
                instagram_logger.error(f"Erro no upload direto: {str(upload_err)}")
                
                # Fallback para URL se o upload direto falhar
                instagram_logger.info("Fallback para método de URL após falha no upload direto")
                container_data = {
                    "media_type": "STORIES",  # Tipo correto para stories
                    "video_url": body["video_url"],
                    "access_token": access_token
                }
                container_response = requests.post(container_url, data=container_data)

            # Se for agendado, adicionar timestamp
            if body["when"] == "schedule" and body.get("schedule_date"):
                try:
                    schedule_time = datetime.fromisoformat(body["schedule_date"].replace('Z', '+00:00'))
                    container_data["publishing_type"] = "SCHEDULED"
                    container_data["scheduled_publish_time"] = int(schedule_time.timestamp())
                except ValueError as e:
                    instagram_logger.error(f"Data de agendamento inválida: {str(e)}")
                    raise HTTPException(status_code=400, detail=f"Data de agendamento inválida: {str(e)}")

            instagram_logger.debug(f"URL do container: {container_url}")
            instagram_logger.debug(f"Dados do container: {json.dumps(container_data)}")

            # Se não estiver usando o upload direto de arquivo, verifica a resposta aqui
            if 'container_response' not in locals() or container_response is None:
                container_response = requests.post(container_url, data=container_data)
                instagram_logger.debug(f"Resposta da criação do container: {container_response.text}")
            
            if container_response.status_code != 200:
                instagram_logger.error(f"Erro na criação do container: {container_response.text}")
                error_data = container_response.json()
                
                # Extrair e logar códigos de erro específicos
                if "error" in error_data:
                    error_code = error_data["error"].get("code")
                    error_subcode = error_data["error"].get("error_subcode")
                    instagram_logger.error(f"Erro na criação do container - Código: {error_code}, Subcódigo: {error_subcode}")
                    
                    # Tratamento específico para erro de formato de vídeo
                    if error_code == 352 or (error_subcode and error_subcode == 2207026):
                        instagram_logger.error("Erro de formato de vídeo detectado")
                        format_error_msg = """
Formato de vídeo não suportado pelo Instagram. A conversão automática não resolveu o problema.
Por favor, tente:

1. Usar apenas vídeos no formato MP4 ou MOV (MPEG-4 Part 14)
2. Verificar se a duração do vídeo está dentro dos limites permitidos:
   - Para Stories: entre 3 e 60 segundos
   - Para Reels: entre 3 segundos e 90 segundos
3. Garantir que o tamanho do arquivo é menor que 100MB
4. Usar codecs de vídeo H.264 ou H.265

Para vídeos do TikTok, é recomendado baixar o vídeo e convertê-lo com um software como o VLC antes de fazer upload.
"""
                        raise HTTPException(status_code=400, detail=format_error_msg)
                
                friendly_error = interpret_instagram_error(error_data)
                
                # Para vídeos do TikTok, adicionar sugestão específica
                if "tiktok" in body["video_url"].lower():
                    friendly_error += " Para vídeos do TikTok, tente baixar o vídeo localmente primeiro e depois fazer upload."
                
                raise HTTPException(status_code=400, detail=f"Erro ao criar container de mídia: {friendly_error}")
            
            container_response.raise_for_status()
            
            # Para stories, o processo agora é o mesmo dos vídeos normais,
            # mas com o parâmetro is_story
            container_id = container_response.json().get("id")
            if not container_id:
                instagram_logger.error("Falha ao obter ID do container")
                raise HTTPException(status_code=500, detail="Falha ao criar container de mídia")

            instagram_logger.info(f"Container criado com sucesso: {container_id}")

            # Verificar status do container antes de tentar publicar
            instagram_logger.info("Verificando status do container antes de publicar...")
            status_url = f"https://graph.instagram.com/v18.0/{container_id}"
            status_params = {"access_token": access_token, "fields": "status_code"}
            
            # Aguardar que o container esteja pronto para publicação
            # De acordo com a documentação, deve-se verificar no máximo 1x por minuto por até 5 minutos
            max_attempts = 10
            attempt = 0
            container_ready = False
            
            while attempt < max_attempts:
                attempt += 1
                instagram_logger.debug(f"Verificando status do container (tentativa {attempt}/{max_attempts})")
                
                try:
                    status_response = requests.get(status_url, params=status_params)
                    instagram_logger.debug(f"Resposta do status: {status_response.text}")
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status_code = status_data.get("status_code", "")
                        
                        if status_code == "FINISHED":
                            instagram_logger.info("Container pronto para publicação")
                            container_ready = True
                            break
                        elif status_code == "PUBLISHED":
                            instagram_logger.info("Container já foi publicado")
                            container_ready = True
                            break
                        elif status_code == "ERROR" or status_code == "EXPIRED":
                            # Tentar obter mais detalhes sobre o erro
                            error_details = ""
                            error_data = {}
                            try:
                                # Primeiro, tentar obter mais detalhes com o endpoint padrão
                                error_detail_url = f"https://graph.instagram.com/v18.0/{container_id}"
                                error_detail_params = {
                                    "access_token": access_token,
                                    "fields": "status_code,status,error"  # Adicionar o campo error
                                }
                                error_detail_response = requests.get(error_detail_url, params=error_detail_params)
                                instagram_logger.debug(f"Detalhes do erro (1): {error_detail_response.text}")
                                
                                if error_detail_response.status_code == 200:
                                    error_details = error_detail_response.text
                                    response_json = error_detail_response.json()
                                    
                                    # Verificar se temos o objeto error
                                    if "error" in response_json:
                                        error_data = response_json
                                        instagram_logger.debug(f"Encontrado objeto 'error' nos detalhes")
                                
                                # Se não conseguimos o objeto error, tentar fazer uma chamada que provavelmente falhará
                                # para obter uma resposta de erro completa
                                if not error_data.get("error"):
                                    instagram_logger.debug("Tentando obter detalhes do erro com chamada secundária")
                                    
                                    # Tentar publicar o container incorreto para forçar um erro detalhado
                                    invalid_publish_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media_publish"
                                    invalid_publish_params = {
                                        "creation_id": container_id,
                                        "access_token": access_token
                                    }
                                    
                                    try:
                                        error_response = requests.post(invalid_publish_url, data=invalid_publish_params)
                                        if error_response.status_code != 200 and "error" in error_response.json():
                                            error_data = error_response.json()
                                            instagram_logger.debug(f"Detalhes do erro (2): {error_response.text}")
                                    except Exception as pub_error:
                                        instagram_logger.error(f"Erro ao tentar obter detalhes secundários: {str(pub_error)}")
                                        
                            except Exception as detail_err:
                                instagram_logger.error(f"Erro ao obter detalhes: {str(detail_err)}")
                            
                            # Interpretar o erro
                            friendly_error = ""
                            if error_data and "error" in error_data:
                                instagram_logger.debug(f"Código de erro encontrado: {error_data['error'].get('code')}, Subcódigo: {error_data['error'].get('error_subcode')}")
                                friendly_error = interpret_instagram_error(error_data)
                            else:
                                # Códigos de status conhecidos
                                status_errors = {
                                    "ERROR": "Erro ao processar o vídeo. Verifique o formato e tamanho.",
                                    "EXPIRED": "O container expirou. Tente novamente.",
                                    "IN_PROGRESS": "O vídeo ainda está em processamento.",
                                    "PUBLISHED": "O vídeo já foi publicado.",
                                    "SCHEDULED": "O vídeo está agendado para publicação."
                                }
                                friendly_error = status_errors.get(status_code, f"Erro no processamento do container: {status_code}")
                                
                            error_msg = f"{friendly_error} Detalhes: {error_details}"
                            instagram_logger.error(error_msg)

                            # Para stories, tentar abordagem alternativa com REELS
                            if body["type"].lower() == "story" and attempt == 1:
                                instagram_logger.info("Tentando abordagem alternativa para story usando REELS...")
                                
                                # Criar novo container com tipo REELS para story
                                alt_container_data = {
                                    "media_type": "REELS",
                                    "video_url": body["video_url"],
                                    "caption": caption if caption else "Story",
                                    "access_token": access_token
                                }
                                
                                try:
                                    alt_container_response = requests.post(container_url, data=alt_container_data)
                                    instagram_logger.debug(f"Resposta da criação alternativa: {alt_container_response.text}")
                                    
                                    if alt_container_response.status_code == 200:
                                        container_id = alt_container_response.json().get("id")
                                        if container_id:
                                            instagram_logger.info(f"Container alternativo criado: {container_id}")
                                            continue  # Voltar para a verificação com o novo container
                                except Exception as alt_err:
                                    instagram_logger.error(f"Erro na criação alternativa: {str(alt_err)}")
                            
                            # Se tiver problemas com vídeos do TikTok, sugerir alternativa
                            if "tiktok" in body["video_url"].lower():
                                instagram_logger.warning("Vídeo do TikTok detectado - pode haver incompatibilidade")
                                sugestao = " Para vídeos do TikTok, tente baixar o vídeo localmente e depois fazer upload, ou use uma URL de vídeo de outra plataforma."
                            
                            # Sugestões com base no erro
                            sugestao = ""
                            if "muito grande" in error_msg.lower():
                                sugestao = " Tente com um vídeo menor (menos de 8MB)."
                            elif "formato" in error_msg.lower():
                                sugestao = " Tente com um vídeo no formato MP4."
                            elif "proporção" in error_msg.lower():
                                sugestao = " Tente com um vídeo em formato vertical (9:16) para stories."
                            
                            # Se não for story ou a abordagem alternativa falhar
                            raise HTTPException(status_code=400, detail=f"{friendly_error}{sugestao}")
                        elif status_code == "IN_PROGRESS":
                            instagram_logger.debug("Container ainda em processamento...")
                        else:
                            instagram_logger.warning(f"Status desconhecido: {status_code}")
                    else:
                        instagram_logger.warning(f"Erro ao verificar status (HTTP {status_response.status_code})")
                        
                        # Verificar se é um erro de limite de requisições
                        try:
                            error_data = status_response.json()
                            if "error" in error_data:
                                error_code = error_data["error"].get("code")
                                error_subcode = error_data["error"].get("error_subcode")
                                
                                # Códigos relacionados a limite de requisições
                                if error_code == 4 and error_subcode == 1349210:
                                    instagram_logger.warning("Limite de requisições da API atingido, aguardando mais tempo")
                                    time.sleep(10)  # Aguardar mais tempo antes da próxima tentativa
                                    continue
                                
                                # Logar o erro para diagnóstico
                                instagram_logger.error(f"Erro na verificação - Código: {error_code}, Subcódigo: {error_subcode}")
                                instagram_logger.error(f"Mensagem de erro: {error_data['error'].get('message')}")
                        except Exception as parse_err:
                            instagram_logger.error(f"Erro ao parsear resposta de erro: {str(parse_err)}")
                    
                    # Ajustar o tempo de espera baseado na tentativa
                    if attempt < 3:
                        time.sleep(60)  # Primeiras tentativas, aguardar 6 segundos
                    else:
                        time.sleep(60)  # Tentativas posteriores, aguardar mais tempo
                    
                except Exception as e:
                    instagram_logger.error(f"Erro ao verificar status: {str(e)}")
                    time.sleep(10)  # Em caso de erro, aguardar mais tempo
            
            if not container_ready:
                instagram_logger.error("Timeout aguardando processamento do container")
                raise HTTPException(
                    status_code=408,
                    detail="O vídeo está demorando muito para processar. Por favor, tente novamente com um vídeo menor ou aguarde alguns minutos."
                )

            # Tentar publicar
            instagram_logger.info("Iniciando publicação do vídeo")
            publish_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media_publish"
            publish_data = {
                "creation_id": container_id,
                "access_token": access_token
            }

            instagram_logger.debug(f"URL de publicação: {publish_url}")
            instagram_logger.debug(f"Dados de publicação: {json.dumps(publish_data)}")

            # Tentar publicar algumas vezes
            max_publish_attempts = 3
            publish_attempt = 0
            publish_success = False
            publish_response = None
            last_error = None

            while publish_attempt < max_publish_attempts and not publish_success:
                publish_attempt += 1
                instagram_logger.info(f"Tentativa de publicação {publish_attempt}/{max_publish_attempts}")

                try:
                    # Publicar o container
                    publish_response = requests.post(publish_url, data=publish_data)
                    instagram_logger.debug(f"Resposta da publicação: {publish_response.text}")
                    
                    if publish_response.status_code == 200:
                        publish_success = True
                        break
                    else:
                        error_data = publish_response.json()
                        error_message = error_data.get('error', {}).get('message', 'Erro desconhecido')
                        friendly_error = interpret_instagram_error(error_data)
                        last_error = friendly_error
                        
                        instagram_logger.error(f"Erro de publicação: {error_message}")
                        instagram_logger.error(f"Erro interpretado: {friendly_error}")
                        
                        if "Media ID is not available" in error_message:
                            instagram_logger.warning("Mídia ainda não disponível, aguardando mais...")
                            time.sleep(5)  # Esperar mais 5 segundos antes da próxima tentativa
                        else:
                            # Para stories que falham, tentar converter o tipo
                            if body["type"].lower() == "story" and publish_attempt == 1:
                                instagram_logger.info("Tentando opção alternativa para story...")
                                
                                # Tentar criar novo container com REELS como alternativa
                                alt_container_data = {
                                    "media_type": "REELS",  # Tentar com REELS como alternativa
                                    "video_url": body["video_url"],
                                    "caption": caption if caption else "",
                                    "access_token": access_token
                                }
                                
                                try:
                                    alt_container_response = requests.post(
                                        f"https://graph.instagram.com/v18.0/{instagram_user_id}/media", 
                                        data=alt_container_data
                                    )
                                    
                                    instagram_logger.debug(f"Resposta da criação alternativa (REELS): {alt_container_response.text}")
                                    
                                    if alt_container_response.status_code == 200:
                                        alt_container_id = alt_container_response.json().get("id")
                                        if alt_container_id:
                                            instagram_logger.info(f"Container alternativo (REELS) criado: {alt_container_id}")
                                            # Atualizar ID para tentar novamente
                                            publish_data["creation_id"] = alt_container_id
                                            # Não incrementar a contagem de tentativas
                                            publish_attempt -= 1
                                            # Aguardar um pouco para o container ser processado
                                            time.sleep(5)
                                            continue
                                except Exception as alt_err:
                                    instagram_logger.error(f"Erro na criação alternativa: {str(alt_err)}")

                            raise HTTPException(status_code=400, detail=f"Erro ao publicar: {error_message}")
                
                except Exception as e:
                    instagram_logger.error(f"Erro na tentativa de publicação {publish_attempt}: {str(e)}")
                    last_error = str(e)
                    if publish_attempt == max_publish_attempts:
                        raise HTTPException(status_code=400, detail=f"Erro ao publicar: {str(e)}")
                    time.sleep(5)

            if not publish_success:
                instagram_logger.error(f"Todas as tentativas de publicação falharam. Último erro: {last_error}")
                
                # Sugerir solução com base no erro
                sugestao = ""
                if "muito grande" in last_error.lower():
                    sugestao = " Tente com um vídeo menor (menos de 8MB)."
                elif "formato" in last_error.lower():
                    sugestao = " Tente com um vídeo no formato MP4."
                elif "limite" in last_error.lower():
                    sugestao = " Tente novamente amanhã quando o limite diário for reiniciado."
                elif "proporção" in last_error.lower():
                    sugestao = " Tente com um vídeo em formato vertical (9:16) para stories."
                
                raise HTTPException(
                    status_code=400,
                    detail=f"Não foi possível publicar o vídeo: {last_error}{sugestao}"
                )

            # Limpar arquivo temporário
            try:
                os.remove(video_path)
            except Exception as e:
                instagram_logger.warning(f"Erro ao remover arquivo temporário: {str(e)}")

            # Mensagem específica para o tipo de conteúdo
            content_type_msg = {
                "reel": "Reel publicado com sucesso",
                "feed": "Vídeo publicado com sucesso no feed",
                "story": "Story publicado com sucesso"
            }.get(body["type"].lower(), "Conteúdo publicado com sucesso")

            return {
                "status": "success",
                "message": content_type_msg if body["when"] == "now" else f"{body['type'].capitalize()} agendado com sucesso",
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
                    instagram_logger.debug(f"Arquivo temporário removido: {video_path}")
                
                # Limpar diretório de arquivos convertidos
                temp_converted_dir = os.path.join(os.path.dirname(video_path), "instagram_converted") if 'video_path' in locals() else None
                if temp_converted_dir and os.path.exists(temp_converted_dir):
                    instagram_logger.debug(f"Limpando diretório temporário: {temp_converted_dir}")
                    try:
                        for temp_file in os.listdir(temp_converted_dir):
                            file_path = os.path.join(temp_converted_dir, temp_file)
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                        os.rmdir(temp_converted_dir)
                    except Exception as cleanup_err:
                        instagram_logger.warning(f"Erro ao limpar diretório temporário: {str(cleanup_err)}")
            except Exception as e:
                instagram_logger.warning(f"Erro ao remover arquivos temporários: {str(e)}")

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
                instagram_logger.debug(f"Arquivo temporário removido: {video_path}")
            
            # Limpar diretório de arquivos convertidos
            temp_converted_dir = os.path.join(os.path.dirname(video_path), "instagram_converted") if 'video_path' in locals() else None
            if temp_converted_dir and os.path.exists(temp_converted_dir):
                instagram_logger.debug(f"Limpando diretório temporário: {temp_converted_dir}")
                try:
                    for temp_file in os.listdir(temp_converted_dir):
                        file_path = os.path.join(temp_converted_dir, temp_file)
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                    os.rmdir(temp_converted_dir)
                except Exception as cleanup_err:
                    instagram_logger.warning(f"Erro ao limpar diretório temporário: {str(cleanup_err)}")
        except Exception as e:
            instagram_logger.warning(f"Erro ao remover arquivos temporários: {str(e)}")

@router.post("/check-video")
async def check_video_url(
    request: Request,
    body: dict,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Verifica se uma URL de vídeo é adequada para publicação no Instagram.
    Útil para diagnosticar problemas antes de tentar publicar.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Validar campos obrigatórios
    if "video_url" not in body:
        raise HTTPException(status_code=400, detail="URL do vídeo é obrigatória")
    
    video_url = body["video_url"]
    result = {"url": video_url, "diagnostics": {}}
    
    try:
        # Verificar cabeçalhos
        head_response = requests.head(video_url, allow_redirects=True, timeout=10)
        result["status_code"] = head_response.status_code
        result["diagnostics"]["headers"] = dict(head_response.headers)
        
        # Verificar tipo de conteúdo
        content_type = head_response.headers.get('Content-Type', '')
        result["content_type"] = content_type
        result["is_video"] = content_type.startswith('video/')
        
        # Verificar tamanho
        content_length = head_response.headers.get('Content-Length')
        if content_length:
            size_bytes = int(content_length)
            size_mb = size_bytes / (1024 * 1024)
            result["size_bytes"] = size_bytes
            result["size_mb"] = round(size_mb, 2)
            
            # Adicionar recomendações
            result["recommendations"] = []
            if size_mb > 100:
                result["recommendations"].append("Vídeo muito grande, considere compressão")
            if size_mb > 15 and not result["is_video"]:
                result["recommendations"].append("Tamanho grande demais para story")
        
        # Baixar alguns bytes para verificar se é realmente um vídeo
        with requests.get(video_url, stream=True, timeout=5) as r:
            r.raise_for_status()
            # Ler os primeiros 20 bytes para identificação
            first_bytes = next(r.iter_content(20), b'')
            result["first_bytes_hex"] = first_bytes.hex()
            
            # Verificar assinatura de formato de vídeo comum
            is_mp4 = b'ftyp' in first_bytes
            result["likely_mp4"] = is_mp4
            
            if not is_mp4 and not result["is_video"]:
                result["recommendations"].append("Arquivo não parece ser um vídeo MP4 válido")
        
        return {
            "status": "success",
            "message": "Diagnóstico de vídeo concluído",
            "result": result
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Erro ao verificar vídeo: {str(e)}",
            "url": video_url
        }

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
            DELETE FROM instagram.instagram_sessions 
            WHERE user_id = %s 
            AND username = %s 
            AND is_active = TRUE
            """,
            [user_id, username],
            fetch=False
        )

        return {
            "status": "success",
            "message": f"Sessão revogada com sucesso para {username}. Por favor, reconecte sua conta do Instagram."
        }

    except Exception as e:
        print(f"Erro ao revogar sessão: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao revogar sessão: {str(e)}")

@router.post("/cleanup")
async def cleanup_instagram_sessions(
    request: Request,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Remove todas as sessões revogadas ou inativas do Instagram para o usuário.
    Útil para limpar o banco de dados de sessões antigas.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    try:
        # Remover todas as sessões inativas do usuário
        result = execute_query(
            "DELETE FROM instagram.instagram_sessions WHERE user_id = %s AND (is_active = FALSE OR status = 'revoked') RETURNING username",
            [user_id]
        )
        
        removed_count = len(result) if result else 0
        removed_usernames = [row["username"] for row in result] if result else []
        
        return {
            "status": "success",
            "message": f"Removidas {removed_count} sessões antigas ou revogadas",
            "removed_sessions": removed_usernames
        }
    except Exception as e:
        instagram_logger.error(f"Erro ao limpar sessões: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao limpar sessões: {str(e)}")

@router.get("/publishing-limit")
async def check_publishing_limit(
    request: Request,
    username: str,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Verifica o limite atual de publicações do Instagram.
    O Instagram limita a 50 publicações por dia (em período móvel de 24h).
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")
    
    # Buscar sessão do Instagram
    instagram_logger.info(f"Buscando sessão para usuário {user_id} e conta {username}")
    session = execute_query(
        """
        SELECT * FROM instagram.instagram_sessions 
        WHERE user_id = %s AND username = %s AND is_active = TRUE
        """,
        [user_id, username]
    )
    
    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão não encontrada para o usuário {username}")
    
    session_data = session[0]
    
    try:
        # Converter session_data de string para dict se necessário
        if isinstance(session_data["session_data"], str):
            session_data_dict = json.loads(session_data["session_data"])
        else:
            session_data_dict = session_data["session_data"]
        
        # Extrair o token de acesso
        access_token = session_data_dict.get("page_access_token") or session_data_dict.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Token de acesso não encontrado na sessão")
        
        # Limpar o token
        access_token = access_token.strip().strip('"').strip("'")
        
        # Obter ID da conta Instagram
        instagram_account_id = session_data_dict.get("account_id") or session_data_dict.get("id")
        if not instagram_account_id:
            raise HTTPException(status_code=400, detail="ID da conta Instagram não encontrado na sessão")
        
        # Consultar o limite de publicação
        limit_url = f"https://graph.instagram.com/v18.0/{instagram_account_id}/content_publishing_limit"
        limit_params = {
            "access_token": access_token,
            "fields": "config,quota_usage"
        }
        
        instagram_logger.debug(f"Consultando limite de publicação para {username}")
        limit_response = requests.get(limit_url, params=limit_params)
        
        if limit_response.status_code != 200:
            error_data = limit_response.json()
            friendly_error = interpret_instagram_error(error_data)
            raise HTTPException(status_code=400, detail=f"Erro ao verificar limite: {friendly_error}")
        
        # Processar resposta
        limit_data = limit_response.json()
        instagram_logger.debug(f"Resposta do limite: {json.dumps(limit_data)}")
        
        # Formatar resultados
        config = limit_data.get("config", {})
        quota_usage = limit_data.get("quota_usage", 0)
        
        result = {
            "username": username,
            "publicacoes_restantes": config.get("quota_total", 50) - quota_usage,
            "publicacoes_usadas": quota_usage,
            "limite_total": config.get("quota_total", 50),
            "intervalo_atualizacao": config.get("quota_usage_window", {"hours": 24}),
            "dados_brutos": limit_data
        }
        
        return {
            "status": "success",
            "message": f"Limite de publicação para {username}",
            "data": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        instagram_logger.error(f"Erro ao verificar limite de publicação: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao verificar limite de publicação: {str(e)}")
def convert_video_for_instagram(input_path, output_dir=None, is_tiktok=False):
    """
    Converte um vídeo para um formato compatível com o Instagram (MP4 com codec H.264).
    
    Args:
        input_path: Caminho do vídeo original
        output_dir: Diretório para salvar o vídeo convertido (opcional)
        is_tiktok: Indica se o vídeo é do TikTok (tratamento especial)
        
    Returns:
        Path do vídeo convertido ou None se falhar
    """
    instagram_logger.info(f"Iniciando conversão do vídeo: {input_path}")
    
    # Verificar se o vídeo existe
    if not os.path.exists(input_path):
        instagram_logger.error(f"Arquivo de vídeo não encontrado: {input_path}")
        return None
    
    # Criar diretório temporário para saída se não fornecido
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(input_path), "instagram_converted")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Gerar nome de arquivo único para saída
    random_id = uuid.uuid4().hex[:8]
    output_filename = f"instagram_compatible_{random_id}.mp4"
    output_path = os.path.join(output_dir, output_filename)
    
    # Tentar encontrar o caminho do FFmpeg
    ffmpeg_path = "ffmpeg"  # Padrão se estiver no PATH
    
    # Em sistemas Windows, procurar em locais comuns
    if os.name == 'nt':
        possible_paths = [
            r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
            r"C:\Users\gusta\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-7.1.1-full_build\bin\ffmpeg.exe",
            r"C:\ffmpeg\bin\ffmpeg.exe",
            r"ffmpeg.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                ffmpeg_path = path
                break
    else:
        # Para sistemas Unix (Linux/Ubuntu/Mac)
        possible_paths = [
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
            "/opt/homebrew/bin/ffmpeg",  # Para Mac com Homebrew
            "ffmpeg"  # Se estiver no PATH
        ]
        
        for path in possible_paths:
            try:
                # No Unix, podemos verificar se o comando existe com 'which'
                result = subprocess.run(["which", path], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    ffmpeg_path = result.stdout.strip()
                    break
            except:
                # Se 'which' falhar, tentar verificar diretamente
                if os.path.exists(path):
                    ffmpeg_path = path
                    break
        
    instagram_logger.debug(f"Usando FFmpeg em: {ffmpeg_path}")
    
    try:
        # Primeiro, obter informações sobre o vídeo original
        probe_command = [
            ffmpeg_path,
            "-i", input_path,
            "-v", "error"
        ]
        
        probe_process = subprocess.Popen(
            probe_command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        _, probe_stderr = probe_process.communicate()
        instagram_logger.debug(f"Informações do vídeo original: {probe_stderr}")
        
        # Verificar o tamanho do arquivo original
        file_size_mb = os.path.getsize(input_path) / (1024 * 1024)
        instagram_logger.debug(f"Tamanho do arquivo original: {file_size_mb:.2f} MB")
        
        # Comando FFmpeg para converter para MP4 com codec H.264 compatível com Instagram
        if is_tiktok:
            # Tratamento especial para vídeos do TikTok - conversão mais rigorosa
            instagram_logger.info("Usando conversão especial para vídeo do TikTok")
            
            # Comando específico para TikTok que usa parâmetros mais rigorosos
            command = [
                ffmpeg_path,
                "-i", input_path,
                "-c:v", "libx264",
                "-profile:v", "baseline",  # Perfil mais compatível
                "-level", "3.0",          # Nível de compatibilidade mais amplo
                "-preset", "slow",        # Melhor compressão
                "-crf", "28",             # Qualidade mais comprimida
                "-maxrate", "2500k",      # Limitar bitrate máximo
                "-bufsize", "5000k",      # Buffer para bitrate
                "-pix_fmt", "yuv420p",    # Formato de pixel padrão
                "-vf", "scale=720:-2,setsar=1:1",  # Apenas ajustar largura mantendo proporção
                "-c:a", "aac",
                "-b:a", "128k",
                "-ac", "2",               # 2 canais de áudio
                "-ar", "44100",           # Taxa de amostragem de áudio padrão
                "-movflags", "+faststart",
                "-metadata", "title=Instagram Video",
                "-y",
                output_path
            ]
        else:
            # Conversão padrão para outros vídeos com parâmetros mais compatíveis
            command = [
                ffmpeg_path,
                "-i", input_path,
                "-c:v", "libx264",         # Codec de vídeo H.264
                "-profile:v", "baseline",   # Perfil mais compatível
                "-level", "3.0",           # Nível de compatibilidade para dispositivos mais antigos
                "-preset", "slow",         # Melhor compressão
                "-crf", "26",              # Qualidade razoável com boa compressão
                "-maxrate", "2500k",       # Limitar bitrate máximo
                "-bufsize", "5000k",       # Buffer para bitrate
                "-vf", "scale=720:-2,setsar=1:1",  # Manter proporção original
                "-pix_fmt", "yuv420p",     # Formato de pixel padrão
                "-c:a", "aac",             # Codec de áudio AAC
                "-b:a", "128k",            # Bitrate do áudio
                "-ac", "2",                # 2 canais de áudio
                "-ar", "44100",            # Taxa de amostragem padrão
                "-movflags", "+faststart", # Otimiza para streaming
                "-y",                      # Sobrescrever se existir
                output_path
            ]
        
        instagram_logger.debug(f"Executando comando: {' '.join(command)}")
        
        # Executar FFmpeg
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Capturar saída
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            instagram_logger.error(f"Erro na conversão: {stderr}")
            
            # Tentar abordagem alternativa com parâmetros mais simples
            instagram_logger.info("Tentando método alternativo de conversão...")
            alt_command = [
                ffmpeg_path,
                "-i", input_path,
                "-c:v", "libx264",
                "-profile:v", "baseline",  # Mais compatível
                "-level", "3.0",
                "-preset", "slow",         # Melhor compressão
                "-crf", "28",              # Qualidade mais comprimida para garantir tamanho menor
                "-vf", "scale=720:-2",     # Escala com largura fixa mantendo proporção
                "-pix_fmt", "yuv420p",     # Formato de pixel padrão
                "-c:a", "aac",
                "-b:a", "128k",
                "-movflags", "+faststart",
                "-y",
                output_path
            ]
            
            instagram_logger.debug(f"Executando comando alternativo: {' '.join(alt_command)}")
            
            alt_process = subprocess.Popen(
                alt_command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            alt_stdout, alt_stderr = alt_process.communicate()
            
            if alt_process.returncode != 0:
                instagram_logger.error(f"Falha também no método alternativo: {alt_stderr}")
                
                # Tentar um terceiro método com configurações mínimas
                instagram_logger.info("Tentando método de conversão com configurações mínimas...")
                simple_command = [
                    ffmpeg_path,
                    "-i", input_path,
                    "-c:v", "libx264",
                    "-profile:v", "baseline",
                    "-preset", "fast",
                    "-pix_fmt", "yuv420p",
                    "-c:a", "aac",
                    "-y",
                    output_path
                ]
                
                instagram_logger.debug(f"Executando comando simples: {' '.join(simple_command)}")
                
                simple_process = subprocess.Popen(
                    simple_command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                simple_stdout, simple_stderr = simple_process.communicate()
                
                if simple_process.returncode != 0:
                    instagram_logger.error(f"Todos os métodos de conversão falharam. Último erro: {simple_stderr}")
                    return None
        
        # Verificar se o arquivo foi criado
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            output_size_mb = os.path.getsize(output_path) / (1024 * 1024)
            instagram_logger.info(f"Vídeo convertido com sucesso: {output_path} ({output_size_mb:.2f} MB)")
            return output_path
        else:
            instagram_logger.error("Arquivo de saída não existe ou está vazio")
            return None
        
    except Exception as e:
        instagram_logger.error(f"Erro ao converter vídeo: {str(e)}")
        return None

def upload_to_s3(file_path, bucket_name="zindex123", region="sa-east-1"):
    """
    Faz upload de um arquivo para um bucket S3 e retorna a URL pública.
    
    Args:
        file_path: Caminho do arquivo a ser enviado
        bucket_name: Nome do bucket S3
        region: Região AWS do bucket
        
    Returns:
        URL pública do arquivo no S3 ou None se falhar
    """
    instagram_logger.info(f"Iniciando upload para S3: {file_path}")
    
    if not os.path.exists(file_path):
        instagram_logger.error(f"Arquivo não encontrado: {file_path}")
        return None
    
    # Credenciais da AWS de variáveis de ambiente
    aws_access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    
    # Nome do arquivo no S3 (usando timestamp e nome original para evitar conflitos)
    filename = os.path.basename(file_path)
    timestamp = int(time.time())
    s3_filename = f"instagram_videos/{timestamp}_{filename}"
    
    try:
        # Criar cliente S3
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # Upload do arquivo
        instagram_logger.debug(f"Enviando arquivo para S3: {s3_filename}")
        s3_client.upload_file(
            file_path, 
            bucket_name, 
            s3_filename,
            ExtraArgs={'ContentType': 'video/mp4'}  # Removido ACL: 'public-read' que estava causando erro
        )
        
        # Gerar URL pública
        try:
            # Gerar URL pré-assinada válida por 24 horas (Instagram precisa de tempo para processar)
            instagram_logger.debug(f"Gerando URL pré-assinada para S3: {s3_filename}")
            s3_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket_name,
                    'Key': s3_filename
                },
                ExpiresIn=86400  # 24 horas
            )
            instagram_logger.info(f"Upload para S3 concluído com URL pré-assinada: {s3_url}")
        except Exception as url_err:
            instagram_logger.error(f"Erro ao gerar URL pré-assinada: {str(url_err)}")
            # Tentar URL padrão como fallback
            s3_url = f"https://{bucket_name}.s3.{region}.amazonaws.com/{s3_filename}"
            instagram_logger.info(f"Usando URL S3 padrão: {s3_url}")
        
        return s3_url
    
    except NoCredentialsError:
        instagram_logger.error("Credenciais da AWS inválidas")
        return None
    except ClientError as e:
        instagram_logger.error(f"Erro no cliente S3: {str(e)}")
        return None
    except Exception as e:
        instagram_logger.error(f"Erro ao fazer upload para S3: {str(e)}")
        return None

@router.post("/rate-limit-status")
async def rate_limit_status(
    request: Request,
    body: dict,
    jwt_token: str = Header(None, alias="jwt_token")
):
    """
    Endpoint para obter o status de limite de publicação do Instagram.
    """
    # Verificar JWT
    user_id = get_user_id_from_token(request, jwt_token)
    user = get_current_user(request, jwt_token)
    
    if not user:
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
                    DELETE FROM instagram.instagram_sessions 
                    WHERE user_id = %s 
                    AND username = %s 
                    AND is_active = TRUE
                    """,
                    [user_id, body["username"]],
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
            try:
                # Verificar se é URL do TikTok
                is_tiktok = "tiktok" in body["video_url"].lower()
                if is_tiktok:
                    instagram_logger.info("Detectada URL do TikTok, usando tratamento especial")
                
                # Verificar se a URL é acessível
                head_response = requests.head(body["video_url"], allow_redirects=True, timeout=10)
                head_response.raise_for_status()
                
                # Verificar o tipo de conteúdo
                content_type = head_response.headers.get('Content-Type', '')
                instagram_logger.debug(f"Tipo de conteúdo do vídeo: {content_type}")
                
                if not content_type.startswith('video/'):
                    instagram_logger.warning(f"URL pode não ser um vídeo direto. Content-Type: {content_type}")
                
                # Tentar obter o tamanho do vídeo
                content_length = head_response.headers.get('Content-Length')
                if content_length:
                    size_mb = int(content_length) / (1024 * 1024)
                    instagram_logger.debug(f"Tamanho do vídeo: {size_mb:.2f} MB")
                    
                    # Stories têm limite de tamanho
                    if body["type"].lower() == "story" and size_mb > 15:
                        instagram_logger.warning(f"Vídeo pode ser muito grande para story: {size_mb:.2f} MB (limite ~15MB)")
                
                # Baixar o vídeo com streaming
                video_response = requests.get(body["video_url"], stream=True, timeout=30)
                video_response.raise_for_status()
                
                # Criar arquivo temporário
                import tempfile
                temp_dir = tempfile.gettempdir()
                
                # Em ambientes de produção Linux/Ubuntu, usar um diretório mais adequado se possível
                if os.name != 'nt' and os.access('/var/tmp', os.W_OK):
                    temp_dir = '/var/tmp'  # Diretório mais adequado para arquivos temporários grandes no Linux
                
                video_path = os.path.join(temp_dir, f"video_{user_id}_{int(datetime.now().timestamp())}.mp4")
                
                # Salvar vídeo
                with open(video_path, 'wb') as f:
                    for chunk in video_response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                # Verificar se o arquivo foi criado corretamente
                if not os.path.exists(video_path) or os.path.getsize(video_path) == 0:
                    instagram_logger.error("Arquivo de vídeo vazio ou não criado")
                    raise HTTPException(status_code=400, detail="Erro ao baixar vídeo - arquivo inválido")
                
                video_size_mb = os.path.getsize(video_path) / (1024 * 1024)
                instagram_logger.debug(f"Vídeo baixado para: {video_path} ({video_size_mb:.2f} MB)")
                
                # Converter o vídeo para formato compatível com Instagram usando FFmpeg
                instagram_logger.info("Convertendo vídeo para formato compatível com Instagram...")
                try:
                    # Criar diretório temporário para vídeos convertidos
                    temp_converted_dir = os.path.join(temp_dir, "instagram_converted")
                    try:
                        os.makedirs(temp_converted_dir, exist_ok=True)
                        # Verificar se o diretório foi criado e tem permissões de escrita
                        if not os.path.exists(temp_converted_dir) or not os.access(temp_converted_dir, os.W_OK):
                            # Tentar diretório alternativo
                            instagram_logger.warning(f"Diretório {temp_converted_dir} não tem permissões de escrita, usando alternativa")
                            temp_converted_dir = os.path.join(tempfile.gettempdir(), f"instagram_conv_{uuid.uuid4().hex[:8]}")
                            os.makedirs(temp_converted_dir, exist_ok=True)
                    except Exception as dir_err:
                        # Se falhar em criar o diretório, usar um alternativo
                        instagram_logger.error(f"Erro ao criar diretório temporário: {str(dir_err)}")
                        temp_converted_dir = os.path.join(tempfile.gettempdir(), f"instagram_conv_{uuid.uuid4().hex[:8]}")
                        os.makedirs(temp_converted_dir, exist_ok=True)
                    
                    instagram_logger.debug(f"Diretório temporário para conversão: {temp_converted_dir}")
                    
                    # Converter o vídeo
                    converted_video_path = convert_video_for_instagram(video_path, temp_converted_dir)
                    
                    if converted_video_path and os.path.exists(converted_video_path):
                        instagram_logger.info(f"Vídeo convertido com sucesso: {converted_video_path}")
                        
                        # Substituir o caminho do vídeo original pelo convertido
                        video_path = converted_video_path
                        
                        # Fazer upload do vídeo convertido para o S3
                        instagram_logger.info("Enviando vídeo convertido para o S3...")
                        s3_video_url = upload_to_s3(video_path)
                        
                        if s3_video_url:
                            instagram_logger.info(f"Vídeo enviado com sucesso para o S3: {s3_video_url}")
                            # Substituir a URL original pelo link do S3
                            body["video_url"] = s3_video_url
                        else:
                            instagram_logger.warning("Falha ao enviar vídeo para S3, usando URL original")
                        
                        # Atualizar informações de tamanho
                        video_size_mb = os.path.getsize(video_path) / (1024 * 1024)
                        instagram_logger.debug(f"Vídeo convertido: {video_path} ({video_size_mb:.2f} MB)")
                    else:
                        instagram_logger.warning("Conversão de vídeo falhou, continuando com o vídeo original")
                except Exception as conv_err:
                    instagram_logger.error(f"Erro na conversão do vídeo: {str(conv_err)}")
                    instagram_logger.warning("Continuando com o vídeo original sem conversão")
                
                # Para TikTok, tentar fazer upload direto para o Instagram
                if is_tiktok and body["type"].lower() == "story":
                    instagram_logger.info("Para vídeos de TikTok, usando URL direta em vez de download")
                    # Continuar usando a URL direta neste caso
                
            except requests.RequestException as e:
                instagram_logger.error(f"Erro ao baixar vídeo: {str(e)}")
                if hasattr(e, 'response') and e.response:
                    instagram_logger.error(f"Status: {e.response.status_code}, Resposta: {e.response.text[:200]}")
                raise HTTPException(status_code=400, detail=f"Erro ao baixar vídeo: {str(e)}")
                
            except Exception as e:
                instagram_logger.error(f"Erro inesperado ao baixar vídeo: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Erro ao processar vídeo: {str(e)}")

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
            instagram_logger.info(f"Iniciando upload de {body['type'].lower()}")
            
            # Definir tipo de mídia e endpoint correto baseado no tipo de post
            if body["type"].lower() == "story":
                # Para stories, usar STORIES conforme documentação oficial
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "STORIES",  # Tipo correto para stories
                    "video_url": body["video_url"],
                    "access_token": access_token
                }
            elif body["type"].lower() == "reel":
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "REELS",  # Tipo específico para reels
                    "video_url": body["video_url"],
                    "caption": caption,
                    "access_token": access_token
                }
            else:  # feed
                container_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media"
                container_data = {
                    "media_type": "REELS",  # Usar REELS para vídeos de feed (conforme erro anterior)
                    "video_url": body["video_url"],
                    "caption": caption,
                    "access_token": access_token
                }

            # Postar com arquivo anexado
            try:
                container_response = requests.post(container_url, data=container_data)
                instagram_logger.debug(f"Resposta com upload direto: {container_response.text}")
            except Exception as upload_err:
                instagram_logger.error(f"Erro no upload direto: {str(upload_err)}")
                
                # Fallback para URL se o upload direto falhar
                instagram_logger.info("Fallback para método de URL após falha no upload direto")
                container_data = {
                    "media_type": "STORIES",  # Tipo correto para stories
                    "video_url": body["video_url"],
                    "access_token": access_token
                }
                container_response = requests.post(container_url, data=container_data)

            # Se for agendado, adicionar timestamp
            if body["when"] == "schedule" and body.get("schedule_date"):
                try:
                    schedule_time = datetime.fromisoformat(body["schedule_date"].replace('Z', '+00:00'))
                    container_data["publishing_type"] = "SCHEDULED"
                    container_data["scheduled_publish_time"] = int(schedule_time.timestamp())
                except ValueError as e:
                    instagram_logger.error(f"Data de agendamento inválida: {str(e)}")
                    raise HTTPException(status_code=400, detail=f"Data de agendamento inválida: {str(e)}")

            instagram_logger.debug(f"URL do container: {container_url}")
            instagram_logger.debug(f"Dados do container: {json.dumps(container_data)}")

            # Se não estiver usando o upload direto de arquivo, verifica a resposta aqui
            if 'container_response' not in locals() or container_response is None:
                container_response = requests.post(container_url, data=container_data)
                instagram_logger.debug(f"Resposta da criação do container: {container_response.text}")
            
            if container_response.status_code != 200:
                instagram_logger.error(f"Erro na criação do container: {container_response.text}")
                error_data = container_response.json()
                
                # Extrair e logar códigos de erro específicos
                if "error" in error_data:
                    error_code = error_data["error"].get("code")
                    error_subcode = error_data["error"].get("error_subcode")
                    instagram_logger.error(f"Erro na criação do container - Código: {error_code}, Subcódigo: {error_subcode}")
                    
                    # Tratamento específico para erro de formato de vídeo
                    if error_code == 352 or (error_subcode and error_subcode == 2207026):
                        instagram_logger.error("Erro de formato de vídeo detectado")
                        format_error_msg = """
Formato de vídeo não suportado pelo Instagram. A conversão automática não resolveu o problema.
Por favor, tente:

1. Usar apenas vídeos no formato MP4 ou MOV (MPEG-4 Part 14)
2. Verificar se a duração do vídeo está dentro dos limites permitidos:
   - Para Stories: entre 3 e 60 segundos
   - Para Reels: entre 3 segundos e 90 segundos
3. Garantir que o tamanho do arquivo é menor que 100MB
4. Usar codecs de vídeo H.264 ou H.265

Para vídeos do TikTok, é recomendado baixar o vídeo e convertê-lo com um software como o VLC antes de fazer upload.
"""
                        raise HTTPException(status_code=400, detail=format_error_msg)
                
                friendly_error = interpret_instagram_error(error_data)
                
                # Para vídeos do TikTok, adicionar sugestão específica
                if "tiktok" in body["video_url"].lower():
                    friendly_error += " Para vídeos do TikTok, tente baixar o vídeo localmente primeiro e depois fazer upload."
                
                raise HTTPException(status_code=400, detail=f"Erro ao criar container de mídia: {friendly_error}")
            
            container_response.raise_for_status()
            
            # Para stories, o processo agora é o mesmo dos vídeos normais,
            # mas com o parâmetro is_story
            container_id = container_response.json().get("id")
            if not container_id:
                instagram_logger.error("Falha ao obter ID do container")
                raise HTTPException(status_code=500, detail="Falha ao criar container de mídia")

            instagram_logger.info(f"Container criado com sucesso: {container_id}")

            # Verificar status do container antes de tentar publicar
            instagram_logger.info("Verificando status do container antes de publicar...")
            status_url = f"https://graph.instagram.com/v18.0/{container_id}"
            status_params = {"access_token": access_token, "fields": "status_code"}
            
            # Aguardar que o container esteja pronto para publicação
            # De acordo com a documentação, deve-se verificar no máximo 1x por minuto por até 5 minutos
            max_attempts = 10
            attempt = 0
            container_ready = False
            
            while attempt < max_attempts:
                attempt += 1
                instagram_logger.debug(f"Verificando status do container (tentativa {attempt}/{max_attempts})")
                
                try:
                    status_response = requests.get(status_url, params=status_params)
                    instagram_logger.debug(f"Resposta do status: {status_response.text}")
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status_code = status_data.get("status_code", "")
                        
                        if status_code == "FINISHED":
                            instagram_logger.info("Container pronto para publicação")
                            container_ready = True
                            break
                        elif status_code == "PUBLISHED":
                            instagram_logger.info("Container já foi publicado")
                            container_ready = True
                            break
                        elif status_code == "ERROR" or status_code == "EXPIRED":
                            # Tentar obter mais detalhes sobre o erro
                            error_details = ""
                            error_data = {}
                            try:
                                # Primeiro, tentar obter mais detalhes com o endpoint padrão
                                error_detail_url = f"https://graph.instagram.com/v18.0/{container_id}"
                                error_detail_params = {
                                    "access_token": access_token,
                                    "fields": "status_code,status,error"  # Adicionar o campo error
                                }
                                error_detail_response = requests.get(error_detail_url, params=error_detail_params)
                                instagram_logger.debug(f"Detalhes do erro (1): {error_detail_response.text}")
                                
                                if error_detail_response.status_code == 200:
                                    error_details = error_detail_response.text
                                    response_json = error_detail_response.json()
                                    
                                    # Verificar se temos o objeto error
                                    if "error" in response_json:
                                        error_data = response_json
                                        instagram_logger.debug(f"Encontrado objeto 'error' nos detalhes")
                                
                                # Se não conseguimos o objeto error, tentar fazer uma chamada que provavelmente falhará
                                # para obter uma resposta de erro completa
                                if not error_data.get("error"):
                                    instagram_logger.debug("Tentando obter detalhes do erro com chamada secundária")
                                    
                                    # Tentar publicar o container incorreto para forçar um erro detalhado
                                    invalid_publish_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media_publish"
                                    invalid_publish_params = {
                                        "creation_id": container_id,
                                        "access_token": access_token
                                    }
                                    
                                    try:
                                        error_response = requests.post(invalid_publish_url, data=invalid_publish_params)
                                        if error_response.status_code != 200 and "error" in error_response.json():
                                            error_data = error_response.json()
                                            instagram_logger.debug(f"Detalhes do erro (2): {error_response.text}")
                                    except Exception as pub_error:
                                        instagram_logger.error(f"Erro ao tentar obter detalhes secundários: {str(pub_error)}")
                                        
                            except Exception as detail_err:
                                instagram_logger.error(f"Erro ao obter detalhes: {str(detail_err)}")
                            
                            # Interpretar o erro
                            friendly_error = ""
                            if error_data and "error" in error_data:
                                instagram_logger.debug(f"Código de erro encontrado: {error_data['error'].get('code')}, Subcódigo: {error_data['error'].get('error_subcode')}")
                                friendly_error = interpret_instagram_error(error_data)
                            else:
                                # Códigos de status conhecidos
                                status_errors = {
                                    "ERROR": "Erro ao processar o vídeo. Verifique o formato e tamanho.",
                                    "EXPIRED": "O container expirou. Tente novamente.",
                                    "IN_PROGRESS": "O vídeo ainda está em processamento.",
                                    "PUBLISHED": "O vídeo já foi publicado.",
                                    "SCHEDULED": "O vídeo está agendado para publicação."
                                }
                                friendly_error = status_errors.get(status_code, f"Erro no processamento do container: {status_code}")
                                
                            error_msg = f"{friendly_error} Detalhes: {error_details}"
                            instagram_logger.error(error_msg)

                            # Para stories, tentar abordagem alternativa com REELS
                            if body["type"].lower() == "story" and attempt == 1:
                                instagram_logger.info("Tentando abordagem alternativa para story usando REELS...")
                                
                                # Criar novo container com tipo REELS para story
                                alt_container_data = {
                                    "media_type": "REELS",
                                    "video_url": body["video_url"],
                                    "caption": caption if caption else "Story",
                                    "access_token": access_token
                                }
                                
                                try:
                                    alt_container_response = requests.post(container_url, data=alt_container_data)
                                    instagram_logger.debug(f"Resposta da criação alternativa: {alt_container_response.text}")
                                    
                                    if alt_container_response.status_code == 200:
                                        container_id = alt_container_response.json().get("id")
                                        if container_id:
                                            instagram_logger.info(f"Container alternativo criado: {container_id}")
                                            continue  # Voltar para a verificação com o novo container
                                except Exception as alt_err:
                                    instagram_logger.error(f"Erro na criação alternativa: {str(alt_err)}")
                            
                            # Se tiver problemas com vídeos do TikTok, sugerir alternativa
                            if "tiktok" in body["video_url"].lower():
                                instagram_logger.warning("Vídeo do TikTok detectado - pode haver incompatibilidade")
                                sugestao = " Para vídeos do TikTok, tente baixar o vídeo localmente e depois fazer upload, ou use uma URL de vídeo de outra plataforma."
                            
                            # Sugestões com base no erro
                            sugestao = ""
                            if "muito grande" in error_msg.lower():
                                sugestao = " Tente com um vídeo menor (menos de 8MB)."
                            elif "formato" in error_msg.lower():
                                sugestao = " Tente com um vídeo no formato MP4."
                            elif "proporção" in error_msg.lower():
                                sugestao = " Tente com um vídeo em formato vertical (9:16) para stories."
                            
                            # Se não for story ou a abordagem alternativa falhar
                            raise HTTPException(status_code=400, detail=f"{friendly_error}{sugestao}")
                        elif status_code == "IN_PROGRESS":
                            instagram_logger.debug("Container ainda em processamento...")
                        else:
                            instagram_logger.warning(f"Status desconhecido: {status_code}")
                    else:
                        instagram_logger.warning(f"Erro ao verificar status (HTTP {status_response.status_code})")
                        
                        # Verificar se é um erro de limite de requisições
                        try:
                            error_data = status_response.json()
                            if "error" in error_data:
                                error_code = error_data["error"].get("code")
                                error_subcode = error_data["error"].get("error_subcode")
                                
                                # Códigos relacionados a limite de requisições
                                if error_code == 4 and error_subcode == 1349210:
                                    instagram_logger.warning("Limite de requisições da API atingido, aguardando mais tempo")
                                    time.sleep(10)  # Aguardar mais tempo antes da próxima tentativa
                                    continue
                                
                                # Logar o erro para diagnóstico
                                instagram_logger.error(f"Erro na verificação - Código: {error_code}, Subcódigo: {error_subcode}")
                                instagram_logger.error(f"Mensagem de erro: {error_data['error'].get('message')}")
                        except Exception as parse_err:
                            instagram_logger.error(f"Erro ao parsear resposta de erro: {str(parse_err)}")
                    
                    # Ajustar o tempo de espera baseado na tentativa
                    if attempt < 3:
                        time.sleep(60)  # Primeiras tentativas, aguardar 6 segundos
                    else:
                        time.sleep(60)  # Tentativas posteriores, aguardar mais tempo
                    
                except Exception as e:
                    instagram_logger.error(f"Erro ao verificar status: {str(e)}")
                    time.sleep(10)  # Em caso de erro, aguardar mais tempo
            
            if not container_ready:
                instagram_logger.error("Timeout aguardando processamento do container")
                raise HTTPException(
                    status_code=408,
                    detail="O vídeo está demorando muito para processar. Por favor, tente novamente com um vídeo menor ou aguarde alguns minutos."
                )

            # Tentar publicar
            instagram_logger.info("Iniciando publicação do vídeo")
            publish_url = f"https://graph.instagram.com/v18.0/{instagram_user_id}/media_publish"
            publish_data = {
                "creation_id": container_id,
                "access_token": access_token
            }

            instagram_logger.debug(f"URL de publicação: {publish_url}")
            instagram_logger.debug(f"Dados de publicação: {json.dumps(publish_data)}")

            # Tentar publicar algumas vezes
            max_publish_attempts = 3
            publish_attempt = 0
            publish_success = False
            publish_response = None
            last_error = None

            while publish_attempt < max_publish_attempts and not publish_success:
                publish_attempt += 1
                instagram_logger.info(f"Tentativa de publicação {publish_attempt}/{max_publish_attempts}")

                try:
                    # Publicar o container
                    publish_response = requests.post(publish_url, data=publish_data)
                    instagram_logger.debug(f"Resposta da publicação: {publish_response.text}")
                    
                    if publish_response.status_code == 200:
                        publish_success = True
                        break
                    else:
                        error_data = publish_response.json()
                        error_message = error_data.get('error', {}).get('message', 'Erro desconhecido')
                        friendly_error = interpret_instagram_error(error_data)
                        last_error = friendly_error
                        
                        instagram_logger.error(f"Erro de publicação: {error_message}")
                        instagram_logger.error(f"Erro interpretado: {friendly_error}")
                        
                        if "Media ID is not available" in error_message:
                            instagram_logger.warning("Mídia ainda não disponível, aguardando mais...")
                            time.sleep(5)  # Esperar mais 5 segundos antes da próxima tentativa
                        else:
                            # Para stories que falham, tentar converter o tipo
                            if body["type"].lower() == "story" and publish_attempt == 1:
                                instagram_logger.info("Tentando opção alternativa para story...")
                                
                                # Tentar criar novo container com REELS como alternativa
                                alt_container_data = {
                                    "media_type": "REELS",  # Tentar com REELS como alternativa
                                    "video_url": body["video_url"],
                                    "caption": caption if caption else "",
                                    "access_token": access_token
                                }
                                
                                try:
                                    alt_container_response = requests.post(
                                        f"https://graph.instagram.com/v18.0/{instagram_user_id}/media", 
                                        data=alt_container_data
                                    )
                                    
                                    instagram_logger.debug(f"Resposta da criação alternativa (REELS): {alt_container_response.text}")
                                    
                                    if alt_container_response.status_code == 200:
                                        alt_container_id = alt_container_response.json().get("id")
                                        if alt_container_id:
                                            instagram_logger.info(f"Container alternativo (REELS) criado: {alt_container_id}")
                                            # Atualizar ID para tentar novamente
                                            publish_data["creation_id"] = alt_container_id
                                            # Não incrementar a contagem de tentativas
                                            publish_attempt -= 1
                                            # Aguardar um pouco para o container ser processado
                                            time.sleep(5)
                                            continue
                                except Exception as alt_err:
                                    instagram_logger.error(f"Erro na criação alternativa: {str(alt_err)}")

                            raise HTTPException(status_code=400, detail=f"Erro ao publicar: {error_message}")
                
                except Exception as e:
                    instagram_logger.error(f"Erro na tentativa de publicação {publish_attempt}: {str(e)}")
                    last_error = str(e)
                    if publish_attempt == max_publish_attempts:
                        raise HTTPException(status_code=400, detail=f"Erro ao publicar: {str(e)}")
                    time.sleep(5)

            if not publish_success:
                instagram_logger.error(f"Todas as tentativas de publicação falharam. Último erro: {last_error}")
                
                # Sugerir solução com base no erro
                sugestao = ""
                if "muito grande" in last_error.lower():
                    sugestao = " Tente com um vídeo menor (menos de 8MB)."
                elif "formato" in last_error.lower():
                    sugestao = " Tente com um vídeo no formato MP4."
                elif "limite" in last_error.lower():
                    sugestao = " Tente novamente amanhã quando o limite diário for reiniciado."
                elif "proporção" in last_error.lower():
                    sugestao = " Tente com um vídeo em formato vertical (9:16) para stories."
                
                raise HTTPException(
                    status_code=400,
                    detail=f"Não foi possível publicar o vídeo: {last_error}{sugestao}"
                )

            # Limpar arquivo temporário
            try:
                os.remove(video_path)
            except Exception as e:
                instagram_logger.warning(f"Erro ao remover arquivo temporário: {str(e)}")

            # Mensagem específica para o tipo de conteúdo
            content_type_msg = {
                "reel": "Reel publicado com sucesso",
                "feed": "Vídeo publicado com sucesso no feed",
                "story": "Story publicado com sucesso"
            }.get(body["type"].lower(), "Conteúdo publicado com sucesso")

            return {
                "status": "success",
                "message": content_type_msg if body["when"] == "now" else f"{body['type'].capitalize()} agendado com sucesso",
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
                    instagram_logger.debug(f"Arquivo temporário removido: {video_path}")
                
                # Limpar diretório de arquivos convertidos
                temp_converted_dir = os.path.join(os.path.dirname(video_path), "instagram_converted") if 'video_path' in locals() else None
                if temp_converted_dir and os.path.exists(temp_converted_dir):
                    instagram_logger.debug(f"Limpando diretório temporário: {temp_converted_dir}")
                    try:
                        for temp_file in os.listdir(temp_converted_dir):
                            file_path = os.path.join(temp_converted_dir, temp_file)
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                        os.rmdir(temp_converted_dir)
                    except Exception as cleanup_err:
                        instagram_logger.warning(f"Erro ao limpar diretório temporário: {str(cleanup_err)}")
            except Exception as e:
                instagram_logger.warning(f"Erro ao remover arquivos temporários: {str(e)}")

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
                instagram_logger.debug(f"Arquivo temporário removido: {video_path}")
            
            # Limpar diretório de arquivos convertidos
            temp_converted_dir = os.path.join(os.path.dirname(video_path), "instagram_converted") if 'video_path' in locals() else None
            if temp_converted_dir and os.path.exists(temp_converted_dir):
                instagram_logger.debug(f"Limpando diretório temporário: {temp_converted_dir}")
                try:
                    for temp_file in os.listdir(temp_converted_dir):
                        file_path = os.path.join(temp_converted_dir, temp_file)
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                    os.rmdir(temp_converted_dir)
                except Exception as cleanup_err:
                    instagram_logger.warning(f"Erro ao limpar diretório temporário: {str(cleanup_err)}")
        except Exception as e:
            instagram_logger.warning(f"Erro ao remover arquivos temporários: {str(e)}")