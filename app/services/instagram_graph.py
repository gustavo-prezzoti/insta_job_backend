import json
import os
import requests
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from fastapi import HTTPException

from app.core.config import (
    FACEBOOK_GRAPH_API_BASE_URL,
    INSTAGRAM_CLIENT_ID,
    INSTAGRAM_CLIENT_SECRET,
    INSTAGRAM_REDIRECT_URI,
    INSTAGRAM_GRAPH_API_VERSION,
    TEMP_DIR
)
from app.core.postgres import execute_query
from app.utils.serialization import serialize_session_data

# Base URL for Graph API
GRAPH_API_URL = f"{FACEBOOK_GRAPH_API_BASE_URL}/{INSTAGRAM_GRAPH_API_VERSION}"


def generate_instagram_auth_url(redirect_uri: Optional[str] = None) -> str:
    """
    Generate Instagram Business Login authorization URL for OAuth flow (novo padrão Meta 2024).
    Args:
        redirect_uri: Optional custom redirect URI (defaults to config value)
    Returns:
        Authorization URL to redirect user to
    """
    if not INSTAGRAM_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Instagram Client ID not configured")

    final_redirect_uri = redirect_uri or INSTAGRAM_REDIRECT_URI

    # Novos escopos obrigatórios para Instagram Business Login
    scopes = [
        "instagram_business_basic",
        "instagram_business_content_publish",
        "instagram_business_manage_messages",
        "instagram_business_manage_comments"
    ]

    # Parâmetros extras para forçar login pelo Instagram (não Facebook)
    extra_params = "&enable_fb_login=0&force_authentication=1"

    # Novo endpoint Instagram Business Login
    auth_url = (
        f"https://www.instagram.com/oauth/authorize"
        f"?client_id={INSTAGRAM_CLIENT_ID}"
        f"&redirect_uri={final_redirect_uri}"
        f"&response_type=code"
        f"&scope={','.join(scopes)}"
        f"{extra_params}"
    )
    return auth_url


def exchange_code_for_token(code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
    """
    Exchange authorization code for access token.
    
    Args:
        code: Authorization code from callback
        redirect_uri: Optional custom redirect URI (defaults to config value)
        
    Returns:
        Dictionary with token information
    """
    print(f"[INSTAGRAM_API] Iniciando troca de código por token. Code length: {len(code)}")
    
    if not INSTAGRAM_CLIENT_ID or not INSTAGRAM_CLIENT_SECRET:
        print("[INSTAGRAM_API] ERRO: Credenciais da API não configuradas")
        raise HTTPException(status_code=500, detail="Instagram API credentials not configured")
    
    final_redirect_uri = redirect_uri or INSTAGRAM_REDIRECT_URI
    print(f"[INSTAGRAM_API] Redirect URI: {final_redirect_uri}")
    
    # Make token exchange request
    try:
        print(f"[INSTAGRAM_API] Enviando requisição para trocar código por token...")
        
        # Usar o endpoint oficial do Instagram em vez do Graph API do Facebook
        url = "https://api.instagram.com/oauth/access_token"
        data = {
            "client_id": INSTAGRAM_CLIENT_ID,
            "client_secret": INSTAGRAM_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "redirect_uri": final_redirect_uri,
            "code": code
        }
        
        print(f"[INSTAGRAM_API] Request URL: {url}")
        print(f"[INSTAGRAM_API] Payload: client_id={INSTAGRAM_CLIENT_ID[:5]}..., redirect_uri={final_redirect_uri}")
        
        response = requests.post(url, data=data)
        
        print(f"[INSTAGRAM_API] Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[INSTAGRAM_API] ERRO: Resposta não-200: {response.text}")
        
        response.raise_for_status()
        token_data = response.json()
        
        print(f"[INSTAGRAM_API] Token data recebido: {token_data.keys()}")
        
        # Se não precisar converter para token de longa duração, retornar diretamente
        return token_data
        
    except requests.RequestException as e:
        print(f"[INSTAGRAM_API] ERRO ao trocar código por token: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"[INSTAGRAM_API] Response content: {e.response.text}")
        raise HTTPException(status_code=400, detail=f"Failed to exchange code for token: {str(e)}")


def exchange_for_long_lived_token(short_lived_token: str) -> Dict[str, Any]:
    """
    Exchange short-lived token for long-lived token.
    
    Args:
        short_lived_token: Short-lived access token
        
    Returns:
        Dictionary with long-lived token information
    """
    print(f"[INSTAGRAM_API] Convertendo token de curta duração para longa duração...")
    
    try:
        url = f"{FACEBOOK_GRAPH_API_BASE_URL}/{INSTAGRAM_GRAPH_API_VERSION}/oauth/access_token"
        params = {
            "grant_type": "fb_exchange_token",
            "client_id": INSTAGRAM_CLIENT_ID,
            "client_secret": INSTAGRAM_CLIENT_SECRET,
            "fb_exchange_token": short_lived_token
        }
        
        print(f"[INSTAGRAM_API] Request URL: {url}")
        print(f"[INSTAGRAM_API] Params: client_id={INSTAGRAM_CLIENT_ID[:5]}...")
        
        response = requests.get(url, params=params)
        
        print(f"[INSTAGRAM_API] Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[INSTAGRAM_API] ERRO: Resposta não-200: {response.text}")
            
        response.raise_for_status()
        token_data = response.json()
        
        print(f"[INSTAGRAM_API] Long-lived token obtido, expires_in: {token_data.get('expires_in', 'N/A')}")
        
        # Add expiry timestamp
        if "expires_in" in token_data:
            expiry_time = datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])
            token_data["expires_at"] = expiry_time.isoformat()
            print(f"[INSTAGRAM_API] Token expira em: {expiry_time.isoformat()}")
            
        return token_data
        
    except requests.RequestException as e:
        print(f"[INSTAGRAM_API] ERRO ao trocar por token de longa duração: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"[INSTAGRAM_API] Response content: {e.response.text}")
        raise HTTPException(status_code=400, detail=f"Failed to obtain long-lived token: {str(e)}")


def get_user_accounts(access_token: str) -> list:
    """
    Get user's Instagram business accounts.
    
    Args:
        access_token: Facebook access token
        
    Returns:
        List of Instagram business accounts
    """
    print(f"[INSTAGRAM_API] Obtendo contas do usuário com token: {access_token[:10]}...")
    
    try:
        # First, get user's Facebook pages
        print(f"[INSTAGRAM_API] Buscando páginas do Facebook do usuário...")
        response = requests.get(
            f"{GRAPH_API_URL}/me/accounts",
            params={"access_token": access_token}
        )
        
        print(f"[INSTAGRAM_API] Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[INSTAGRAM_API] ERRO: Resposta não-200: {response.text}")
            
        response.raise_for_status()
        pages = response.json().get("data", [])
        
        print(f"[INSTAGRAM_API] Páginas encontradas: {len(pages)}")
        
        instagram_accounts = []
        
        # For each page, get connected Instagram business account
        for i, page in enumerate(pages):
            page_id = page["id"]
            page_name = page.get("name", "Unknown")
            page_access_token = page["access_token"]
            
            print(f"[INSTAGRAM_API] Verificando página {i+1}/{len(pages)}: {page_name} (ID: {page_id})")
            
            ig_response = requests.get(
                f"{GRAPH_API_URL}/{page_id}",
                params={
                    "fields": "instagram_business_account{id,name,username,profile_picture_url}",
                    "access_token": page_access_token
                }
            )
            
            print(f"[INSTAGRAM_API] Instagram response status: {ig_response.status_code}")
            
            if ig_response.status_code != 200:
                print(f"[INSTAGRAM_API] ERRO ao buscar conta Instagram para página {page_id}: {ig_response.text}")
                continue
                
            ig_data = ig_response.json()
            
            if "instagram_business_account" in ig_data:
                instagram_account = ig_data["instagram_business_account"]
                instagram_account["page_id"] = page_id
                instagram_account["page_access_token"] = page_access_token
                instagram_accounts.append(instagram_account)
                print(f"[INSTAGRAM_API] Conta Instagram encontrada: {instagram_account.get('username', 'Unknown')}")
            else:
                print(f"[INSTAGRAM_API] Nenhuma conta Instagram conectada para a página {page_name}")
        
        print(f"[INSTAGRAM_API] Total de contas Instagram encontradas: {len(instagram_accounts)}")
        return instagram_accounts
        
    except requests.RequestException as e:
        print(f"[INSTAGRAM_API] ERRO ao buscar contas do usuário: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"[INSTAGRAM_API] Response content: {e.response.text}")
        raise HTTPException(status_code=400, detail=f"Failed to retrieve Instagram accounts: {str(e)}")


def create_instagram_session(user_id: int, account_data: Dict[str, Any], token_data: Dict[str, Any]):
    """
    Create a new Instagram Graph API session.
    If a session for the same username already exists, update it instead of creating a new one.
    
    Args:
        user_id: User ID in our system
        account_data: Instagram account data
        token_data: Access token data
        
    Returns:
        Created or updated session data
    """
    try:
        username = account_data.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Username not found in account data")
        
        # Prepare session data to be stored
        session_data = {
            "account_id": account_data.get("id"),
            "page_id": account_data.get("page_id"),
            "access_token": token_data.get("access_token"),
            "expires_at": token_data.get("expires_at")
        }
        
        # Calculate expiry time for session record
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        if token_data.get("expires_at"):
            try:
                token_expiry = datetime.fromisoformat(token_data["expires_at"])
                if token_expiry < expires_at:
                    expires_at = token_expiry
            except (ValueError, TypeError):
                pass

        # Check if a session for this username and user already exists
        existing_session = execute_query(
            "SELECT * FROM instagram_sessions WHERE user_id = %s AND username = %s",
            [user_id, username]
        )

        current_time = datetime.now(timezone.utc).isoformat()

        if existing_session:
            # Update existing session
            print(f"[INSTAGRAM_API] Sessão para {username} já existe, removendo sessões antigas...")
            
            # Remover (não apenas desativar) todas as sessões existentes para este usuário+username
            execute_query(
                "DELETE FROM instagram_sessions WHERE user_id = %s AND username = %s",
                [user_id, username],
                fetch=False
            )
            
            # Criar nova sessão ativa
            result = execute_query(
                """INSERT INTO instagram_sessions 
                (user_id, username, session_data, status, is_active, account_type, expires_at, created_at, updated_at) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) 
                RETURNING *""",
                [
                    user_id,
                    username,
                    serialize_session_data(session_data),
                    "active",
                    True,
                    "graph_api",
                    expires_at.isoformat(),
                    current_time,
                    current_time
                ]
            )
            
            return result[0] if result else None
        else:
            # Create new session
            print(f"[INSTAGRAM_API] Criando nova sessão para {username}...")
            
            result = execute_query(
                """INSERT INTO instagram_sessions 
                (user_id, username, session_data, status, is_active, account_type, expires_at, created_at, updated_at) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) 
                RETURNING *""",
                [
                    user_id,
                    username,
                    serialize_session_data(session_data),
                    "active",
                    True,
                    "graph_api",
                    expires_at.isoformat(),
                    current_time,
                    current_time
                ]
            )
            
            return result[0] if result else None
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating Instagram session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create Instagram session: {str(e)}")


def get_instagram_session(user_id: int, username: str):
    """
    Get Instagram session for user and username.
    
    Args:
        user_id: User ID
        username: Instagram username
        
    Returns:
        Session data or None if not found
    """
    response = execute_query("SELECT * FROM instagram_sessions WHERE user_id = %s AND username = %s AND is_active = %s", [user_id, username, True])
    return response[0] if response else None


def check_token_validity(session_data: Dict[str, Any]) -> bool:
    """
    Check if Instagram access token is still valid.
    
    Args:
        session_data: Session data with access token
        
    Returns:
        True if token is valid, False otherwise
    """
    if isinstance(session_data, str):
        try:
            session_data = json.loads(session_data)
        except json.JSONDecodeError:
            return False
    
    # Check if token present
    access_token = session_data.get("access_token")
    if not access_token:
        return False
    
    # Check if expires_at is present and not expired
    expires_at = session_data.get("expires_at")
    if expires_at:
        try:
            expiry_time = datetime.fromisoformat(expires_at)
            if expiry_time <= datetime.now(timezone.utc):
                return False
        except (ValueError, TypeError):
            pass
    
    # Verify token with a simple API call
    try:
        response = requests.get(
            f"{GRAPH_API_URL}/me",
            params={"access_token": access_token}
        )
        return response.status_code == 200
    except:
        return False


def publish_to_instagram(
    session_data,
    post_type,
    video_url,
    caption,
    hashtags,
    user_id=None,
    username=None,
    schedule_type="now",
    session_id=None
):
    """
    Publish content to Instagram using Graph API.
    
    Args:
        session_data: Instagram session data with access token
        post_type: Type of post (feed, reel, story)
        video_url: URL of video to publish
        caption: Caption for the post
        hashtags: Hashtags for the post
        user_id: User ID in our system
        username: Instagram username
        schedule_type: Type of scheduling (now, schedule)
        session_id: ID of the session record
        
    Returns:
        Dict with result details
    """
    print(f"Publishing to Instagram with Graph API: {post_type}, {video_url}")
    
    # Parse session data
    if isinstance(session_data, str):
        try:
            session_data = json.loads(session_data)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid session data format")
    
    # Extract credentials
    access_token = session_data.get("access_token")
    ig_account_id = session_data.get("account_id")
    
    if not access_token or not ig_account_id:
        raise HTTPException(status_code=400, detail="Missing access token or account ID")
    
    # Download video if it's a remote URL
    video_temp_path = None
    try:
        if video_url.startswith(('http://', 'https://')):
            os.makedirs(TEMP_DIR, exist_ok=True)
            
            # Create a unique filename
            video_filename = f"{uuid.uuid4()}.mp4"
            video_temp_path = os.path.join(TEMP_DIR, video_filename)
            
            # Download the video
            print(f"Downloading video from {video_url}")
            with requests.get(video_url, stream=True) as r:
                r.raise_for_status()
                with open(video_temp_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            print(f"Video downloaded to {video_temp_path}")
            local_video_path = video_temp_path
        else:
            # Local file path
            local_video_path = video_url
        
        # Combine caption and hashtags
        full_caption = caption
        if hashtags:
            full_caption += "\n\n" + hashtags
        
        # Handle different post types
        instagram_post_id = None
        instagram_url = None
        
        if post_type == "feed":
            # Publish as feed video
            result = publish_video_to_feed(ig_account_id, access_token, local_video_path, full_caption)
            instagram_post_id = result.get("id")
            if instagram_post_id:
                instagram_url = f"https://www.instagram.com/p/{instagram_post_id}/"
        
        elif post_type == "reel":
            # Publish as reel
            result = publish_reel(ig_account_id, access_token, local_video_path, full_caption)
            instagram_post_id = result.get("id")
            if instagram_post_id:
                instagram_url = f"https://www.instagram.com/reel/{instagram_post_id}/"
        
        elif post_type == "story":
            # Publish as story
            result = publish_story(ig_account_id, access_token, local_video_path)
            instagram_post_id = result.get("id")
            if instagram_post_id and username:
                instagram_url = f"https://www.instagram.com/stories/{username}/{instagram_post_id}/"
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported post type: {post_type}")
        
        # Record publication in database
        if user_id and username and instagram_post_id:
            try:
                post_data = {
                    "user_id": user_id,
                    "session_id": session_id,
                    "username": username,
                    "post_type": post_type,
                    "caption": caption,
                    "hashtags": hashtags,
                    "schedule_type": schedule_type,
                    "instagram_post_id": str(instagram_post_id),
                    "instagram_url": instagram_url,
                    "video_url": video_url,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                execute_query("INSERT INTO instagram_posts (user_id, session_id, username, post_type, caption, hashtags, schedule_type, instagram_post_id, instagram_url, video_url, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", [
                    post_data["user_id"],
                    post_data["session_id"],
                    post_data["username"],
                    post_data["post_type"],
                    post_data["caption"],
                    post_data["hashtags"],
                    post_data["schedule_type"],
                    post_data["instagram_post_id"],
                    post_data["instagram_url"],
                    post_data["video_url"],
                    post_data["created_at"]
                ])
            except Exception as db_err:
                print(f"Error recording post in database: {str(db_err)}")
                # Continue even if database recording fails
        
        return {
            "detail": "Post published successfully",
            "media_id": instagram_post_id,
            "permalink": instagram_url
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error publishing to Instagram: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to publish to Instagram: {str(e)}")
    
    finally:
        # Clean up temporary file
        if video_temp_path and os.path.exists(video_temp_path):
            try:
                os.unlink(video_temp_path)
                print(f"Temporary video file removed: {video_temp_path}")
            except Exception as e:
                print(f"Error removing temporary file: {str(e)}")


def publish_video_to_feed(ig_account_id, access_token, video_path, caption):
    """
    Publish video to Instagram feed using Graph API.
    This is a multi-step process:
    1. Create a media container
    2. Publish the container
    
    Args:
        ig_account_id: Instagram account ID
        access_token: Access token
        video_path: Path to video file
        caption: Caption for the post
        
    Returns:
        Dict with result details
    """
    try:
        # Step 1: Create a media container
        with open(video_path, 'rb') as video_file:
            container_response = requests.post(
                f"{GRAPH_API_URL}/{ig_account_id}/media",
                params={
                    "access_token": access_token,
                    "media_type": "VIDEO",
                    "caption": caption,
                    "video_url": "https://www.example.com/placeholder.mp4"  # Placeholder, will be replaced
                },
                files={
                    "video": video_file
                }
            )
            
            if container_response.status_code != 200:
                print(f"Error creating media container: {container_response.text}")
                raise HTTPException(status_code=400, detail="Failed to initialize video upload")
            
            container_data = container_response.json()
            container_id = container_data.get("id")
            
            if not container_id:
                raise HTTPException(status_code=400, detail="No container ID received")
        
        # Step 2: Wait for container to be ready (status check)
        status = "IN_PROGRESS"
        max_checks = 10
        for _ in range(max_checks):
            status_response = requests.get(
                f"{GRAPH_API_URL}/{container_id}",
                params={
                    "access_token": access_token,
                    "fields": "status_code,status"
                }
            )
            
            status_data = status_response.json()
            status = status_data.get("status_code", "")
            
            if status == "FINISHED":
                break
                
            if status == "ERROR":
                error_msg = status_data.get("status", {}).get("error_message", "Unknown error")
                raise HTTPException(status_code=400, detail=f"Error processing video: {error_msg}")
                
            # Wait a bit before checking again
            import time
            time.sleep(3)
        
        if status != "FINISHED":
            raise HTTPException(status_code=400, detail="Video processing timed out")
            
        # Step 3: Publish the container
        publish_response = requests.post(
            f"{GRAPH_API_URL}/{ig_account_id}/media_publish",
            params={
                "access_token": access_token,
                "creation_id": container_id
            }
        )
        
        if publish_response.status_code != 200:
            print(f"Error publishing media: {publish_response.text}")
            raise HTTPException(status_code=400, detail="Failed to publish video")
            
        return publish_response.json()
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in publish_video_to_feed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error publishing video: {str(e)}")


def publish_reel(ig_account_id, access_token, video_path, caption):
    """
    Publish video as a reel using Graph API.
    
    Args:
        ig_account_id: Instagram account ID
        access_token: Access token
        video_path: Path to video file
        caption: Caption for the reel
        
    Returns:
        Dict with result details
    """
    try:
        # Similar to feed videos but with different media_type
        with open(video_path, 'rb') as video_file:
            container_response = requests.post(
                f"{GRAPH_API_URL}/{ig_account_id}/media",
                params={
                    "access_token": access_token,
                    "media_type": "REELS",
                    "caption": caption,
                    "video_url": "https://www.example.com/placeholder.mp4"  # Placeholder
                },
                files={
                    "video": video_file
                }
            )
            
            if container_response.status_code != 200:
                print(f"Error creating reel container: {container_response.text}")
                raise HTTPException(status_code=400, detail="Failed to initialize reel upload")
            
            container_data = container_response.json()
            container_id = container_data.get("id")
            
            if not container_id:
                raise HTTPException(status_code=400, detail="No container ID received")
        
        # Wait for container to be ready
        status = "IN_PROGRESS"
        max_checks = 10
        for _ in range(max_checks):
            status_response = requests.get(
                f"{GRAPH_API_URL}/{container_id}",
                params={
                    "access_token": access_token,
                    "fields": "status_code,status"
                }
            )
            
            status_data = status_response.json()
            status = status_data.get("status_code", "")
            
            if status == "FINISHED":
                break
                
            if status == "ERROR":
                error_msg = status_data.get("status", {}).get("error_message", "Unknown error")
                raise HTTPException(status_code=400, detail=f"Error processing reel: {error_msg}")
                
            # Wait before checking again
            import time
            time.sleep(3)
        
        if status != "FINISHED":
            raise HTTPException(status_code=400, detail="Reel processing timed out")
            
        # Publish the container
        publish_response = requests.post(
            f"{GRAPH_API_URL}/{ig_account_id}/media_publish",
            params={
                "access_token": access_token,
                "creation_id": container_id
            }
        )
        
        if publish_response.status_code != 200:
            print(f"Error publishing reel: {publish_response.text}")
            raise HTTPException(status_code=400, detail="Failed to publish reel")
            
        return publish_response.json()
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in publish_reel: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error publishing reel: {str(e)}")


def publish_story(ig_account_id, access_token, video_path):
    """
    Publish video as a story using Graph API.
    
    Args:
        ig_account_id: Instagram account ID
        access_token: Access token
        video_path: Path to video file
        
    Returns:
        Dict with result details
    """
    try:
        # Stories have a simpler process than feed videos
        with open(video_path, 'rb') as video_file:
            response = requests.post(
                f"{GRAPH_API_URL}/{ig_account_id}/stories",
                params={
                    "access_token": access_token,
                    "media_type": "VIDEO"
                },
                files={
                    "video": video_file
                }
            )
            
            if response.status_code != 200:
                print(f"Error publishing story: {response.text}")
                raise HTTPException(status_code=400, detail="Failed to publish story")
                
            return response.json()
    
    except Exception as e:
        print(f"Error in publish_story: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error publishing story: {str(e)}")


def delete_instagram_session(session_id: int):
    """
    Delete Instagram session.
    
    Args:
        session_id: Session ID
        
    Returns:
        Updated session data
    """
    response = execute_query("UPDATE instagram_sessions SET is_active = %s WHERE id = %s RETURNING *", [False, session_id])
    return response[0] if response else None


def exchange_code_for_token_instagram(code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
    """
    Troca o code por access_token usando o endpoint oficial Instagram Business Login.
    Args:
        code: Authorization code from callback
        redirect_uri: Optional custom redirect URI (defaults to config value)
    Returns:
        Dictionary with token information
    """
    if not INSTAGRAM_CLIENT_ID or not INSTAGRAM_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Instagram API credentials not configured")

    final_redirect_uri = redirect_uri or INSTAGRAM_REDIRECT_URI
    url = "https://api.instagram.com/oauth/access_token"
    data = {
        "client_id": INSTAGRAM_CLIENT_ID,
        "client_secret": INSTAGRAM_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "redirect_uri": final_redirect_uri,
        "code": code
    }
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            msg += f" | {e.response.text}"
        raise HTTPException(status_code=400, detail=f"Failed to exchange code for token: {msg}") 