from datetime import datetime, timezone, timedelta
import jwt
from fastapi import HTTPException, Header, Request
from passlib.context import CryptContext
from app.core.config import JWT_SECRET, JWT_EXPIRATION
from app.services.auth import get_user_from_db

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Cria um hash seguro da senha usando bcrypt
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha em texto plano corresponde ao hash armazenado
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(f"Erro ao verificar senha: {e}")
        return False

def is_password_hashed(password: str) -> bool:
    """
    Verifica se a string já parece ser um hash bcrypt
    (útil para a migração de senhas existentes)
    """
    try:
        return password.startswith('$2')
    except Exception:
        return False

def create_jwt_token(user_id: int, plan_id: str = None) -> str:
    """
    Create a JWT token for the user
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + JWT_EXPIRATION
    }
    
    if plan_id:
        payload["plan_id"] = plan_id
        
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt(token: str):
    """Valida o JWT e retorna o payload (deve conter user_id)."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="JWT inválido")

def get_jwt_from_request(request: Request, jwt_token: str = None):
    """
    Extrai o JWT do header 'jwt_token', 'jwt-token' ou 'Authorization: Bearer ...'.
    """
    # Tenta pegar do header customizado
    if jwt_token:
        return jwt_token
    # Tenta pegar do header com hífen
    jwt_token_hyphen = request.headers.get("jwt-token")
    if jwt_token_hyphen:
        return jwt_token_hyphen
    # Tenta pegar do Authorization padrão
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]
    raise HTTPException(status_code=401, detail="JWT não fornecido no header (jwt_token, jwt-token ou Authorization)")

def get_user_id_from_token(request: Request, jwt_token: str = Header(None, alias="jwt_token")):
    """
    Extrai o user_id do token JWT enviado via header 'jwt_token', 'jwt-token' ou 'Authorization: Bearer ...'.
    """
    token = get_jwt_from_request(request, jwt_token)
    payload = verify_jwt(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuário inválido no token")
    return user_id

def get_current_user(request: Request, jwt_token: str = Header(None, alias="jwt_token")):
    """
    Valida o JWT enviado via header 'jwt_token', 'jwt-token' ou 'Authorization: Bearer ...' e retorna o usuário atual.
    """
    try:
        token = get_jwt_from_request(request, jwt_token)
        payload = verify_jwt(token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Usuário inválido no token")
        user = get_user_from_db(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        # Verificar se o usuário está ativo
        status = user.get("status", "active")
        if status != "active":
            raise HTTPException(status_code=403, detail="Usuário inativo")
        return user
    except HTTPException:
        raise
    except Exception as e:
        print(f"Erro ao obter usuário: {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao verificar usuário") 