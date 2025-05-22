from fastapi import APIRouter, Header, HTTPException
from app.models.user import LoginRequest
from app.services.auth import authenticate_user
from app.core.database import get_user_from_db
from app.core.security import verify_jwt

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login")
def login_user(request: LoginRequest):
    """
    Endpoint para autenticar usuário:
      - Recebe body com {email, password}.
      - Valida as credenciais.
      - Se válido, gera e retorna um JWT.
      - Se inválido, retorna erro 401.
    """
    return authenticate_user(request.email, request.password)

@router.get("/validate")
def validate_token(jwt_token: str = Header(...)):
    """
    Endpoint para validar um token JWT:
      - Recebe o JWT no header.
      - Verifica se o token é válido.
      - Verifica se o usuário associado existe/está ativo.
      - Se válido, retorna informações do usuário.
    """
    payload = verify_jwt(jwt_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuário inválido no token")

    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado ou inativo")

    return {"valid": True, "user_id": user_id} 