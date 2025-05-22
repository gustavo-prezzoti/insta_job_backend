from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

# Imports absolutos
from app.core.config import CORS_ALLOW_ORIGINS, CORS_ALLOW_CREDENTIALS, CORS_ALLOW_METHODS, CORS_ALLOW_HEADERS, TEMP_DIR
from app.api.routes.auth import router as auth_router
from app.api.routes.user import router as user_router
from app.api.routes.instagram import router as instagram_router
from app.api.routes.instagram_oauth import router as instagram_oauth_router
from app.api.routes.scheduled_posts import router as scheduled_posts_router
from app.api.routes.webhook import router as webhook_router

# Criar diretório temporário se não existir
os.makedirs(TEMP_DIR, exist_ok=True)

# Limpar arquivos temporários existentes
for file in os.listdir(TEMP_DIR):
    try:
        os.remove(os.path.join(TEMP_DIR, file))
    except Exception as e:
        print(f"Erro ao remover arquivo temporário {file}: {str(e)}")

# Inicializar app
app = FastAPI(title="ViralYX API", version="1.0.0")

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=CORS_ALLOW_METHODS,
    allow_headers=CORS_ALLOW_HEADERS,
)

# Incluir rotas
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(instagram_router)
app.include_router(instagram_oauth_router)
app.include_router(scheduled_posts_router)
app.include_router(webhook_router)

# Rotas de status
@app.get("/")
def index():
    return {"status": "success", "message": "API do Viralyx está funcionando"}

@app.get("/health")
def health():
    return {"status": "success", "message": "API do Viralyx está funcionando"} 