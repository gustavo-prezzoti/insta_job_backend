# Este arquivo torna o diretório app/api/routes um pacote Python

# Importa os módulos de rota para que possam ser importados com app.api.routes
from app.api.routes import auth, user, instagram, scheduled_posts, webhook

# Routes module initialization
from app.api.routes.auth import router as auth_router
from app.api.routes.user import router as user_router
from app.api.routes.instagram import router as instagram_router
from app.api.routes.scheduled_posts import router as scheduled_posts_router
from app.api.routes.webhook import router as webhook_router

# Export routers
auth = auth_router
user = user_router
instagram = instagram_router
scheduled_posts = scheduled_posts_router
webhook = webhook_router 