import os
from datetime import timedelta
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
load_dotenv(dotenv_path)

# Diretórios
TEMP_DIR = os.environ.get("TEMP_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "temporary"))

# JWT Config
JWT_SECRET = os.environ.get("JWT_SECRET", "ultra_secret_key_change_in_production")
JWT_EXPIRATION = timedelta(days=int(os.environ.get("JWT_EXPIRATION_DAYS", "7")))

# Supabase Config
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

# AWS SES Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_SES_SENDER = os.environ.get("AWS_SES_SENDER", "no-reply@example.com")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

# SOAX Proxy Configuration
SOAX_USERNAME = os.environ.get("SOAX_USERNAME", "")
SOAX_PASSWORD = os.environ.get("SOAX_PASSWORD", "")
SOAX_API_KEY = os.environ.get("SOAX_API_KEY", "")

# CORS Settings
CORS_ALLOW_ORIGINS = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["*"]
CORS_ALLOW_HEADERS = ["*"]

# Webhook Configuration
WEBHOOK_SECRET_TOKEN = os.environ.get("WEBHOOK_SECRET_TOKEN", "webhook_secret_change_in_production")

# Domain for URLs
DOMAIN = os.environ.get("DOMAIN", "http://localhost:8081")

# Instagram Graph API Configuration
INSTAGRAM_CLIENT_ID = os.environ.get("INSTAGRAM_CLIENT_ID", "")
INSTAGRAM_CLIENT_SECRET = os.environ.get("INSTAGRAM_CLIENT_SECRET", "")
INSTAGRAM_REDIRECT_URI = os.environ.get("INSTAGRAM_REDIRECT_URI", f"{DOMAIN}/instagram/oauth/callback")
INSTAGRAM_GRAPH_API_VERSION = os.environ.get("INSTAGRAM_GRAPH_API_VERSION", "v19.0")
FACEBOOK_GRAPH_API_BASE_URL = os.environ.get("FACEBOOK_GRAPH_API_BASE_URL", "https://graph.facebook.com") 