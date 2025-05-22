"""
Arquivo de inicialização para a aplicação ViralYX API.
Usado para iniciar a aplicação a partir da raiz do projeto.
"""
import os
import sys
import uvicorn
from app.services.scheduler import start_scheduler
from app.services.scheduled_posts import cron_posting

if __name__ == "__main__":
    print("Iniciando ViralYX API...")
    
    # Iniciar o agendador para posts programados
    scheduler = start_scheduler()
    
    # Importar app aqui para garantir que ele é importado após a limpeza dos diretórios temporários
    try:
        from app.main import app
        
        # Iniciar a aplicação FastAPI
        print("Iniciando servidor FastAPI...")
        # Usando porta 8000 em vez de 8080 para evitar problemas de permissão
        uvicorn.run(app, host="0.0.0.0", port=8000)
    except ModuleNotFoundError as e:
        print(f"Erro ao importar módulo FastAPI: {e}")
        print("Verificando instalação de dependências...")
        print("Execute 'pip install -r requirements.txt' para instalar as dependências necessárias.")
    except Exception as e:
        print(f"Erro ao iniciar servidor: {e}") 