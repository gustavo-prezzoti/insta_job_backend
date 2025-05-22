"""
Arquivo de inicialização para a aplicação ViralYX API.
Usado para iniciar a aplicação a partir da raiz do projeto.
"""
import os
import uvicorn
import sys

# Adiciona o diretório raiz ao path para que os imports funcionem corretamente
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.config import TEMP_DIR
from app.services.scheduled_posts import cron_posting

# Criar diretório temporário se não existir
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

# Limpar arquivos temporários existentes
for file in os.listdir(TEMP_DIR):
    try:
        os.remove(os.path.join(TEMP_DIR, file))
    except Exception as e:
        print(f"Erro ao remover arquivo temporário {file}: {str(e)}")

if __name__ == "__main__":
    try:
        # Tentar importar o APScheduler
        from apscheduler.schedulers.background import BackgroundScheduler

        # Configurar o scheduler
        scheduler = BackgroundScheduler()

        # Adicionar a tarefa para executar a cada 10 minutos
        scheduler.add_job(cron_posting, 'interval', minutes=10, id='instagram_posting')

        # Iniciar o scheduler
        scheduler.start()

        print("Iniciando API com agendador de tarefas automático...")
        print("Tarefa de postagem do Instagram agendada para executar a cada 10 minutos")

    except ImportError:
        # Fallback para quando APScheduler não está instalado
        import threading
        import time

        print("APScheduler não encontrado. Para instalar, execute:")
        print("pip install apscheduler")
        print("\nUsando método alternativo para agendamento...")

        def scheduler_thread():
            """Thread simples que executa a função cron_posting a cada 10 minutos"""
            while True:
                try:
                    print("Executando verificação de posts agendados...")
                    cron_posting()
                except Exception as e:
                    print(f"Erro na execução da rotina de agendamento: {str(e)}")

                # Aguardar 10 minutos
                time.sleep(600)  # 10 minutos em segundos

        # Iniciar a thread de agendamento
        scheduler_t = threading.Thread(target=scheduler_thread, daemon=True)
        scheduler_t.start()

        print("Thread de agendamento iniciada. Posts serão verificados a cada 10 minutos.")

    # Importar app aqui para garantir que ele é importado após a limpeza dos diretórios temporários
    from app.main import app
    
    # Iniciar a aplicação FastAPI
    uvicorn.run(app, host="0.0.0.0", port=8000) 