import os
import time
import threading
from datetime import datetime, timezone, timedelta
from app.core.config import TEMP_DIR
from app.services.scheduled_posts import cron_posting

def initialize_temp_directory():
    """Inicializa o diretório temporário e limpa arquivos existentes"""
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Limpar arquivos temporários existentes
    for file in os.listdir(TEMP_DIR):
        try:
            os.remove(os.path.join(TEMP_DIR, file))
        except Exception as e:
            print(f"Erro ao remover arquivo temporário {file}: {str(e)}")

def start_scheduler():
    """Inicializa e executa o agendador de tarefas de cron"""
    # Garantir que o diretório temporário existe e está limpo
    initialize_temp_directory()

    # Tentar usar APScheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler

        # Configurar o scheduler
        scheduler = BackgroundScheduler()

        # Adicionar a tarefa para executar a cada 10 minutos
        scheduler.add_job(cron_posting, 'interval', minutes=10, id='instagram_posting')

        # Iniciar o scheduler
        scheduler.start()

        print("Agendador iniciado com sucesso")
        print("Tarefa de postagem do Instagram agendada para executar a cada 10 minutos")

        return scheduler

    except ImportError:
        # Fallback para quando APScheduler não está instalado
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

        return scheduler_t
        
    except Exception as e:
        print(f"Erro ao inicializar agendador: {e}")
        return None 