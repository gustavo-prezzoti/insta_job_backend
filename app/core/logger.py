import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Criar diretório de logs se não existir
log_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
os.makedirs(log_directory, exist_ok=True)

def setup_instagram_logger():
    """
    Configura um logger específico para a API do Instagram
    """
    # Criar logger
    instagram_logger = logging.getLogger('instagram_api')
    instagram_logger.setLevel(logging.DEBUG)

    # Criar arquivo de log com rotação
    log_file = os.path.join(log_directory, 'instagram_api.log')
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )

    # Criar formatador
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)

    # Adicionar handler ao logger
    instagram_logger.addHandler(file_handler)

    return instagram_logger

# Criar instância do logger
instagram_logger = setup_instagram_logger() 