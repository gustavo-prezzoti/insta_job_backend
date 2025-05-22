import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

# Configurações de conexão com o PostgreSQL
PG_HOST = "aws-0-sa-east-1.pooler.supabase.com"
PG_DATABASE = "postgres"
PG_USER = "postgres.qrkoibgclfeanzossjem"
PG_PASSWORD = "Cap0199**"
PG_PORT = "5432"
PG_SCHEMA = "instagram"

@contextmanager
def get_db_connection(use_schema=True):
    """
    Cria e gerencia conexão com o banco PostgreSQL.
    
    Args:
        use_schema: Se True, define o search_path para o schema PG_SCHEMA
    
    Exemplo de uso:
    ```
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM tabela")
            resultado = cursor.fetchall()
    ```
    """
    connection = None
    try:
        # Conectar usando os parâmetros, sem definir o schema ainda
        connection = psycopg2.connect(
            host=PG_HOST,
            database=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD,
            port=PG_PORT,
            cursor_factory=RealDictCursor
        )
        connection.autocommit = False
        
        # Se use_schema=True, definir o search_path para o schema especificado
        if use_schema:
            with connection.cursor() as cursor:
                cursor.execute(f"SET search_path TO {PG_SCHEMA}")
                connection.commit()
                
        yield connection
    except Exception as e:
        print(f"Erro ao conectar com PostgreSQL: {e}")
        raise
    finally:
        if connection:
            connection.close()

def execute_query(query, params=None, fetch=True, commit=True, use_schema=True):
    """
    Executa uma query no banco de dados.
    
    Args:
        query: Query SQL a ser executada
        params: Parâmetros para a query (opcional)
        fetch: Se True, retorna os resultados da query
        commit: Se True, faz commit das alterações
        use_schema: Se True, usa o schema definido em PG_SCHEMA
        
    Returns:
        Resultados da query se fetch=True, None caso contrário
    """
    try:
        with get_db_connection(use_schema=use_schema) as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, params or {})
                
                if fetch:
                    result = cursor.fetchall()
                else:
                    result = None
                    
                if commit:
                    conn.commit()
                    
        return result
    except Exception as e:
        print(f"Erro ao executar query: {e}")
        print(f"Query: {query}")
        print(f"Params: {params}")
        raise

def create_schema():
    """
    Cria o schema se não existir.
    """
    schema_query = f"CREATE SCHEMA IF NOT EXISTS {PG_SCHEMA}"
    # Usar use_schema=False para não definir o search_path ao criar o schema
    execute_query(schema_query, fetch=False, use_schema=False)
    print(f"Schema {PG_SCHEMA} criado ou verificado com sucesso!")

def create_tables():
    """
    Cria as tabelas necessárias no banco de dados se elas não existirem.
    """
    # Primeiro garantir que o schema exista
    create_schema()
    
    # Definições das tabelas - agora com schema explícito
    tables = [
        f"""
        CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.kiwify_users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            password VARCHAR(255) NOT NULL,
            force_password_change BOOLEAN DEFAULT FALSE,
            status VARCHAR(50) DEFAULT 'active',
            subscription_id VARCHAR(255),
            current_plan_id VARCHAR(255),
            current_plan_start_date TIMESTAMP WITH TIME ZONE,
            current_plan_end_date TIMESTAMP WITH TIME ZONE,
            product_id VARCHAR(255),
            product_name VARCHAR(255),
            transaction_id VARCHAR(255),
            last_login TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.instagram_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username VARCHAR(255) NOT NULL,
            session_data TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'active',
            is_active BOOLEAN DEFAULT TRUE,
            account_type VARCHAR(50) DEFAULT 'instagrapi',
            expires_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.instagram_posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            session_id INTEGER,
            username VARCHAR(255) NOT NULL,
            post_type VARCHAR(50) NOT NULL,
            caption TEXT,
            hashtags TEXT,
            schedule_type VARCHAR(50) DEFAULT 'now',
            instagram_post_id VARCHAR(255),
            instagram_url VARCHAR(255),
            video_url TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.instagram_scheduled_posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username VARCHAR(255) NOT NULL,
            type VARCHAR(50) NOT NULL,
            video_url TEXT NOT NULL,
            caption TEXT,
            tags TEXT,
            status VARCHAR(50) DEFAULT 'pendente',
            error_message TEXT,
            schedule_for TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    
    # Executar criação de cada tabela
    for table_query in tables:
        execute_query(table_query, fetch=False)
    
    print("Tabelas criadas com sucesso!")
    
# Índices para melhorar performance
def create_indexes():
    """
    Cria índices para melhorar a performance das consultas.
    """
    indexes = [
        f"CREATE INDEX IF NOT EXISTS idx_kiwify_users_email ON {PG_SCHEMA}.kiwify_users (email)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_sessions_user_id ON {PG_SCHEMA}.instagram_sessions (user_id)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_sessions_username ON {PG_SCHEMA}.instagram_sessions (username)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_sessions_active ON {PG_SCHEMA}.instagram_sessions (is_active)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_posts_user_id ON {PG_SCHEMA}.instagram_posts (user_id)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_scheduled_posts_user_id ON {PG_SCHEMA}.instagram_scheduled_posts (user_id)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_scheduled_posts_status ON {PG_SCHEMA}.instagram_scheduled_posts (status)",
        f"CREATE INDEX IF NOT EXISTS idx_instagram_scheduled_posts_schedule_for ON {PG_SCHEMA}.instagram_scheduled_posts (schedule_for)"
    ]
    
    for index_query in indexes:
        execute_query(index_query, fetch=False)
        
    print("Índices criados com sucesso!") 