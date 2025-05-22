"""
Script para criar um usuário administrador padrão no sistema
"""
from app.core.postgres import execute_query
from app.core.security import hash_password
from datetime import datetime, timezone

def create_default_user():
    # Configurações do usuário default
    email = "teste@teste.com"
    name = "Administrador"
    # Senha "admin123" hasheada com bcrypt
    password = hash_password("teste")
    
    # Data atual formatada para timestamp
    current_time = datetime.now(timezone.utc).isoformat()
    
    # Query para inserir o usuário
    query = """
    INSERT INTO instagram.kiwify_users
    (email, name, password, force_password_change, status, 
    subscription_id, current_plan_id, current_plan_start_date, current_plan_end_date, 
    product_id, product_name, transaction_id, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    RETURNING id;
    """
    
    # Parâmetros para a query
    params = (
        email, name, password, True, "active",
        "default_sub", "admin_plan", current_time, 
        datetime.now(timezone.utc).replace(year=2030).isoformat(),  # Plano válido até 2030
        "admin_product", "Plano Administrador", "manual_creation",
        current_time, current_time
    )
    
    try:
        result = execute_query(query, params)
        user_id = result[0]['id'] if result else None
        
        if user_id:
            print(f"Usuário administrador criado com sucesso! ID: {user_id}")
            print(f"Email: {email}")
            print(f"Senha: admin123")
            print("Importante: Altere a senha após o primeiro login!")
        else:
            print("Falha ao criar usuário. Verifique se já existe um usuário com o mesmo email.")
    except Exception as e:
        print(f"Erro ao criar usuário: {e}")

if __name__ == "__main__":
    create_default_user() 