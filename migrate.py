"""
Script para executar a migração do banco de dados.
Este script cria as tabelas necessárias e os índices para o projeto.
"""
from app.core.postgres import create_tables, create_indexes

if __name__ == "__main__":
    print("Iniciando migração do banco de dados...")
    
    # Criar tabelas
    create_tables()
    
    # Criar índices
    create_indexes()
    
    print("Migração concluída com sucesso!") 