import hmac
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Header
from app.models.webhook import SubscriptionWebhook
from app.core.postgres import execute_query
from app.core.config import WEBHOOK_SECRET_TOKEN
from app.services.email import send_email

router = APIRouter(prefix="/webhook", tags=["Webhooks"])

@router.post("/subscription")
async def subscription_webhook(webhook: SubscriptionWebhook, signature: str = None, request: Request = None):
    """
    Webhook para receber notificações de assinaturas
    """
    try:
        # Log webhook request information for debugging
        if request:
            print(f"[WEBHOOK] Headers: {dict(request.headers)}")

        # Get the raw request body for signature validation
        body_bytes = await request.body()
        body_str = body_bytes.decode()

        # Verify the signature
        SECRET_TOKEN = WEBHOOK_SECRET_TOKEN

        # Calculate signature from the request body
        calculated_signature = hmac.new(
            SECRET_TOKEN.encode(),
            body_str.encode(),
            hashlib.sha1
        ).hexdigest()

        print(f"[WEBHOOK] Signature recebida: {signature}")
        print(f"[WEBHOOK] Signature calculada: {calculated_signature}")

        # Compare signatures
        if signature != calculated_signature:
            print(f"[WEBHOOK] Assinatura inválida")
            return {"status": "error", "message": "Assinatura inválida"}

        print(f"[WEBHOOK] Recebido webhook de assinatura: {webhook.data.subscription_id}")

        # Check webhook event type if available
        if hasattr(webhook.data, 'webhook_event_type') and webhook.data.webhook_event_type != "order_approved":
            return {"status": "success", "message": "Webhook recebido com sucesso"}

        # Extract relevant data
        subscription = webhook.data
        subscription_id = subscription.subscription_id
        start_date = subscription.start_date
        next_payment = subscription.next_payment
        status = subscription.status

        # Check if plan information is available
        if hasattr(subscription, 'plan'):
            product_id = subscription.plan.id
            product_name = subscription.plan.name
        elif hasattr(subscription, 'product'):
            product_id = subscription.product.id
            product_name = subscription.product.name
        else:
            product_id = "unknown"
            product_name = "unknown"

        # Buscar o usuário pelo ID da assinatura
        user_response = execute_query("""
            SELECT *
            FROM kiwify_users
            WHERE subscription_id = %s
        """, (subscription_id,))

        if user_response:
            # Usuário encontrado, atualizar informações de assinatura
            user = user_response[0]
            user_id = user["id"]

            print(f"[WEBHOOK] Atualizando assinatura para usuário ID: {user_id}")

            # Atualizar informações no banco de dados
            update_data = {
                "transaction_id": webhook.data.order_id if hasattr(webhook.data, 'order_id') else None,
                "current_plan_start_date": start_date,
                "current_plan_end_date": next_payment if status == "active" else None,
                "status": "active" if status == "active" else "inactive",
                "subscription_id": subscription_id,
                "product_id": product_id,
                "product_name": product_name,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

            execute_query("""
                UPDATE kiwify_users
                SET transaction_id = %s,
                    current_plan_start_date = %s,
                    current_plan_end_date = %s,
                    status = %s,
                    subscription_id = %s,
                    product_id = %s,
                    product_name = %s,
                    updated_at = %s
                WHERE id = %s
            """, (
                update_data["transaction_id"],
                update_data["current_plan_start_date"],
                update_data["current_plan_end_date"],
                update_data["status"],
                update_data["subscription_id"],
                update_data["product_id"],
                update_data["product_name"],
                update_data["updated_at"],
                user_id
            ))

            # Send email notification about subscription update
            try:
                user_email = user.get("email")
                if user_email:
                    # Format dates for better readability
                    formatted_start = datetime.fromisoformat(start_date).strftime("%d/%m/%Y")
                    formatted_end = "Recorrente" if not next_payment else datetime.fromisoformat(next_payment).strftime("%d/%m/%Y")

                    # Prepare email content
                    email_subject = f"Sua Assinatura do Viralyx foi Atualizada"
                    email_text = f"""
Olá {user.get('name', 'Cliente')},

Sua assinatura do Viralyx foi atualizada com sucesso.

Detalhes da assinatura:
- Plano: {product_name}
- Status: {"Ativo" if status == "active" else "Inativo"}
- Data de início: {formatted_start}

Se você tiver alguma dúvida sobre sua assinatura, entre em contato com nossa equipe de suporte.

Atenciosamente,
Equipe Viralyx
"""

                    # HTML version using the new template
                    email_html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIRALYX.AI - Assinatura Atualizada</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
            background-color: #000;
            padding: 15px;
            border-radius: 8px;
        }}
        .logo img {{
            max-width: 250px;
        }}
        h1 {{
            color: #4a00e0;
            text-align: center;
            margin-bottom: 20px;
        }}
        .credentials {{
            background-color: #f7f7f7;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
            border-left: 4px solid #4a00e0;
        }}
        .credentials p {{
            margin: 8px 0;
            font-size: 16px;
        }}
        .button-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .button {{
            display: inline-block;
            background-color: #4a00e0;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            font-size: 16px;
        }}
        .note {{
            font-size: 14px;
            color: #666;
            border-top: 1px solid #eee;
            padding-top: 20px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="logo">
        <div style="color: white; font-size: 24px; font-weight: bold; margin-bottom: 5px;">VIRALYX.AI</div>
        <div style="color: white; font-size: 14px;">INTELIGÊNCIA ARTIFICIAL VIRAL</div>
    </div>

    <h1>Sua assinatura foi atualizada!</h1>

    <p>Olá {user.get('name', 'Cliente')},</p>

    <p>Sua assinatura do VIRALYX.AI foi atualizada com sucesso!</p>

    <p>Estamos felizes em informar que sua compra na Kiwify foi aprovada com sucesso!</p>

    <div class="credentials">
        <p><strong>Plano:</strong> {product_name}</p>
        <p><strong>Status:</strong> {"Ativo" if status == "active" else "Inativo"}</p>
        <p><strong>Data de início:</strong> {formatted_start}</p>
    </div>

    <div class="button-container">
        <a href="https://www.viralyx.ai/login" class="button">Acessar minha conta</a>
    </div>

    <p>Caso tenha qualquer dúvida ou precise de suporte, não hesite em nos contatar.</p>

    <p>Agradecemos por escolher a VIRALYX.AI!</p>

    <div class="note">
        <p>Este é um e-mail automático. Por favor, não responda diretamente a esta mensagem.</p>
    </div>
</body>
</html>
"""

                    # Send the email
                    send_email(
                        recipient=user_email,
                        subject=email_subject,
                        body_text=email_text,
                        body_html=email_html
                    )
            except Exception as email_err:
                print(f"[WEBHOOK] Erro ao enviar email de atualização: {str(email_err)}")
                # Continue even if email fails

            return {"status": "success", "message": f"Assinatura atualizada para usuário ID: {user_id}"}

        else:
            # Cria novo usuário
            # Check if customer data is available in the expected format
            try:
                if hasattr(webhook.data, 'customer'):
                    customer = webhook.data.customer
                    customer_email = customer.email
                    customer_name = customer.full_name
                else:
                    # Fallback to looking for customer data in other locations
                    customer_email = webhook.data.email if hasattr(webhook.data, 'email') else "unknown@example.com"
                    customer_name = webhook.data.name if hasattr(webhook.data, 'name') else "Unknown User"

                print(f"[WEBHOOK] Criando novo usuário com email: {customer_email}")

                # Generate a secure random password
                import secrets
                import string
                from app.core.security import hash_password
                random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))

                user_data = {
                    "email": customer_email,
                    "name": customer_name,
                    "password": hash_password(random_password),  # Secure password instead of email+123456
                    "force_password_change": True,  # Force password change on first login
                    "status": "active" if status == "active" else "inactive",
                    "subscription_id": subscription_id,
                    "product_id": product_id,
                    "product_name": product_name,
                    "current_plan_start_date": start_date,
                    "current_plan_end_date": next_payment if status == "active" else None,
                    "transaction_id": webhook.data.order_id if hasattr(webhook.data, 'order_id') else None,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }

                print(f"[WEBHOOK] Inserindo novo usuário no banco de dados")
                execute_query("""
                    INSERT INTO kiwify_users (email, name, password, force_password_change, status, subscription_id, product_id, product_name, current_plan_start_date, current_plan_end_date, transaction_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_data["email"],
                    user_data["name"],
                    user_data["password"],
                    user_data["force_password_change"],
                    user_data["status"],
                    user_data["subscription_id"],
                    user_data["product_id"],
                    user_data["product_name"],
                    user_data["current_plan_start_date"],
                    user_data["current_plan_end_date"],
                    user_data["transaction_id"],
                    user_data["created_at"],
                    user_data["updated_at"]
                ))
                print(f"[WEBHOOK] Novo usuário criado com sucesso: {customer_email}")

                # Send welcome email with temporary password
                try:
                    # Format dates for better readability
                    formatted_start = datetime.fromisoformat(start_date).strftime("%d/%m/%Y")
                    formatted_end = "Recorrente" if not next_payment else datetime.fromisoformat(next_payment).strftime("%d/%m/%Y")

                    # Prepare email content
                    email_subject = f"VIRALYX.AI - Sua compra foi aprovada!"
                    email_text = f"""
Olá {customer_name},

Estamos felizes em informar que sua compra na Kiwify foi aprovada com sucesso! Seja bem-vindo(a) ao VIRALYX.AI, sua plataforma de Inteligência Artificial Viral.

Para começar a usar nosso sistema, criamos uma senha temporária para você. Por favor, utilize as credenciais abaixo para fazer seu primeiro acesso:

Login: {customer_email}
Senha temporária: {random_password}

Importante: Por motivos de segurança, você será solicitado(a) a alterar esta senha temporária no seu primeiro acesso ao sistema.

Detalhes da assinatura:
- Plano: {product_name}
- Status: {"Ativo" if status == "active" else "Inativo"}
- Data de início: {formatted_start}
- Próximo pagamento: {formatted_end}

Caso tenha qualquer dúvida ou precise de suporte, não hesite em nos contatar.

Agradecemos por escolher a VIRALYX.AI!

Este é um e-mail automático. Por favor, não responda diretamente a esta mensagem.
"""

                    # HTML version using the provided template
                    email_html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIRALYX.AI - Compra Aprovada</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
            background-color: #000;
            padding: 15px;
            border-radius: 8px;
        }}
        .logo img {{
            max-width: 250px;
        }}
        h1 {{
            color: #4a00e0;
            text-align: center;
            margin-bottom: 20px;
        }}
        .credentials {{
            background-color: #f7f7f7;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
            border-left: 4px solid #4a00e0;
        }}
        .credentials p {{
            margin: 8px 0;
            font-size: 16px;
        }}
        .button-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .button {{
            display: inline-block;
            background-color: #4a00e0;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            font-size: 16px;
        }}
        .note {{
            font-size: 14px;
            color: #666;
            border-top: 1px solid #eee;
            padding-top: 20px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="logo">
        <div style="color: white; font-size: 24px; font-weight: bold; margin-bottom: 5px;">VIRALYX.AI</div>
        <div style="color: white; font-size: 14px;">INTELIGÊNCIA ARTIFICIAL VIRAL</div>
    </div>

    <h1>Sua compra foi aprovada!</h1>

    <p>Olá {customer_name},</p>

    <p>Estamos felizes em informar que sua compra na Kiwify foi aprovada com sucesso! Seja bem-vindo(a) ao VIRALYX.AI, sua plataforma de Inteligência Artificial Viral.</p>

    <p>Para começar a usar nosso sistema, criamos uma senha temporária para você. Por favor, utilize as credenciais abaixo para fazer seu primeiro acesso:</p>

    <div class="credentials">
        <p><strong>Login:</strong> {customer_email}</p>
        <p><strong>Senha temporária:</strong> {random_password}</p>
    </div>

    <p><strong>Importante:</strong> Por motivos de segurança, você será solicitado(a) a alterar esta senha temporária no seu primeiro acesso ao sistema.</p>

    <div class="credentials">
        <p><strong>Detalhes da assinatura:</strong></p>
        <p><strong>Plano:</strong> {product_name}</p>
        <p><strong>Status:</strong> {"Ativo" if status == "active" else "Inativo"}</p>
        <p><strong>Data de início:</strong> {formatted_start}</p>
    </div>

    <div class="button-container">
        <a href="https://www.viralyx.ai/login" class="button">Acessar minha conta</a>
    </div>

    <p>Caso tenha qualquer dúvida ou precise de suporte, não hesite em nos contatar.</p>

    <p>Agradecemos por escolher a VIRALYX.AI!</p>

    <div class="note">
        <p>Este é um e-mail automático. Por favor, não responda diretamente a esta mensagem.</p>
    </div>
</body>
</html>
"""

                    # Send the email
                    send_email(
                        recipient=customer_email,
                        subject=email_subject,
                        body_text=email_text,
                        body_html=email_html
                    )
                except Exception as email_err:
                    print(f"[WEBHOOK] Erro ao enviar email de boas-vindas: {str(email_err)}")
                    # Continue even if email fails

                return {"status": "success", "message": "Novo usuário criado com sucesso"}

            except Exception as user_err:
                print(f"[WEBHOOK] Erro ao criar novo usuário: {str(user_err)}")
                return {"status": "error", "message": f"Erro ao criar usuário: {str(user_err)}"}

    except Exception as e:
        print(f"[WEBHOOK] Erro ao processar webhook de assinatura: {str(e)}")
        # Return 200 OK even on error to prevent retries, but log the error
        return {"status": "error"} 