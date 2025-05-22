import boto3
from botocore.exceptions import ClientError
from app.core.config import AWS_REGION, AWS_SES_SENDER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def send_email(recipient, subject, body_text, body_html=None):
    """
    Send an email using AWS SES.

    Args:
        recipient: Email address of the recipient
        subject: Email subject
        body_text: Plain text email body
        body_html: HTML email body (optional)

    Returns:
        Dictionary with status and message
    """
    try:
        # Create a new SES resource with credentials
        ses_client = boto3.client(
            'ses',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY
        ) if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY else boto3.client('ses', region_name=AWS_REGION)

        # Prepare email message
        message = {
            'Subject': {
                'Data': subject,
                'Charset': 'UTF-8'
            },
            'Body': {
                'Text': {
                    'Data': body_text,
                    'Charset': 'UTF-8'
                }
            }
        }

        # Add HTML body if provided
        if body_html:
            message['Body']['Html'] = {
                'Data': body_html,
                'Charset': 'UTF-8'
            }

        # Send the email
        response = ses_client.send_email(
            Source=AWS_SES_SENDER,
            Destination={
                'ToAddresses': [recipient]
            },
            Message=message
        )

        print(f"[EMAIL] Email enviado para {recipient}, Message ID: {response['MessageId']}")
        return {"status": "success", "message_id": response['MessageId']}

    except ClientError as e:
        print(f"[EMAIL] Erro ao enviar email para {recipient}: {e.response['Error']['Message']}")
        return {"status": "error", "message": e.response['Error']['Message']}
    except Exception as e:
        print(f"[EMAIL] Erro ao enviar email para {recipient}: {str(e)}")
        return {"status": "error", "message": str(e)} 