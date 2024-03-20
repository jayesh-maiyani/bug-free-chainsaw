# tasks.py

from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMessage, get_connection
import tempfile, requests

otp_mail_connection = get_connection(
    host = settings.EMAIL_HOST,
    use_tls = settings.EMAIL_USE_TLS,
    port = settings.EMAIL_PORT,
    username = settings.OTP_EMAIL,
    password = settings.OTP_EMAIL_PASSWORD
)

@shared_task
def send_info_email_task(recipients, subject, message):
    # Your email sending code here
    # Example: send email using Django's EmailMessage

    try:
        email = EmailMessage(
            subject=subject,
            body=message,
            to=recipients,
            connection = otp_mail_connection
        )
        
        email.content_subtype = "html"
        email.send()
    except Exception as e:
        pass


@shared_task
def send_otp_email_task(recipients, subject, message):
    # Your email sending code here
    # Example: send email using Django's EmailMessage

    try:
        email = EmailMessage(
            subject=subject,
            body=message,
            to=recipients,
            connection = otp_mail_connection
        )
        
        email.content_subtype = "html"
        email.send()
    except Exception as e:
        pass


@shared_task
def send_subscription_email_task(recipients, subject, message, url):
    # Your email sending code here
    # Example: send email using Django's EmailMessage

    try:
        email = EmailMessage(
            subject=subject,
            body=message,
            to=recipients,
            connection = otp_mail_connection
        )
            
        response = requests.get(url)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(response.content)
            temp_file_path = f.name
            with open(temp_file_path, "rb") as pdf_file:
                pdf_data = pdf_file.read()
                email.attach("invoice.pdf", pdf_data, "application/pdf")
        
        email.content_subtype = "html"
        email.send()
    except Exception as e:
        pass