from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

def send_activation_email(recipient_email, activation_url):
    subject = 'Activate your account on '+settings.SITE_NAME
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]

    html_context = render_to_string('myapp/activation_email.html', {'activation_url':activation_url})

    text_context = strip_tags(html_context)
    email = EmailMultiAlternatives(subject, text_context, from_email, to)
    email.attach_alternative(html_context, "text/html")
    email.send()

def send_reset_password_email(receipient_email, reset_url):
    subject = 'Reset Your Password on '+settings.SITE_NAME
    from_email = settings.EMAIL_HOST_USER
    to = [receipient_email]

    html_context = render_to_string('myapp/reset_password.html', {'reset_url':reset_url})

    text_context = strip_tags(html_context)
    email = EmailMultiAlternatives(subject, text_context, from_email, to)
    email.attach_alternative(html_context, "text/html")
    email.send()
