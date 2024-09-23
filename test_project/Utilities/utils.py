# Standard Library Imports
from random import randint

# Django Imports
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import get_template


def generate_otp(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)
 
def send_email_otp(user, otp):
    context = {
        'user_email': user.email,
        'otp': otp
    }
    template = get_template('otp.html').render(context)
    email = EmailMessage('Email Verification OTP',template,settings.EMAIL_HOST_USER,[user.email])
    email.content_subtype = "html"
    try:
        email.send(fail_silently=False)
        print("Mail successfully sent")
        return True
    except Exception as e:
        print("mailerror", str(e))
        return False, str(e)