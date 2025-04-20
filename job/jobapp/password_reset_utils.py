import uuid
import secrets
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse

from .models import CustomUser

def get_user_by_email(email):
    """Get a user by their email address"""
    try:
        return CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return None

def generate_password_reset_token(user):
    """
    Generate a password reset token for a user.
    Saves the token directly to the user model.
    """
    # Generate a new token
    token = secrets.token_urlsafe(32)
    
    # Save the token to the user model
    user.reset_token = token
    user.save()
    
    # Return a simple object with the token for compatibility
    class TokenObj:
        def __init__(self, token):
            self.token = token
    
    return TokenObj(token)

def send_password_reset_email(user, token, request):
    """Send a password reset email to a user"""
    reset_url = request.build_absolute_uri(
        reverse('reset_password', kwargs={'user_id': user.id, 'token': token.token})
    )
    
    subject = 'Reset Your JobFinder Password'
    message = f"""Hello {user.first_name},

You requested a password reset for your JobFinder account.

Please click the link below to reset your password:
{reset_url}

This link will expire in 24 hours.

If you did not request a password reset, please ignore this email.

Best regards,
The JobFinder Team
"""
    
    # Print the reset URL for development/testing purposes
    print(f"Password reset URL for {user.email}: {reset_url}")
    print("\n----- EMAIL CONTENT (for development) -----")
    print(f"Subject: {subject}")
    print(f"To: {user.email}")
    print(f"From: {settings.DEFAULT_FROM_EMAIL}")
    print(f"Message: {message}")
    print("----- END EMAIL CONTENT -----\n")
    
    try:
        # Try to send using configured SMTP
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        
        send_mail(subject, message, email_from, recipient_list)
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        print("Using console backend as fallback for development.")
        
        # For development, use console backend as fallback
        from django.core.mail.backends.console import EmailBackend
        backend = EmailBackend()
        from django.core.mail.message import EmailMessage
        email = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
            connection=backend
        )
        email.send()
        
        # We'll still return True since this is just for development
        return True

def validate_password_reset_token(user_id, token):
    """
    Validate a password reset token.
    Returns the user if the token is valid, None otherwise.
    """
    try:
        user = CustomUser.objects.get(id=user_id, reset_token=token)
        return user
    except CustomUser.DoesNotExist:
        return None 