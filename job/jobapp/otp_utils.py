import random
import string
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP, CustomUser

def generate_otp(length=6):
    """Generate a random numeric OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def create_otp_for_user(user, expiry_minutes=10):
    """Create and save an OTP for the specified user"""
    # Invalidate any existing OTPs for this user
    OTP.objects.filter(user=user, is_verified=False).update(is_verified=True)
    
    # Generate a new OTP
    otp_code = generate_otp()
    expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    
    # Create and save new OTP
    otp = OTP.objects.create(
        user=user,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    return otp

def verify_otp(user, otp_code):
    """Verify if the provided OTP is valid for the user"""
    try:
        otp = OTP.objects.filter(
            user=user,
            otp_code=otp_code,
            is_verified=False
        ).latest('created_at')
        
        # Check if OTP has expired
        if otp.is_expired():
            return False
        
        # Mark OTP as verified
        otp.is_verified = True
        otp.save()
        return True
    except OTP.DoesNotExist:
        return False

def send_otp_email(user, otp):
    """Send OTP to user's email address"""
    subject = 'Your One-Time Password for JobEntry'
    message = f'''
    Hello {user.first_name},
    
    Your one-time password (OTP) for JobEntry is: {otp.otp_code}
    
    This OTP will expire in 10 minutes.
    
    Please do not share this OTP with anyone.
    
    Best regards,
    JobEntry Team
    '''
    
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    
    return send_mail(subject, message, from_email, recipient_list)

def get_user_by_email(email):
    """Get a user by their email address"""
    try:
        return CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return None 