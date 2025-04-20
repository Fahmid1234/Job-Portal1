from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django_extensions.db.fields import AutoSlugField
from django_ckeditor_5.fields import CKEditor5Field
from django.core.mail import send_mail

# Create your models here
class CustomUser(AbstractUser):
    USER = ((1, 'Recruiter'),
            (2, 'Applicant'))
    profile_pic = models.ImageField(upload_to='profile_pic', null=True)
    user_type = models.CharField(choices=USER, max_length=20, null=True)
    reset_token = models.CharField(max_length=100, null=True, blank=True)


class Applicant(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, null=True)
    first_name = models.CharField(max_length=50, null=True)
    last_name = models.CharField(max_length=50, null=True)
    address = models.TextField(null=True, blank=True)
    cv = models.FileField(upload_to='resume', validators=[FileExtensionValidator(allowed_extensions=['pdf'])])
    gender = models.CharField(max_length=20)
    phone_number = models.CharField(max_length=15, null=True)


class Recuiter(models.Model): 
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, null=True)
    first_name = models.CharField(max_length=50, null=True)
    last_name = models.CharField(max_length=50, null=True)
    state = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    company = models.CharField(max_length=50)
    logo = models.ImageField(upload_to='company_logo')  
    
    def __str__(self):
        return self.company
    
class Category(models.Model):
    category = models.CharField(max_length=50, null=True)
    slug = AutoSlugField(populate_from='category', unique=True)
    logo = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.category

    class Meta:
        verbose_name_plural = 'Categories'

class Type(models.Model):
    job_type = models.CharField(max_length=50)
    
    def __str__(self):
        return self.job_type

class Job(models.Model):
    company_name = models.ForeignKey(Recuiter, on_delete=models.CASCADE) 
    email = models.EmailField(null=True)
    description = CKEditor5Field(config_name='default')
    website = models.CharField(max_length=50, null=True, blank=True)
    position = models.CharField(max_length=100)
    slug = AutoSlugField(populate_from='position', unique=True)
    min_salary = models.IntegerField()
    max_salary = models.IntegerField()
    job_type = models.ForeignKey(Type, null=True, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    post_date = models.DateField(auto_now_add=True, null=True)
    post_time = models.TimeField(auto_now_add=True, null=True)
    apply_date = models.DateField(null=True)
    apply_time = models.TimeField(null=True)
    vacancy = models.IntegerField(null=True)
    responsibility = CKEditor5Field(config_name='default', null=True, blank=True)
    qualification = CKEditor5Field(config_name='default', null=True, blank=True)
    
    def __str__(self):
        return self.position



class Job_Apply(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]
    applicants = models.ForeignKey(Applicant, on_delete=models.CASCADE, null=True)
    recruiter = models.ForeignKey(Recuiter, on_delete=models.CASCADE, null=True, blank=True)
    job = models.ForeignKey(Job, on_delete=models.CASCADE, null=True)
    cover_letter = models.TextField(null=True)
    cv = models.FileField(upload_to='resume', validators=[FileExtensionValidator(allowed_extensions=['pdf'])])
    portfolio = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    updated_at = models.DateTimeField(auto_now=True)
    # slug = AutoSlugField(populate_from='job__position', unique=True, null=True)

    def __str__(self):
        return f"{self.applicants.user.username} - {self.job.position} ({self.status})"


class Notification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:30]}..."

# Signal to create notification when application status changes
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Job_Apply)
def create_notification(sender, instance, created, **kwargs):
    if not created:  # Only for updates, not new applications
        if instance.status == 'accepted':
            message = f"Your application for {instance.job.position} has been accepted by {instance.recruiter.company}!"
            Notification.objects.create(
                user=instance.applicants.user,
                message=message
            )
        elif instance.status == 'rejected':
            message = f"Your application for {instance.job.position} has been rejected by {instance.recruiter.company}."
            Notification.objects.create(
                user=instance.applicants.user,
                message=message
            )

class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"OTP for {self.user.email}"
    
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

class PasswordResetToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"Password Reset Token for {self.user.email}"
    
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

