from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
# Register your models here.

@admin.register(CustomUser)
class UserModel(UserAdmin):
    list_display = ['username', 'profile_pic']
    
@admin.register(Applicant)
class ApplicantAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'last_name', 'address', 'cv', 'gender', 'phone_number']

@admin.register(Recuiter)
class RecuiterAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'last_name', 'country', 'company', 'logo']

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ['company_name', 'description', 'position', 'job_type']
    
@admin.register(Category)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ['category', 'logo']
    
@admin.register(Type)
class JobTypeAdmin(admin.ModelAdmin):
    list_display = ['job_type']

@admin.register(Job_Apply)
class Job_ApplyAdmin(admin.ModelAdmin):
    list_display = ['job', 'portfolio', 'cv', 'cover_letter']

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp_code', 'is_verified', 'created_at', 'expires_at')
    search_fields = ('user__email', 'otp_code')
    list_filter = ('is_verified', 'created_at')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)