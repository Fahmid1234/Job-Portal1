from django.shortcuts import render, redirect
from .EmailBackend import EmailBackend
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import *
from django.db.models import Count, Q
from datetime import datetime, timedelta
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from .otp_utils import create_otp_for_user, send_otp_email, verify_otp, get_user_by_email

# Create your views here.
def index(request):
    remain_date = ''
    remain_time = ''
    current_time = timezone.now()
    category = Category.objects.all()
    job = Job.objects.all().order_by('post_date')[:5]
    current_date = datetime.now().date()
    current_time = datetime.now().time()
    full = Job.objects.filter(job_type__job_type='Full Time')
    part = Job.objects.filter(job_type__job_type='Part Time')
    remote = Job.objects.filter(job_type__job_type='Freelancing')
    
    categories = Category.objects.annotate(job_count=Count('job'))
    def convert_to_timedelta(time_value):
        return timedelta(hours=time_value.hour, minutes=time_value.minute, seconds=time_value.second)
    
    current_time_timedelta = convert_to_timedelta(current_time)
    for i in job:
        remain_date = i.apply_date - current_date
        apply_time_timedelta = convert_to_timedelta(i.apply_time)
        remain_time = apply_time_timedelta - current_time_timedelta
        
        if remain_date.days ==  0 and remain_time.total_seconds() < 0:
            i.delete()
    return render(request, 'index.html', {'job': job, 'remain_date': remain_date, 'remain_time': remain_time, 'category': category, 'categories': categories, 'full': full, 'part': part, 'remote': remote})

def author(request):
    return render(request, 'author.html')
def register(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        return render(request, 'register.html')
def logins(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        return render(request, 'login.html')

def dologout(request):
    logout(request)
    messages.success(request, "You have been successfully logged out.")
    return redirect('index')

def check_registration(request):
    if request.method == "POST":
        userType = request.POST.get('userType')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        conf_password = request.POST.get('conf_password')
        
        # For applicants
        if userType == 'applicant':
            profile_pic = request.FILES.get('profile_pic')  # Get the profile picture
            address = request.POST.get('address')
            gender = request.POST.get('gender')
            phone_number = request.POST.get('phone_number')
            resume = request.FILES.get('resume')  # Get the uploaded resume file

            if CustomUser.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists. Please choose another one.')
                return redirect('register')
            
            if CustomUser.objects.filter(email=email).exists():
                messages.error(request, 'Email is already registered. Please log in or use a different email.')
                return redirect('register')

            if password == conf_password and len(password) >= 6:
                try:
                    # Create new CustomUser for applicant
                    customuser = CustomUser()
                    customuser.first_name = first_name
                    customuser.last_name = last_name
                    customuser.username = username
                    customuser.profile_pic = profile_pic  # Set profile picture for applicant
                    customuser.email = email
                    customuser.user_type = 2  # Applicant user type
                    customuser.set_password(password)  
                    customuser.save()

                    # Create Applicant instance and link it to the CustomUser
                    applicant = Applicant()
                    applicant.user = customuser  # Associate with CustomUser
                    applicant.first_name = first_name
                    applicant.last_name = last_name
                    applicant.address = address
                    applicant.cv = resume  # Save the uploaded CV
                    applicant.gender = gender
                    applicant.phone_number = phone_number
                    applicant.save()

                    messages.success(request, 'Registration successful! You can now log in with your credentials.')
                    return redirect('login')
                except Exception as e:
                    messages.error(request, f'An error occurred: {e}')
                    return redirect('register')
            else:
                messages.error(request, 'Passwords do not match or do not meet the length requirement (6 or more characters).')
                return redirect('register')

        # For recruiters
        elif userType == 'recruiter':
            country = request.POST.get('country')
            state = request.POST.get('state')
            company_name = request.POST.get('company')
            company_logo = request.FILES.get('company_logo')  # Get company logo

            if CustomUser.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists. Please choose another one.')
                return redirect('register')

            if CustomUser.objects.filter(email=email).exists():
                messages.error(request, 'Email is already registered. Please log in or use a different email.')
                return redirect('register')

            if password == conf_password and len(password) >= 6:
                try:
                    # Create new CustomUser for recruiter
                    customuser = CustomUser()
                    customuser.first_name = first_name
                    customuser.last_name = last_name
                    customuser.username = username
                    customuser.email = email
                    customuser.user_type = 1  # Recruiter user type
                    customuser.set_password(password)
                    customuser.save()

                    # Create Recruiter instance and link it to CustomUser
                    recruiter = Recuiter()
                    recruiter.user = customuser  # Associate with CustomUser
                    recruiter.first_name = first_name
                    recruiter.last_name = last_name
                    recruiter.state = state
                    recruiter.country = country
                    recruiter.company = company_name
                    recruiter.logo = company_logo  # Save the company logo
                    recruiter.save()

                    messages.success(request, 'Registration successful! You can now log in with your credentials.')
                    return redirect('login')
                except Exception as e:
                    messages.error(request, f'An error occurred: {e}')
                    return redirect('register')
            else:
                messages.error(request, 'Passwords do not match or do not meet the length requirement (6 or more characters).')
                return redirect('register')

    return redirect('register')

def do_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = EmailBackend.authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.first_name}! You have successfully logged in.')
            return redirect('index')
        else:
            messages.error(request, 'Invalid email or password. Please try again.')
            return redirect('login')
    else:
        return redirect('login')
    
def about(request):
    return render(request, 'about.html')

def contact(request):
    return render(request, 'contact.html')

@login_required(login_url='login')
def job_apply(request):
    categories = Category.objects.all()
    user = request.user
    company = Recuiter.objects.get(user=user).company
    current_date = datetime.now().date()
    current_time = datetime.now().time()
    job_types = Type.objects.all()
    return render(request, 'job_apply.html', {'email': user.email, 'company': company, 'categories': categories, 'job_types': job_types})

@login_required(login_url='login')
def add_job(request):
    if request.method == 'POST':
        company_name = request.POST.get('company')
        email = request.POST.get('email')
        description = request.POST.get('description')
        website = request.POST.get('website')
        position = request.POST.get('position')
        min_salary = request.POST.get('min_salary')
        max_salary = request.POST.get('max_salary')
        apply_date = request.POST.get('apply_date')
        apply_time = request.POST.get('apply_time')
        job_type_name = request.POST.get('job_type')
        category_id = request.POST.get('category')
        vacancy = request.POST.get('vacancy')
        responsibility = request.POST.get('responsibility')
        qualifications = request.POST.get('qualifications')

        company = get_object_or_404(Recuiter, company=company_name)
        job_type = get_object_or_404(Type, job_type=job_type_name)

        job = Job(
            company_name=company,  
            email=email,
            description=description,
            website=website,
            position=position,
            min_salary=min_salary,
            max_salary=max_salary,
            apply_date=apply_date,
            apply_time=apply_time,
            job_type=job_type,
            category_id=category_id,
            vacancy=vacancy,
            responsibility=responsibility,
            qualification=qualifications,
        )

        job.save()
        messages.success(request, f'Your job "{position}" has been posted successfully!')
        return redirect('index')

    categories = Category.objects.all()
    job_types = Type.objects.all()  

    context = {
        'categories': categories,
        'job_types': job_types,
        'company': company,
        'email': request.user.email
    }

    return render(request, 'index.html', context)

def get_job(request, slug):
    remain_date = None
    remain_time = ''
    job = Job.objects.filter(category__slug=slug)
    job_count = job.count()
    current_date = datetime.now().date()
    current_time = datetime.now().time()
    def convert_to_timedelta(time_value):
        return timedelta(hours=time_value.hour, minutes=time_value.minute, seconds=time_value.second)
    
    current_time_timedelta = convert_to_timedelta(current_time)
    for i in job:
        remain_date = i.apply_date - current_date
        apply_time_timedelta = convert_to_timedelta(i.apply_time)
        remain_time = apply_time_timedelta - current_time_timedelta
    
        if remain_date.days ==  0 and remain_time.total_seconds() < 0:
            i.delete()
    context = {
        'job': job,
        'job_count': job_count,
        'remain_date': remain_date,
        'remain_time': remain_time
    }
    return render(request, 'job-list.html', context)

def searching(request):
    remain_date = None
    remain_time = None
    
    job_title = request.POST.get('job_title', '')
    category = request.POST.get('category', '')
    location = request.POST.get('location', '')

    if job_title and location and category:
        
        jobs = Job.objects.filter(Q(position__icontains=job_title) & Q(company_name__state__icontains=location) & Q(category__category__icontains=category))
    elif category:
        jobs = Job.objects.filter(category__category__icontains=category)
    elif job_title:
        jobs = Job.objects.filter(position__icontains=job_title)
    elif location:
        jobs = Job.objects.filter(company_name__state__icontains=location)
    else:
        jobs = Job.objects.all()
        
    
    current_date = datetime.now().date()
    current_time = datetime.now().time()

    def convert_to_timedelta(time_value):
        return timedelta(hours=time_value.hour, minutes=time_value.minute, seconds=time_value.second)

    current_time_timedelta = convert_to_timedelta(current_time)

    job_data = []
    for job in jobs:
        remain_date = job.apply_date - current_date
        apply_time_timedelta = convert_to_timedelta(job.apply_time)
        remain_time = apply_time_timedelta - current_time_timedelta
        
        if remain_date.days ==  0 and remain_time.total_seconds() < 0:
            job.delete()

        job_data.append({
            'job': job,
            'remain_date': remain_date,
            'remain_time': remain_time
        })
    
    job_count = len(job_data)

    return render(request, "search-result.html", {'job': jobs, 'remain_date': remain_date, 'remain_time': remain_time, 'job_count': job_count})

def search_result(request):
    return render(request, 'search-result.html')

def job_details(request, slug):
    remain_time = ''
    remain_date = ''
    job = Job.objects.filter(slug=slug)
    current_date = datetime.now().date()
    current_time = datetime.now().time()
    def convert_to_timedelta(time_value):
        return timedelta(hours=time_value.hour, minutes=time_value.minute, seconds=time_value.second)
    
    current_time_timedelta = convert_to_timedelta(current_time)

    for i in job:
        remain_date = i.apply_date - current_date
        apply_time_timedelta = convert_to_timedelta(i.apply_time)
        remain_time = apply_time_timedelta - current_time_timedelta
    
        if remain_date.days ==  0 and remain_time.total_seconds() < 0:
            i.delete()
        
        applicant = Applicant.objects.all()
    
    return render(request, 'job-detail.html', {'job': job, 'remain_date': remain_date, 'remain_time': remain_time})

@login_required(login_url='login')
def job_application(request, slug):
    if request.method == "POST":
        # name = request.POST.get('name')
        # email = request.POST.get('email')
        portfolio = request.POST.get('portfolio')
        cv = request.FILES.get('cv')
        cover_letter = request.POST.get('cover_letter')
        print(portfolio)
        print(cv)
        print(cover_letter)

        try:
            applicant = Applicant.objects.get(user=request.user)
            job = get_object_or_404(Job, slug=slug)

            job_application = Job_Apply.objects.create(
                applicants=applicant,
                job=job,
                cover_letter=cover_letter,
                portfolio=portfolio,
                cv=cv,
                recruiter=job.company_name
            )
            job_application.save()
            
            messages.success(request, f'Your application for "{job.position}" has been submitted successfully! It is now pending approval.')
            return redirect('index')

        except Applicant.DoesNotExist:
            messages.error(request, 'You must be an applicant to apply for a job.')
            return render(request, 'error.html', {'message': 'You must be an applicant to apply for a job.'})


    job = get_object_or_404(Job, slug=slug)
    return render(request, 'job-detail.html', {'job': job})

@login_required(login_url='login')
def my_profile(request):
    if request.user.user_type == '2':
        applicant = Applicant.objects.get(user=request.user)
    else:
        recruiter = Recuiter.objects.get(user=request.user)

    return render(request, 'my_profile.html', {'applicant': recruiter if request.user.user_type == '1' else applicant})

@login_required(login_url='login')
def edit_profile(request):
    if request.user.user_type == '2':
        applicant = Applicant.objects.get(user=request.user)
    else:
        recruiter = Recuiter.objects.get(user=request.user)
    
    return render(request, 'edit_profile.html', {'applicant': recruiter if request.user.user_type == '1' else applicant})

@login_required(login_url='login')
def edited_profile(request):
    if request.user.user_type == '2':
        if request.method == 'POST':
            f_name = request.POST.get('f_name')
            l_name = request.POST.get('l_name')
            p_number = request.POST.get('p_number')
            gender = request.POST.get('gender')
            address = request.POST.get('address')
            cv = request.POST.get('cv')
            
            try:
                customuser = CustomUser.objects.get(username=request.user.username)
                customuser.first_name = f_name
                customuser.last_name = l_name
                customuser.save()
            except Exception as e:
                print(e)
            try:
                applicant = Applicant.objects.get(user=request.user)
                
                applicant.first_name = f_name
                applicant.last_name = l_name
                applicant.phone_number = p_number
                applicant.gender = gender
                applicant.address = address
                if cv:
                    applicant.cv = cv
                    
                applicant.save()
                messages.success(request, 'Your profile has been updated successfully!')
                
            except Exception as e:
                messages.error(request, f'An error occurred while updating your profile: {e}')
                print(e)
    else:
        if request.method == 'POST':
            f_name = request.POST.get('f_name')
            l_name = request.POST.get('l_name')
            company = request.POST.get('company')
            state = request.POST.get('state')
            country = request.POST.get('country')
            logo = request.FILES.get('logo')
            

            try:
                customuser = CustomUser.objects.get(username=request.user.username)
                customuser.first_name = f_name
                customuser.last_name = l_name
                customuser.save()
            except Exception as e:
                print(e)
            try:
                recruiter = Recuiter.objects.get(user=request.user)

                recruiter.first_name = f_name
                recruiter.last_name = l_name
                recruiter.company = company
                recruiter.state = state
                recruiter.country = country
                
                if logo:
                    recruiter.logo = logo

                recruiter.save()
                messages.success(request, 'Your company profile has been updated successfully!')
                
            except Exception as e:
                messages.error(request, f'An error occurred while updating your profile: {e}')
                print(e)
    return redirect('my_profile')

@login_required(login_url='login')
def application_history(request):
    try:
        applicant = Applicant.objects.get(user=request.user)
        applications = Job_Apply.objects.filter(applicants=applicant)

        return render(request, 'application_history.html', {
            'applications': applications,
        })
    except Applicant.DoesNotExist:
        messages.error(request, 'You do not have any applications.')
        return render(request, 'error.html', {'message': 'You do not have any applications.'})
    
@login_required(login_url='login')
def cng_pass(request):
    return render(request, 'password_change.html')

@login_required(login_url='login')
def password_changed(request):
    if request.method == "POST":
        new_password = request.POST.get('password')
        confirm_password = request.POST.get('password1')
        
        user = request.user
        if user.user_type == '2': 
            try:
                customuser = request.user
                if len(new_password) >= 6 and len(confirm_password) >= 6:
                    if new_password == confirm_password:
                        logout(request)
                        customuser.set_password(new_password)
                        customuser.save()

                        user = authenticate(username=customuser.username, password=new_password)
                        if user is not None:
                            login(request, user)
                            messages.success(request, 'Your password has been changed successfully.')
                        else:
                            messages.error(request, "Password update failed. Unable to reauthenticate.")
                    else:
                        messages.error(request, "Passwords do not match.")
                else:
                    messages.error(request, "Password must be at least 6 characters long.")
            except Exception as e:
                print(e)
                messages.error(request, "An error occurred. Password was not changed.")
        elif user.user_type == '1': 
            try:
                recruiter = request.user
                if len(new_password) >= 6 and len(confirm_password) >= 6:
                    if new_password == confirm_password:
                        logout(request)
                        recruiter.set_password(new_password)
                        recruiter.save()

                        user = authenticate(username=recruiter.username, password=new_password)
                        if user is not None:
                            login(request, user)
                            messages.success(request, 'Your password has been changed successfully.')
                        else:
                            messages.error(request, "Password update failed. Unable to reauthenticate.")
                    else:
                        messages.error(request, "Passwords do not match.")
                else:
                    messages.error(request, "Password must be at least 6 characters long.")
            except Exception as e:
                print(e)
                messages.error(request, "An error occurred. Password was not changed.")
    return redirect('cng_pass')

@login_required(login_url='login')
def application_notification(request): 
    try:
        recruiter = None
        if request.user.user_type == '1':
            recruiter = Recuiter.objects.get(user=request.user)  
            applications = Job_Apply.objects.filter(job__company_name=recruiter).select_related('applicants__user', 'job', 'recruiter')
        else:
            applications = None  
    except Recuiter.DoesNotExist:
        applications = None  
    except Exception as e:
        print(f"Error: {e}")
        applications = None
    return render(request, 'job_applied_history.html', {'applications': applications, 'recruiter': recruiter})

@login_required(login_url='login')
def update_application_status(request, application_id):
    if request.method == 'POST' and request.user.user_type == '1':
        try:
            recruiter = Recuiter.objects.get(user=request.user)
            application = Job_Apply.objects.get(id=application_id, job__company_name=recruiter)
            
            new_status = request.POST.get('status')
            if new_status in ['accepted', 'rejected']:
                old_status = application.status
                application.status = new_status
                application.save()
                
                status_message = "accepted" if new_status == "accepted" else "rejected"
                messages.success(request, f'Application for "{application.job.position}" has been {status_message}.')
                
                # Create notification for the applicant
                # Note: This is handled by the signal in models.py
                
            else:
                messages.error(request, 'Invalid status provided.')
                
        except Job_Apply.DoesNotExist:
            messages.error(request, 'Application not found or you do not have permission to update it.')
        except Exception as e:
            messages.error(request, f'An error occurred: {e}')
    
    return redirect('application_notification')

@login_required(login_url='login')
def view_notifications(request):
    if request.user.is_authenticated:
        notifications = Notification.objects.filter(user=request.user)
        return render(request, 'notifications.html', {'notifications': notifications})
    return redirect('login')

@login_required(login_url='login')
def mark_notification_read(request, notification_id):
    if request.user.is_authenticated:
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
            notification.is_read = True
            notification.save()
            messages.success(request, 'Notification marked as read.')
        except Notification.DoesNotExist:
            messages.error(request, 'Notification not found.')
    return redirect('view_notifications')

# Context processor for notifications
def notification_processor(request):
    """
    Context processor to add notification count to all templates
    """
    if request.user.is_authenticated:
        if request.user.user_type == '2':  # Applicant
            unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
            return {'unread_notification_count': unread_count}
    return {'unread_notification_count': 0}

def privacy_policy(request):
    """
    Render the privacy policy page
    """
    return render(request, 'privacy_policy.html')

def terms_conditions(request):
    """
    Render the terms and conditions page
    """
    return render(request, 'terms_conditions.html')

def our_services(request):
    """
    Render the our services page
    """
    return render(request, 'our_services.html')

def email_login(request):
    """View for the OTP-based login page"""
    if request.user.is_authenticated:
        return redirect('index')
    else:
        return render(request, 'email_login.html')

def send_otp(request):
    """Send OTP to user's email address"""
    if request.method == 'POST':
        email = request.POST.get('email')
        
        user = get_user_by_email(email)
        if user is not None:
            # Generate and save OTP
            otp = create_otp_for_user(user)
            
            # Send OTP to user's email
            try:
                send_otp_email(user, otp)
                messages.success(request, f'An OTP has been sent to {email}. Please check your email.')
                # Render OTP verification page
                return render(request, 'verify_otp.html', {'email': email})
            except Exception as e:
                messages.error(request, f'Failed to send OTP. Error: {str(e)}')
                return redirect('email_login')
        else:
            messages.error(request, 'No account found with this email address')
            return redirect('email_login')
    else:
        return redirect('email_login')

def resend_otp(request):
    """Resend OTP to user's email address"""
    if request.method == 'POST':
        email = request.POST.get('email')
        
        user = get_user_by_email(email)
        if user is not None:
            # Generate and save OTP
            otp = create_otp_for_user(user)
            
            # Send OTP to user's email
            try:
                send_otp_email(user, otp)
                messages.success(request, f'A new OTP has been sent to {email}. Please check your email.')
                return render(request, 'verify_otp.html', {'email': email})
            except Exception as e:
                messages.error(request, f'Failed to send OTP. Error: {str(e)}')
                return render(request, 'verify_otp.html', {'email': email})
        else:
            messages.error(request, 'No account found with this email address')
            return redirect('email_login')
    else:
        return redirect('email_login')

def verify_otp_view(request):
    """Verify the OTP submitted by the user"""
    if request.method == 'POST':
        email = request.POST.get('email')
        otp_code = request.POST.get('otp_code')
        
        user = get_user_by_email(email)
        if user is not None:
            if verify_otp(user, otp_code):
                # Log the user in
                login(request, user)
                messages.success(request, f'Welcome back, {user.first_name}! You have successfully logged in using OTP verification.')
                return redirect('index')
            else:
                messages.error(request, 'Invalid or expired OTP. Please try again.')
                return render(request, 'verify_otp.html', {'email': email})
        else:
            messages.error(request, 'No account found with this email address')
            return redirect('email_login')
    else:
        return redirect('email_login')

# Password Reset Views
from .password_reset_utils import (
    get_user_by_email,
    generate_password_reset_token,
    send_password_reset_email,
    validate_password_reset_token
)

def forgot_password(request):
    """View for the forgot password page"""
    if request.user.is_authenticated:
        return redirect('index')
    return render(request, 'forgot_password.html')

def send_reset_email(request):
    """Send a password reset email to the user"""
    if request.method == 'POST':
        email = request.POST.get('email')
        
        user = get_user_by_email(email)
        if user is not None:
            try:
                # Generate a password reset token
                token = generate_password_reset_token(user)
                
                # Send the reset email
                result = send_password_reset_email(user, token, request)
                
                if result:
                    messages.success(request, f'A password reset link has been sent to {email}. Please check your email.')
                    # For development, also show the link in logs
                    print(f"Generated reset token for {email}: {token.token}")
                    return render(request, 'password_reset_sent.html')
                else:
                    messages.error(request, 'Failed to send reset email. Please try again later.')
                    return redirect('forgot_password')
            except Exception as e:
                print(f"Password reset error: {str(e)}")
                messages.error(request, f'An error occurred. Please try again later.')
                return redirect('forgot_password')
        else:
            # Still show success to prevent user enumeration, but log the issue for debugging
            print(f"No user found with email: {email}")
            messages.success(request, f'If an account exists with {email}, a password reset link has been sent.')
            return render(request, 'password_reset_sent.html')
    
    return redirect('forgot_password')

def reset_password(request, user_id, token):
    """View for the reset password page"""
    # Validate the token
    try:
        print(f"Reset password request for user_id: {user_id}, token: {token}")
        user = validate_password_reset_token(user_id, token)
        
        if user is None:
            print(f"Invalid token or token expired for user_id: {user_id}")
            messages.error(request, 'Invalid or expired password reset link. Please request a new one.')
            return redirect('forgot_password')
        
        print(f"Valid token for user: {user.email}")
        return render(request, 'reset_password.html', {
            'token': token,
            'user_id': user_id
        })
    except Exception as e:
        print(f"Error in reset_password view: {str(e)}")
        messages.error(request, 'An error occurred. Please try again.')
        return redirect('forgot_password')

def reset_password_confirm(request):
    """Process the password reset form"""
    if request.method == 'POST':
        token = request.POST.get('token')
        user_id = request.POST.get('user_id')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        print(f"Password reset confirmation for user_id: {user_id}, token: {token}")
        
        try:
            # Validate the token again
            user = validate_password_reset_token(user_id, token)
            
            if user is None:
                print(f"Invalid token during confirmation for user_id: {user_id}")
                messages.error(request, 'Invalid or expired password reset link. Please request a new one.')
                return redirect('forgot_password')
            
            # Validate the passwords
            if len(password) < 6:
                messages.error(request, 'Password must be at least 6 characters long.')
                return render(request, 'reset_password.html', {
                    'token': token,
                    'user_id': user_id
                })
            
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'reset_password.html', {
                    'token': token,
                    'user_id': user_id
                })
            
            # Update the password
            user.set_password(password)
            # Clear the reset token
            user.reset_token = None
            user.save()
            print(f"Password reset successful for user: {user.email}")
            
            messages.success(request, 'Your password has been reset successfully! You can now log in with your new password.')
            return render(request, 'password_reset_success.html')
        except Exception as e:
            print(f"Error in reset_password_confirm view: {str(e)}")
            messages.error(request, f'An error occurred while resetting your password. Please try again.')
            return render(request, 'reset_password.html', {
                'token': token,
                'user_id': user_id
            })
    
    return redirect('forgot_password')