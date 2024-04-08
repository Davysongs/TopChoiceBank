from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from login_required import login_not_required
from accounts.forms import SignUpForm
from .forms import UserForm
from Base.middlewares import CustomException
from accounts.models import Account
from django.http import JsonResponse
from custom_user.models import User
from django.views import View
from django.urls import reverse
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes,force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from .utils import token_generator
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
@login_not_required
def homepage(request):
    return render(request, "index.html")

#login 
@login_not_required
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, email= email, password= password)
        if user is not None:
            login(request,user)
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            messages.info(request,"Username or password is incorrect")
            return render(request, "login.html")
    return render(request, "login.html")

#sign up view
@login_not_required
def register_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            if User.objects.filter(email=email).exists():
                messages.warning(request, 'Email already exists! Please login instead of registration.')
                return render(request, 'register.html', {'form': form})
            first_name = form.cleaned_data.get('first_name')
            last_name = form.cleaned_data.get('last_name')
            password = form.cleaned_data.get('password1')
            user = User.objects.create_user(email=email, password=password,last_name = last_name,first_name = first_name)
            user.is_active= False
            user.save()
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            link = reverse('activate', kwargs={'uidb64':uidb64, 'token':token_generator.make_token(user)})
            activate_url = f"https://{domain}{link}"
            subject = "Account Activation"
            body = f"Hey {first_name},\n" "To activate  your account click on the following link:\n" + activate_url +"\n If that doesnt work please contact the admin or support for assistance"
            email = EmailMessage(
                subject,
                body,
                "no-reply@topchoicebank.com",
                [email]
            )        
            email.send(fail_silently=False)
            messages.add_message(request, messages.INFO, "Check your email for an activation link")
            condition = True
            return render(request, "register.html", {'condition': condition})
        else:
            # Handle form errors 
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return render(request, "register.html", {"form": form})
    if request.method == "GET":
        form = SignUpForm()
        return render(request, "register.html", {"form": form})

#email link validation
@method_decorator(login_not_required, name="dispatch")
class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        
        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.INFO, "Your account has been successfully activated")
            return redirect("login")
        
        return render(request, 'error/404.html', {'error_message': "Account activation error"})

#Logout
def logout_user(request):
    logout(request)
    return redirect('home')

 #profile update and creation
def profile(request):
    user = request.user
    try:
        details = Account.objects.get(user=user)
    except Account.DoesNotExist:
        raise CustomException("Your account isnt properly configured. Contact an Admin")

    if request.method == "GET":
        form = UserForm(instance=details)  # Populate form with existing data
        if details.pin:
            return render(request, 'update.html', {'details': details, 'form': form})
        else:
            return render(request, 'update.html', {'form': form})

    elif request.method == 'POST':
        form = UserForm(request.POST, request.FILES, instance=details)
        if form.is_valid():
            form.save()
            # Add a success message to provide feedback to the user
            #messages.success(request, 'Profile updated successfully.')
            return redirect('dashboard')
        else:
            # Form is not valid, handle the error scenario by rendering the form with errors
            return render(request, 'update.html', {'details': details, 'form': form})
        
@csrf_exempt
def save_profile(request):
    if request.method == 'POST' and request.is_ajax():
        # Get user account
        user_account = request.user.account

        # Extract picture file and nickname from request
        picture_file = request.FILES.get('picture')
        nickname = request.POST.get('nickname')

        # Update account fields
        if picture_file:
            user_account.image = picture_file
        if nickname:
            user_account.nickname = nickname

        # Save account changes
        user_account.save()

        return JsonResponse({'message': 'Picture and nickname saved successfully.'}, status=200)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)





