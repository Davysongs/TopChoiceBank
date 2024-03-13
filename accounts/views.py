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
from django.core.mail import EmailMessage


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
            user = User.objects.create_user(email=email, password=form.cleaned_data.get('password1'),
                                            last_name = form.cleaned_data.get('last_name'),
                                              first_name = form.cleaned_data.get('first_name'))
            user.is_active= False
            user.save()

            subject = "[TOPCHOICEBANK] Verify your email"
            body = "You linked up your Email to TOP CHOICE BANK APP successfully"
            email = EmailMessage(
                subject,
                body,
                "no-reply@topchoicebank.com",
                [email]
            )        
            email.send(fail_silently=False)
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

class VerificationView(View):
    def get(self, request, uidb64, token):
        return redirect("login")



#Logout
def logout_user(request):
    logout(request)
    return redirect('home')



def profile(request):
    user = request.user
    try:
        details = Account.objects.get(user=user)
    except Account.DoesNotExist:
        return CustomException("Your account isnt properly configured. See an Admin")

    if request.method == "GET":
        form = UserForm(instance=details)  # Populate form with existing data
        if details.pin:
            return render(request, 'update.html', {'details': details, 'form': form})
        else:
            return render(request, 'update.html', {'form': form})

    elif request.method == 'POST':
        if request.is_ajax():
            nickname = request.POST.get('nickname')
            image = request.FILES.get('image')
            user = request.user
            
            try:
                # Get or create the Account object for the user
                account = Account.objects.get_or_create(user=user)
                
                # Update the Account object with the received data
                account.nickname = nickname
                account.image = image
                account.save()
                
                # Return a success response
                return JsonResponse({'message': 'Data saved successfully'}, status=200)
            except Exception as e:
                # Return an error response if an exception occurs
                return JsonResponse({'error': str(e)}, status=500)
            
        else:
            form = UserForm(request.POST, request.FILES, instance=details)
            if form.is_valid():
                form.save()
                # Add a success message to provide feedback to the user
                #messages.success(request, 'Profile updated successfully.')
                return redirect('dashboard')
            else:
                # Form is not valid, handle the error scenario by rendering the form with errors
                return render(request, 'update.html', {'details': details, 'form': form})




