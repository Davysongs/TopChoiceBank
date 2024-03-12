from accounts.models import Account
from django.shortcuts import render,redirect
from login_required import login_not_required
from django.http import JsonResponse
import json
# Create your views here.
def deposit(request):
    if request.method == "POST" and request.is_ajax():
        try:
            # Retrieve user's email and account details
            uid = request.user.email
            detail = Account.objects.get(email=uid)
            
            # Extract amount from request data
            data = json.loads(request.body)
            amount = float(data.get('amount', 0))  # Get 'amount' with default value 0
            
            # Update account balance
            balance = detail.balance + amount
            detail.balance = balance
            detail.save()  # Save updated balance
            
            # Prepare success response
            responseData = {'status': 'success', 'message': 'Deposited successfully'}
            return JsonResponse(responseData, status=201)
        
        except Account.DoesNotExist:
            return JsonResponse({'error': 'Account not found'}, status=404)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
        except ValueError:
            return JsonResponse({'error': 'Invalid amount value'}, status=400)
        
        except Exception as e:
            # Log the error for debugging purposes
            print("Error in Deposit View:", e)
            return JsonResponse({'error': 'Something went wrong while processing the transaction'}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    

def withdraw(request):
    pass
def transfer(request):
    pass


# Create your views here.
@login_not_required
def homepage(request):
    return render(request, "index.html")

def dashboard(request):
    if request.method == "GET":
        user = request.user
        details = Account.objects.get(user = user)
        return render(request, "dashboard.html", {'context':details})
    elif request.method=="POST":
        pass
    




