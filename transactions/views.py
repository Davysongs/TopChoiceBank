from accounts.models import Account
from django.shortcuts import render, redirect
from django.http import JsonResponse
import json
from .models import Transaction
from django.db import transaction as db_transaction

def deposit(request):
    if request.method == "POST" and request.is_ajax():
        try:
            uid = request.user.email
            detail = Account.objects.get(email=uid)

            data = json.loads(request.body)
            amount = float(data.get('amount', 0))

            balance = detail.balance + amount
            detail.balance = balance
            detail.save()

            # Log transaction
            Transaction.objects.create(
                name=detail.name,
                bank=detail.bank,
                account_no=detail.account_no,
                amount=amount,
                transaction_ID="unique_transaction_id",  # Generate a unique transaction ID
                info="Deposit",
                status="Success"
            )

            responseData = {'status': 'success', 'message': 'Deposited successfully'}
            return JsonResponse(responseData, status=201)

        except Account.DoesNotExist:
            return JsonResponse({'error': 'Account not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

        except ValueError:
            return JsonResponse({'error': 'Invalid amount value'}, status=400)

        except Exception as e:
            print("Error in Deposit View:", e)
            return JsonResponse({'error': 'Something went wrong while processing the transaction'}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

def withdraw(request):
    if request.method == "POST" and request.is_ajax():
        try:
            uid = request.user.email
            detail = Account.objects.get(email=uid)

            data = json.loads(request.body)
            amount = float(data.get('amount', 0))

            if detail.balance < amount:
                return JsonResponse({'error': 'Insufficient funds'}, status=400)

            balance = detail.balance - amount
            detail.balance = balance
            detail.save()

            # Log transaction
            Transaction.objects.create(
                name=detail.name,
                bank=detail.bank,
                account_no=detail.account_no,
                amount=-amount,
                transaction_ID="unique_transaction_id",  # Generate a unique transaction ID
                info="Withdrawal",
                status="Success"
            )

            responseData = {'status': 'success', 'message': 'Withdrawn successfully'}
            return JsonResponse(responseData, status=201)

        except Account.DoesNotExist:
            return JsonResponse({'error': 'Account not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

        except ValueError:
            return JsonResponse({'error': 'Invalid amount value'}, status=400)

        except Exception as e:
            print("Error in Withdraw View:", e)
            return JsonResponse({'error': 'Something went wrong while processing the transaction'}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

def transfer(request):
    if request.method == "POST" and request.is_ajax():
        try:
            uid = request.user.email
            sender_detail = Account.objects.get(email=uid)

            data = json.loads(request.body)
            amount = float(data.get('amount', 0))
            recipient_account_no = data.get('account_no', '')

            if sender_detail.balance < amount:
                return JsonResponse({'error': 'Insufficient funds'}, status=400)

            with db_transaction.atomic():
                recipient_detail = Account.objects.select_for_update().get(account_no=recipient_account_no)

                sender_detail.balance -= amount
                recipient_detail.balance += amount

                sender_detail.save()
                recipient_detail.save()

                # Log transaction for sender
                Transaction.objects.create(
                    name=sender_detail.name,
                    bank=sender_detail.bank,
                    account_no=sender_detail.account_no,
                    amount=-amount,
                    #TODO:# Generate a unique transaction ID
                    transaction_ID="unique_sender_transaction_id",  
                    info=f"Transfer to {recipient_account_no}",
                    status="Success"
                )

                # Log transaction for recipient
                Transaction.objects.create(
                    name=recipient_detail.name,
                    bank=recipient_detail.bank,
                    account_no=recipient_detail.account_no,
                    amount=amount,
                    transaction_ID="unique_recipient_transaction_id",  # Generate a unique transaction ID
                    info=f"Transfer from {sender_detail.account_no}",
                    status="Success"
                )

            responseData = {'status': 'success', 'message': 'Transferred successfully'}
            return JsonResponse(responseData, status=201)

        except Account.DoesNotExist:
            return JsonResponse({'error': 'Account not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

        except ValueError:
            return JsonResponse({'error': 'Invalid amount value'}, status=400)

        except Exception as e:
            print("Error in Transfer View:", e)
            return JsonResponse({'error': 'Something went wrong while processing the transaction'}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

def dashboard(request):
    if request.method == "GET":
        user = request.user
        try:
            details = Account.objects.get(user=user)
            return render(request, "dashboard.html", {'context': details})
        except Account.DoesNotExist:
            return redirect('logout')
    elif request.method == "POST":
        pass
