from django.urls import path
from . import views
urlpatterns = [
    path('deposit/', views.deposit, name="deposit"),
    path('transfer/', views.transfer, name="transfer"),
    path('withdraw/', views.withdraw, name="withdraw"),
    path('dashboard/', views.dashboard, name= "dashboard"),
]
