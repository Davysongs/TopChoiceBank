from django.urls import path
from . import views

urlpatterns = [
    path('', views.homepage, name="home"),
    path("login/", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    path("logout/",views.logout_user, name="logout"),
    path('profile/', views.profile, name="profile"),
    path('profile/save', views.save_profile, name="save_profile"),
    path('activate/<uidb64>/<token>', views.VerificationView.as_view(), name = "activate")
]
