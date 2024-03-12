from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

# Wire up our API with the proper URL routing.
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
    path('en/',include('transactions.urls')),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)