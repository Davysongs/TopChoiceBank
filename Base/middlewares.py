from django.shortcuts import render
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseRedirect
from django.urls import reverse

class AjaxMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        def is_ajax(self):
            return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'
        
        request.is_ajax = is_ajax.__get__(request)
        response = self.get_response(request)
        return response
    
class CustomErrorHandlerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        # Check if the exception meets the condition
        if isinstance(exception, CustomException):
            # Render the custom error template
            return render(request, 'error/404.html', {'error_message': str(exception)})
        return None

class CustomException(Exception):
    pass

class AuthenticatedRedirectMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            # Redirect authenticated users away from login and sign up pages
            if request.path == reverse('login') or request.path == reverse('register'):
                return HttpResponseRedirect(reverse('dashboard'))