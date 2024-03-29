from pathlib import Path
import os
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-pa*7qjsodoj62^x^a@n9v!c)91+ta+9!t31d667_wzc%z*t#1#'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['.vercel.app', '.now.sh', '127.0.0.1', 'localhost']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'transactions',
    'custom_user.apps.CustomUserConfig',
    'django_use_email_as_username.apps.DjangoUseEmailAsUsernameConfig'
]

AUTH_USER_MODEL = 'custom_user.User'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Base.middlewares.CustomErrorHandlerMiddleware',
    'Base.middlewares.AuthenticatedRedirectMiddleware',
    'Base.middlewares.AjaxMiddleware',
    'django_auto_logout.middleware.auto_logout',
]


ROOT_URLCONF = 'Base.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django_auto_logout.context_processors.auto_logout_client',
            ],
        },
    },
]


WSGI_APPLICATION = 'Base.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'topchoice',
#         'USER': 'root',
#         'PASSWORD':'#$(tVA0nr)',
#         'HOST': '127.0.0.1',
#         'PORT': '3306'
#     }
# }

DATABASES = {
   'default': {
       'ENGINE': 'django.db.backends.postgresql',
       'NAME': 'railway',
       'USER':'postgres',
       'PASSWORD': 'gzwqUNzVkcgbSWMfmhkBKhHvOTtlXBCm',
       'HOST':'roundhouse.proxy.rlwy.net',
       'PORT':'14415',

   }
}

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles_build', 'static')


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

#session timeout
AUTO_LOGOUT = {"IDLE_TIME" : 3000, 'REDIRECT_TO_LOGIN_IMMEDIATELY': True,
               'MESSAGE': 'The session has expired. Please login again to continue.'}

# Media management
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

#auth stuff
LOGIN_REDIRECT_URL='dashboard'  
LOGIN_URL = "login"
LOGOUT_URL = "logout"


#email stuff
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'koladegeorge5@gmail.com'
EMAIL_HOST_PASSWORD = 'lqvvdmxcswrmovvr'
DEFAULT_FROM_EMAIL = 'Top-Choice-Bank <no-reply@topchoicebank.com>'




