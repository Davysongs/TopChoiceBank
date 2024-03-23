from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
from accounts.models import Account

class TokenGenerator(PasswordResetTokenGenerator):
    def make_hash_value(self, user, timestamp):
        return (text_type(user.is_active) + text_type(user.pk) + text_type(timestamp)).encode('utf-8')

token_generator = TokenGenerator()

#def get_password_reset_token

