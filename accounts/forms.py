from user.models import User
from django.contrib.auth.forms import UserCreationForm
from django import forms
from accounts.models import Account

class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields =["email","password1", "password2", "first_name", "last_name"]

class UserForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['image', 'pin', 'phone', 'state', 'postcode', 'country', 'address', 'city', 'nickname']

    def save(self, commit=True):
        # Get the instance of the model form
        instance = super().save(commit=False)

        # Check each field in the form data and update the instance if the field is not empty
        for field_name, field_value in self.cleaned_data.items():
            if field_value and hasattr(instance, field_name):
                setattr(instance, field_name, field_value)

        if commit:
            instance.save()
        return instance
