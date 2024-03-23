from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid

class Account(models.Model):
    user = models.OneToOneField(get_user_model(), null=True, on_delete=models.CASCADE)
    account_no = models.CharField(max_length=10, primary_key=True)
    balance = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    regtime = models.DateTimeField(auto_now_add=True, help_text="Time of registration")
    image = models.ImageField(upload_to='images/', blank=True)
    phone = models.CharField(blank=False, max_length=15)
    address = models.CharField(blank=False, max_length=200)
    city = models.CharField(blank=False, max_length=200)
    country = models.CharField(blank=False, max_length=200)
    postcode = models.CharField(blank=False, max_length=200)
    state = models.CharField(blank=False, max_length=200)
    pin = models.CharField(max_length=128, help_text="4 digit PIN for transaction verification.")
    nickname = models.CharField(max_length=50, null=True, default="User")
    
    # Override save method to hash pin before saving
    def save(self, *args, **kwargs):
        if self.pin:
            # Hash the pin and save it
            self.pin = make_password(self.pin)
        super().save(*args, **kwargs)
    
    def generate_account_no():
        while True:
            account_no = str(uuid.uuid4().int)[:10]  # Generate a UUID and extract the first 10 digits
            if not Account.objects.filter(account_no=account_no).exists():
                return account_no

    # Method to check if the provided pin matches the hashed pin
    def check_pin(self, pin):
        return check_password(pin, self.pin)

    def __str__(self):
        return str(self.user)

# Signal to create Account instance for new user
@receiver(post_save, sender=get_user_model())
def create_account(sender, instance, created, **kwargs):
    if created:
        Account.objects.create(user=instance, account_no=Account.generate_account_no())

# You may need to adjust the create_account function based on your requirements.
