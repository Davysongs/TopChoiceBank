from django.db import models
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.hashers import make_password, check_password
import random
import string

class Account(models.Model):
    user = models.ForeignKey(get_user_model(), null=True, on_delete=models.CASCADE)
    account_no = models.CharField(max_length=10, primary_key=True)
    balance = models.DecimalField(max_digits=8, decimal_places=2, default = 0)
    regtime = models.DateTimeField(auto_now_add=True, help_text="time of registration")
    image = models.ImageField(upload_to='images/', blank=True)
    phone = models.CharField(blank=False, max_length=15)
    address = models.CharField(blank=False, max_length=200)
    city = models.CharField(blank=False, max_length=200)
    country = models.CharField(blank=False, max_length=200)
    postcode = models.CharField(blank=False, max_length=200)
    state = models.CharField(blank=False, max_length=200)
    pin = models.CharField(max_length=128, help_text="4 digit PIN for transaction verification.")        
    nickname = models.CharField(max_length=50, null=True, default="User")

 # Generate account_no if it doesn't exist
    def save(self, *args, **kwargs):
        if not self.account_no:
            self.account_no = self.generate_account_no()
        super().save(*args, **kwargs)

    def generate_account_no(self):
        while True:
            account_no = ''.join(random.choices(string.digits, k=10))
            if not Account.objects.filter(account_no=account_no).exists():
                return account_no
            
    @receiver(post_save, sender=get_user_model())
    def create_user_account(sender, instance, created, **kwargs):
        if created:
            Account.objects.create(user=instance)
    
    
    def save(self, *args, **kwargs):
        # Check if pin is changed before saving
        if self.pin and not self.pin_hashed:
            # Hash the pin and save it
            self.pin_hashed = make_password(self.pin)
        super().save(*args, **kwargs)

    def check_pin(self, pin):
        # Check if the provided pin matches the hashed pin
        return check_password(pin, self.pin_hashed)

            
    def __str__(self):
        return str(self.user)
