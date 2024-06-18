from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid
from phonenumber_field.modelfields import PhoneNumberField

class AccountType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(get_user_model(), null=True, on_delete=models.CASCADE)
    account_type = models.ForeignKey(AccountType, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    account_no = models.CharField(max_length=10, unique=True, editable=False)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    regtime = models.DateTimeField(auto_now_add=True, help_text="Time of registration")
    image = models.ImageField(upload_to='images/', blank=True)
    phone = PhoneNumberField(blank=False, unique=True)
    address = models.CharField(max_length=200)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    postcode = models.CharField(max_length=20)
    state = models.CharField(max_length=100)
    pin = models.CharField(max_length=128, help_text="4 digit PIN for transaction verification.")
    nickname = models.CharField(max_length=50, null=True, default="User")

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['account_no']),
            models.Index(fields=['phone']),
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            original = Account.objects.get(pk=self.pk)
            if original.pin != self.pin:
                self.pin = make_password(self.pin)
        else:
            self.pin = make_password(self.pin)

        if not self.account_no:
            self.account_no = self.generate_account_no()

        super().save(*args, **kwargs)

    @classmethod
    def generate_account_no(cls):
        while True:
            account_no = str(uuid.uuid4().int)[:10]
            if not cls.objects.filter(account_no=account_no).exists():
                return account_no

    def check_pin(self, pin):
        return check_password(pin, self.pin)

    def __str__(self):
        return f"{self.user.username} ({self.account_no})"

# create an AccountType entry (optional)
@receiver(post_save, sender=AccountType)
def create_default_account_types(sender, **kwargs):
    if kwargs.get('created', False):
        default_types = [
            "Savings Account", "Accounting", "Checking Account",
            "Current Account", "Money Market Account", "Account Returns",
            "Discover", "Eazy Account", "Fixed Deposits",
            "Premium Checking", "Standard Savings"
        ]
        for type_name in default_types:
            AccountType.objects.get_or_create(name=type_name)
