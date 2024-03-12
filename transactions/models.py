from django.db import models

STAT = (
    ("Success","Success"),
    ("Failed","Failed"),
    ("Pending","Pending"),
)
# Create your models here.
class Transaction(models.Model):
    name = models.CharField(max_length=120)
    bank = models.CharField(max_length=50)
    account_no = models.CharField(max_length=10)
    amount =  models.DecimalField(max_digits=8, decimal_places=2)
    date = models.DateTimeField(auto_now_add = True, help_text = "time of transaction")
    transaction_ID = models.CharField(max_length=50, primary_key = True)
    info = models.CharField(max_length = 120)
    status = models.CharField(max_length =10, choices = STAT )

    def __str__(self):
        return self.name + "-" + self.account_no + "-" + str(
            self.amount) + "-" + self.date.strftime("%Y-%m-%d %H:%M:%S")