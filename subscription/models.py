from django.db import models

# Create your models here.

class StripeCustomer(models.Model):
    user = models.ForeignKey('accounts.User', on_delete = models.SET_NULL, null = True)
    organization = models.ForeignKey('accounts.Organization', on_delete = models.SET_NULL, null = True)
    stripe_customer_id = models.CharField(max_length = 50, null = True)
    created_date = models.DateTimeField(auto_now_add = True)


class StripeCard(models.Model):
    user = models.ForeignKey('accounts.User', on_delete = models.SET_NULL, null = True)
    fingerprint = models.CharField(max_length = 50, null = True)
    payment_method_id = models.CharField(max_length = 50, null = True)
    brand = models.CharField(max_length = 20, null = True)
    country = models.CharField(max_length=25, null = True)
    customer = models.CharField(max_length = 50, null = True)
    exp_month = models.IntegerField(null = True)
    exp_year = models.IntegerField(null = True)
    last4 = models.IntegerField(null = True)
    funding = models.CharField(max_length = 25, null = True)
    holder_name = models.CharField(max_length = 50, null = True)
    created_date = models.DateTimeField(auto_now = True, null = True)
    last_used_date = models.DateTimeField(null = True)


class StripeProduct(models.Model):
    created_date = models.DateTimeField(auto_now_add = True)
    stripe_product_id = models.CharField(max_length = 100, null = True, blank = True)
    product_name = models.CharField(max_length = 255, null = True, blank = True)
    is_active = models.BooleanField(default = False)

    def __str__(self) -> str:
        return f'{self.product_name} - {self.is_active} - {self.stripe_product_id}'

class StripePrice(models.Model):
    stripe_price_id = models.CharField(max_length = 100, null = True, blank = True)
    recurring_type = models.CharField(max_length = 50, null = True, blank = True)
    interval_count = models.IntegerField(blank = True, null = True)
    price = models.IntegerField(null = True)
    is_live = models.BooleanField(default = True)
    created_date = models.DateTimeField(auto_now_add = True)
    product = models.ForeignKey(StripeProduct, on_delete = models.PROTECT, null = True)
    
    def __str__(self) -> str:
        return f'{self.stripe_price_id} - {self.recurring_type} - {self.price}'
    
class SubscriptionPlan(models.Model):
    PLAN_CHOICES = [("MONTHLY", "MONTHLY"), ("YEARLY", "YEARLY"), ("CUSTOM", "CUSTOM"), ("TRIAL", "TRIAL"), ("DAILY", "DAILY")]
    
    applied_discount = models.BooleanField(default=False)
    discount = models.IntegerField()
    plan_type = models.CharField(choices = PLAN_CHOICES, max_length = 7)
    stripe_price = models.ForeignKey(StripePrice, on_delete=models.PROTECT, null = True, blank = True)
    created_date = models.DateTimeField(auto_now_add = True)
    is_active = models.BooleanField(default = True)

    def __str__(self) -> str:
        return self.plan_type


class OrganizationPlan(models.Model):
    device_limit = models.IntegerField(default = 1)
    subscription_plan = models.ForeignKey('SubscriptionPlan', on_delete = models.SET_NULL, null = True)
    organization = models.ForeignKey('accounts.Organization', on_delete = models.CASCADE, null = True, related_name = "subscription_org")
    utilized_limit = models.IntegerField(default = 0)
    services = models.ManyToManyField('accounts.MasterService', related_name = "subscribed_services")
    un_used_devices = models.ManyToManyField("accounts.Device", blank = True, related_name = "subscription_device") 
    commencing_date = models.DateTimeField(null = True, blank = True, default = None)
    plan_updated_date = models.DateTimeField(null = True)
    expiry_date = models.DateTimeField(null = True, blank = True, default = None)
    is_plan_active = models.BooleanField(default = False)
    auto_renewal = models.BooleanField(default = True)
    cancel_reason = models.TextField(null = True, blank = True)
    price = models.FloatField(blank= True, null = True)
    cancelled_on = models.DateTimeField(null = True, default = None, blank = True)
    last_renewal_date = models.DateTimeField(null = True, default = None, blank = True)
    is_paused = models.BooleanField(null = True, default = False)

    stripe_price = models.ForeignKey(StripePrice, on_delete = models.CASCADE, null = True, blank = True)
    stripe_subscription_id = models.CharField(max_length = 100, null = True, blank = True)
    stripe_product = models.ForeignKey(StripeProduct, on_delete = models.CASCADE, null = True, blank = True)

    def __str__(self) -> str:
        return f"{self.organization.name}, {self.subscription_plan.plan_type}, {self.is_plan_active}, {self.expiry_date}"



class Transaction(models.Model):
    organization = models.ForeignKey("accounts.Organization", on_delete = models.SET_NULL, null = True, related_name = "subscription_transaction_org")
    user = models.ForeignKey("accounts.User", on_delete = models.SET_NULL, null = True, related_name = "transaction_user")
    subscription_plan = models.ForeignKey(SubscriptionPlan, on_delete = models.SET_NULL, null = True)
    organization_plan = models.ForeignKey(OrganizationPlan, on_delete = models.SET_NULL, null = True)
    stripe_checkout_session = models.CharField(max_length = 150, null = True)
    payment_method = models.CharField(max_length = 50, null = True)
    payment_method_id = models.CharField(max_length = 50, null = True)
    status = models.CharField(max_length = 20)
    invoice_link = models.CharField(max_length = 250, null = True)
    date = models.DateTimeField()
    no_of_device = models.IntegerField()
    amount = models.FloatField()


class StripeEvent(models.Model):
    event_id = models.CharField(max_length = 150, unique = True)
    event_name = models.CharField(max_length = 150, null = True, blank = True)
    created_at = models.DateTimeField(auto_now = True, null = True, blank = True)
