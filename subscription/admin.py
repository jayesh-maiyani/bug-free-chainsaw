from django.contrib import admin
from .models import *

# Register your models here.
class SubscriptionPlanAdmin(admin.ModelAdmin):
  list_display = ("plan_type", "applied_discount", "discount", "stripe_price", "is_active")
  
admin.site.register(SubscriptionPlan, SubscriptionPlanAdmin)


class OrganizationPlanAdmin(admin.ModelAdmin):
  list_display = ['subscription_plan', 'organization', 'device_limit', 'price', 'expiry_date', 'is_plan_active', 'stripe_subscription_id', 'stripe_price_id', 'stripe_product_id']
admin.site.register(OrganizationPlan, OrganizationPlanAdmin)


class TransactionAdmin(admin.ModelAdmin):
  list_display = ['organization', 'organization_plan', 'amount', 'no_of_device', 'date']

admin.site.register(Transaction, TransactionAdmin)


class StripeCardAdmin(admin.ModelAdmin):
  list_display = ['user', 'holder_name', 'brand', 'country', 'last4', 'exp_year', 'exp_month']

admin.site.register(StripeCard, StripeCardAdmin)

class StripeCustomerAdmin(admin.ModelAdmin):
  list_display = ['id', 'user', 'organization', 'stripe_customer_id']

admin.site.register(StripeCustomer, StripeCustomerAdmin)


class StripePriceAdmin(admin.ModelAdmin):
  list_display = ['id', 'stripe_price_id', 'recurring_type', 'interval_count', 'price', 'is_live', 'product']
admin.site.register(StripePrice, StripePriceAdmin)


class StripeProductAdmin(admin.ModelAdmin):
  list_display = ['id', 'stripe_product_id', 'product_name', 'is_active']
admin.site.register(StripeProduct, StripeProductAdmin)

# admin.site.register(Transaction)

