######################### Subscription Serializers #########################################################################################

from .models import *
from rest_framework import serializers

from django.conf import settings
import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = [
            "id",
            "plan_type",
            "discount",
            'applied_discount'
        ]

    def to_representation(self, instance):
        rep = super(SubscriptionPlanSerializer, self).to_representation(instance)
        if instance.plan_type == "MONTHLY":
            rep['per_device_price'] = instance.stripe_price.price / 100
        elif instance.plan_type == "YEARLY":
            rep['per_device_price'] = instance.stripe_price.price / 100
            rep['plan_type'] = "ANNUALLY"
        elif instance.plan_type == "DAILY":
            rep['per_device_price'] = instance.stripe_price.price / 100
        else:
            rep['per_device_price'] = 0
        try:
            if instance.applied_discount:
                rep['original_price'] = round(100 * (instance.stripe_price.price / 100) / (100 - instance.discount))
            else:
                rep['original_price'] = instance.stripe_price.price / 100
        except:
            rep['original_price'] = 0
        return rep


class OrganizationPlanSerializer(serializers.ModelSerializer):
    services = serializers.SerializerMethodField()
    plan_type = serializers.SerializerMethodField()
    class Meta:
        model = OrganizationPlan
        fields = [
            'id',
            'device_limit',
            'subscription_plan',
            'services',
            'stripe_subscription_id',
            'price',
            'organization',
            'utilized_limit',
            'un_used_devices',
            'commencing_date',
            'plan_updated_date',
            'expiry_date',
            'is_plan_active',
            'auto_renewal',
            'is_paused',
            'plan_type'
        ]

    def get_plan_type(self, instance):
        return instance.subscription_plan.plan_type

    def get_services(self, instance):
        master_services = instance.services.all()
        if master_services is not None:
            return [service.name for service in master_services]
        else:
            return []
        

class StripeCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = StripeCard
        fields = [
            'id',
            'brand',
            'country',
            'holder_name',
            'funding',
            'exp_month',
            'exp_year',
            'last4',
            'created_date',
            'last_used_date'
        ]

    def to_representation(self, instance):
        rep = super(StripeCardSerializer, self).to_representation(instance)
        rep['exp_month'] = '0'+str(instance.exp_month) if len(str(instance.exp_month)) == 1 else str(instance.exp_month)
        rep['exp_year'] = str(instance.exp_year)[2:]
        return rep



class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = [
            "id",
            "status",
            "date",
            "no_of_device",
            'invoice_link',
            "amount",
            'payment_method'
        ]

    def to_representation(self, instance):
        rep = super(TransactionSerializer,self).to_representation(instance) 
        rep["plan_name"] = instance.subscription_plan.plan_type.capitalize()
        rep['current_plan_id'] = instance.subscription_plan.id
        rep['current_per_device_price'] = round(instance.organization_plan.stripe_price.price / 100)
        return rep
