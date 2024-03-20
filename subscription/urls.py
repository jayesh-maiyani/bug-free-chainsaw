from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import *


router = DefaultRouter()
router.register('checkout',  OrganizationSubscriptionView, basename = "session-checkout")
router.register('transactions', TransactionView, basename = 'transactions')

urlpatterns = [
    path('webhook/' , WebHookView.as_view(), name = "webhook"),
    path('list-services/', ListMasterServicesAPIView.as_view(), name = "list-services"),
    path('list-plans/', ListPlans.as_view(), name = "list-plans"),
    path('', include(router.urls)),
]