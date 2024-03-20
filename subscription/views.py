from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import get_template
from django.db.models import Q

from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import status

from accounts.cron import reactivate_organization
from accounts.models import Device, MasterService, Organization, OrgnisationService, OrgnisationSubService, Service, SubService, User, LogModel, Location
from accounts.pagination import StandardResultsSetPagination
from accounts.serializers import DeviceDashboardSerializer, MasterServiceSerializer
from accounts.helpers import client_log
from accounts.tasks import send_info_email_task, send_subscription_email_task, otp_mail_connection

from .serializers import *

# Create your views here.
import stripe


stripe.api_key = settings.STRIPE_SECRET_KEY
endpoint_secret = settings.STRIPE_WEBHOOK_SECRET


class ListPlans(APIView):
    def get(self, request):
        queryset = SubscriptionPlan.objects.filter(is_active = True).order_by("id")
        serializer = SubscriptionPlanSerializer(queryset, many = True)
        org = Organization.objects.get(user = request.user)
        org_plans = OrganizationPlan.objects.filter(organization = org)
        expired = True
        if org_plans.exists():
            subscriptions = org_plans.filter(is_plan_active = True)
            if subscriptions.exists():
                expired = False
        return Response({'plans':serializer.data, 'can_get_trial': not org_plans.exists(), 'is_plan_expired':expired}, status = status.HTTP_200_OK)
    

class ListMasterServicesAPIView(APIView):

    def get(self, request):
        queryset = MasterService.objects.filter(service_active = True)
        serializer = MasterServiceSerializer(queryset, many = True)
        return Response({"services":serializer.data}, status = status.HTTP_200_OK)



class OrganizationSubscriptionView(ModelViewSet):
    serializer_class = OrganizationPlanSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        user_org = Organization.objects.get(user = self.request.user)
        queryset = OrganizationPlan.objects.filter(organization = user_org, is_plan_active = True)
        if queryset.exists():
            plan = queryset.first()
            plan.utilized_limit = Device.objects.filter(org = user_org, soft_delete = False, is_subscribed = True).count()
            plan.save()
        queryset = OrganizationPlan.objects.filter(organization = user_org, is_plan_active = True)
        return queryset



    @action(methods = ['POST'], detail = False, url_path = 'contact-us')
    def contact_us(self, request):
        try:            
            send_mail(
                subject = "Custom Plan Enquiry",
                from_email = settings.OTP_EMAIL,
                message = "From: " + request.user.username + '\nName: ' + request.user.get_full_name() + \
                    "\nComapny details:\nCompany name: " + request.user.org + \
                    "\nCompany email: " + request.data['company_email'] + \
                    "\nNumber of device: " + str(request.data['num_device']) + "\n\nMessage: " + request.data['message'],
                connection = otp_mail_connection,
                recipient_list = ['customer-support@fusiondatasecure.com']
                
                # recipient_list = ['jayeshmaiyani37@gmail.com']
            )
            return Response({"message":"Thank you for your time, we will contact you shortly."}, status = status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error':'Please fill all the details.'}, status = status.HTTP_400_BAD_REQUEST)
        

    @action(methods = ['POST'], detail = False, url_path = 'contact-to-expire')
    def contact_us_to_expire(self, request):
        org = Organization.objects.get(user = request.user)
        try:
            instance = request.user
            recipient_list = ['customer-support@fusiondatasecure.com']
            # recipient_list = ['jayeshmaiyani37@gmail.com']
            message = get_template("subscription/new_subscription_request.html").render({
                'owner_mail': instance.username,
                'owner': instance.get_full_name(),
                'org': org.name,
                'message': request.data['message']
            })

            subject = 'New Subscription Request From Subscriber'
            send_info_email_task(recipients=recipient_list, subject=subject, message=message)

            return Response({"message":"Thank you for your time, we will contact you shortly."}, status = status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error':'Please fill all the details.'}, status = status.HTTP_400_BAD_REQUEST)

        

    @action(methods=["GET"], detail=True, url_path = "device-counts")
    def get_device_counts(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)        
        try:
            org_plans = OrganizationPlan.objects.filter(id = pk, is_plan_active = True)
            org = Organization.objects.get(name = request.user.org)

            if org_plans.exists():
                org_plan = org_plans.first()
            else:
                return Response({"data":""}, status = status.HTTP_200_OK)
            
            masterservices_name = [ms.name for ms in org_plan.services.all()]
            services = Service.objects.filter(orgnization = org, name__in = masterservices_name)
            
            registered_devices = Device.objects.filter(Q(org = org) & Q(is_subscribed = True) & Q(soft_delete = False))
            id_set = set()
            for d in registered_devices:
                id_set.add(d.id)
            registered_devices = Device.objects.filter(id__in = list(id_set), soft_delete = False)

            device_type_counts = dict()
            device_type_counts["windows"] = registered_devices.filter(device_type = "1").count()
            device_type_counts["mac"] = registered_devices.filter(device_type = "2").count()
            device_type_counts["android"] = registered_devices.filter(device_type = "3").count()
            device_type_counts["ios"] = registered_devices.filter(device_type = "4").count()
            device_type_counts['utilized_percentage'] = "{:.2f}%".format(org_plan.utilized_limit / org_plan.device_limit * 100) 

            return Response({"data":device_type_counts}, status = status.HTTP_200_OK)
        except Exception as e:
            return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)


    @action(methods = ['GET'], detail = False, url_path = 'card')
    def get_card(self, request):
        if request.user.is_owner:

            cards = StripeCard.objects.filter(user = request.user).order_by('-last_used_date')
            if cards.exists():
                card = cards.first()
                serializer = StripeCardSerializer(card)
                return Response({"data":serializer.data}, status = status.HTTP_200_OK)
            else:
                return Response({'data':""}, status = status.HTTP_200_OK)
        else:
            return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    @action(methods = ['GET'], detail = False, url_path = 'all-devices')
    def get_all_devices(self, request):
        org = Organization.objects.get(user = request.user)
        org_plan = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        plan_limit = 0
        utilized_limit = 0

        devices = Device.objects.filter(org = org, soft_delete = False, is_subscribed = False)
        device_count = devices.count()
        
        
        if 'search' in self.request.query_params:
            devices = devices.filter(Q(device_name__istartswith = self.request.query_params['search']) | Q(mac_address__icontains = self.request.query_params['search']))

        if org_plan.exists():
            plan = org_plan.first()
            plan_limit = plan.device_limit
            plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
            plan.save()
            utilized_limit = plan.utilized_limit
            if device_count == 0:
                return Response({'data':[], 'unregistered_counts': device_count, 'plan_limit':plan_limit, 'utilized_limit':utilized_limit}, status = status.HTTP_200_OK)
            elif plan_limit == utilized_limit:
                return Response({'data':[], 'unregistered_counts': device_count, 'plan_limit':plan_limit, 'utilized_limit':utilized_limit}, status = status.HTTP_200_OK)
            serializer = DeviceDashboardSerializer(devices, many = True)
            return Response({'data':serializer.data, 'unregistered_counts': device_count, 'plan_limit':plan_limit, 'utilized_limit':utilized_limit})
        else:
            return Response({'data':[], 'unregistered_counts': device_count, 'plan_limit':plan_limit, 'utilized_limit':utilized_limit}, status = status.HTTP_200_OK)
        


    def create(self, request):
        if request.user.is_owner:
            plan_id = request.data['plan_id']
            if not isinstance(request.data['plan_id'], int):
                return Response({'error':'plan_id must be an integer.'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                master_plan = SubscriptionPlan.objects.get(id = plan_id)
            except:
                return Response({"error":f"Master subscription plan with {plan_id} does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            
            if master_plan.plan_type == "TRIAL":
                no_of_devices = 1
            else:
                try:
                    no_of_devices = int(request.data['no_of_devices'])
                except:
                    return Response({'error':'no_of_devices must be a valid integer.'}, status=status.HTTP_400_BAD_REQUEST)
                if no_of_devices <= 0:
                    return Response({'error':"Please enter a valid integer value for number of devices."}, status=status.HTTP_400_BAD_REQUEST)

            org = Organization.objects.get(user = request.user)
            plan = SubscriptionPlan.objects.get(id = plan_id)

            # because of only one service we are directly assuming that client is buying plan for this service only.
            # later we can create one api for listing all the services and getting the service ids from frontend

            service_ids = [MasterService.objects.order_by('-id').first().id]
            for id in service_ids:
                if not isinstance(id, int):
                    return Response({'error':'service_ids must contain integers only.'}, status=status.HTTP_400_BAD_REQUEST)

            services = MasterService.objects.filter(id__in = service_ids)

            old_plans = OrganizationPlan.objects.filter(organization = org)

            
            if old_plans.exists() and master_plan.plan_type == "TRIAL":
                return Response({'error':"Please consider buying one of our subscription plans."}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            
            if master_plan.plan_type == "TRIAL":               
                org_plan = OrganizationPlan.objects.create(
                    device_limit = no_of_devices,
                    utilized_limit = 0,
                    price = 0,
                    is_plan_active = True,
                    commencing_date = datetime.now(),
                    plan_updated_date = datetime.now(),
                    expiry_date = datetime.now() + timedelta(days = 7),
                    organization = org,
                    subscription_plan = plan,
                    auto_renewal = False
                )

                org.licence = 1
                org.save()
                services = MasterService.objects.filter(id__in = service_ids)
                org_plan.services.add(*services)
                org_plan.save()


                for service in services:
                    organization_service = OrgnisationService.objects.create(
                        name = service.name,
                        create_on = org_plan.commencing_date.date(),
                        expire_on = org_plan.expiry_date.date(),
                        service_active = True,
                        Subscribed = True,
                        orginstion = org,
                        price = service.price
                    )
                    if not service.standalone:
                        master_subservices = service.mastersubsevice_set.all()
                        for sub_service in master_subservices:
                            org_sub_service = OrgnisationSubService.objects.create(
                                name = sub_service.sub_service_name,
                                service = organization_service,
                                orginstion = org,
                                executionTime = sub_service.default_execution_time,
                                raw_executionTime = sub_service.raw_default_execution_time
                            )

                client_log(request, org, "Availed 7 days free trial.")
                return Response({"message":"Your 7 days trial has been started."}, status=status.HTTP_200_OK)

            if OrganizationPlan.objects.filter(subscription_plan = plan, organization = org, is_plan_active = True).exists():
                return Response({"error":"You already have subscribed to similar plan. Consider upgrading it."}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)
            
            if OrganizationPlan.objects.filter(subscription_plan__plan_type__in = ['MONTHLY', 'YEARLY', 'CUSTOM', 'DAILY'], organization = org, is_plan_active = True).exists():
                return Response({'error':"You already have an active plan."}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)


            stripe_customers = StripeCustomer.objects.filter(user = request.user)
            if not stripe_customers.exists():
                
                customer = stripe.Customer.create(
                    email = request.user.username,
                    # payment_method = payment_method
                )

                StripeCustomer.objects.create(
                    user = request.user,
                    organization = org,
                    stripe_customer_id = customer['id']
                )

            else:
                stripe_customer = stripe_customers.first()
                customer = stripe.Customer.retrieve(
                    stripe_customer.stripe_customer_id
                )


            service_ids = " ".join([str(i) for i in service_ids])

            price_id = StripePrice.objects.get(recurring_type = 'month', interval_count = 1, is_live = True).stripe_price_id #default is monthly

            if master_plan.plan_type == "YEARLY":
                price_id = StripePrice.objects.get(recurring_type = 'year', interval_count = 1, is_live = True).stripe_price_id #yearly


            elif master_plan.plan_type == "MONTHLY":
                price_id = price_id #monthly

            elif master_plan.plan_type == "DAILY":
                price_id = StripePrice.objects.get(recurring_type = 'day', interval_count = 1, is_live = True).stripe_price_id

            try: 
                checkout_session = stripe.checkout.Session.create(
                    customer = customer.id,
                    line_items = [
                        {
                            'price':price_id,
                            'quantity': no_of_devices
                        }
                    ],
                    payment_method_types=['card'],
                    mode = 'subscription',
                    # subscription_data = {
                    #     'proration_behavior': 'always_invoice',
                    #     'billing_cycle_anchor': 'now'
                    # },

                    success_url = f"{settings.CLIENT_FRONTEND_URL}/thankyou/",
                    cancel_url = f"{settings.CLIENT_FRONTEND_URL}/error/",
                    metadata = {
                        # "total_price": total_price,
                        'session_type':"new_plan",
                        'org_id': str(org.id),
                        'org_name':org.name,
                        'user_id':str(request.user.id),
                        'service_ids':service_ids,
                        'plan_id':str(plan_id),
                        'no_of_devices':str(no_of_devices)
                    }

                )

                return Response({"url":checkout_session.url}, status = status.HTTP_200_OK)
            except Exception as e:
                return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    @action(methods = ['PUT'], detail = True, url_path = "add-devices")
    def add_devices(self, request, pk = id):
        try:
            if not pk.isnumeric():
                return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
            
            if request.user.is_owner:
                
                org_plans = OrganizationPlan.objects.filter(id = pk, is_plan_active = True)
                org = Organization.objects.get(name = request.user.org)
                
                if org_plans.exists():
                    org_plan = org_plans.first()
                    if org_plan.subscription_plan.plan_type == "TRIAL":
                        return Response({'error':'Please consider subscribing to one of our plans'}, status = status.HTTP_400_BAD_REQUEST)
                    if org_plan.is_paused:
                        return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                    if not org_plan.auto_renewal:
                        return Response({'error':'You have stopped auto renewal of your subscripton.'}, status = status.HTTP_400_BAD_REQUEST)
                    no_of_devices = request.data['no_of_devices']


                    if not isinstance(no_of_devices, int):
                        return Response({'error':'no_of_devices must be a valid integer.'}, status=status.HTTP_400_BAD_REQUEST)

                    if no_of_devices <= 0:
                        return Response({'error':'Number of devices should be atleast 1.'}, status=status.HTTP_400_BAD_REQUEST)
                    
                    stripe_subscription = stripe.Subscription.retrieve(
                        id = org_plan.stripe_subscription_id
                    )

                    plan = stripe.Plan.retrieve(stripe_subscription.plan.id)

                    # Determine the billing interval (month or year) and interval count
                    interval_count = plan.interval_count
                    interval = plan.interval


                    ###### for testing purpose I have set it to 1 day plan before push check once
                    today = datetime.now()
                    remaining_days = (datetime.utcfromtimestamp(stripe_subscription['current_period_end']) - datetime.now()).days
                    if interval == "month":
                        last_renewal = org_plan.expiry_date - relativedelta(months=interval_count)
                        if last_renewal.day == today.day and last_renewal.month == today.month:
                            plan_price = stripe.Price.retrieve(
                                org_plan.stripe_price.stripe_price_id
                            )
                            prorated_amount = round(plan_price['unit_amount'] / 100) * no_of_devices * 100
                        else:
                            total_plan_days = (org_plan.expiry_date - last_renewal).days
                            amount_per_day = stripe_subscription.plan.amount / total_plan_days  # assuming the plan is monthly
                            prorated_amount = int(amount_per_day * no_of_devices * remaining_days)

                        # amount_per_second = stripe_subscription.plan.amount /  24 / 3600  # assuming the plan is daily


                    if interval == "year":
                        last_renewal = org_plan.expiry_date - relativedelta(years=interval_count)
                        if last_renewal.day == today.day and last_renewal.month == today.month:
                            plan_price = stripe.Price.retrieve(
                                org_plan.stripe_price.stripe_price_id
                            )
                            prorated_amount = round(plan_price['unit_amount'] / 100) * no_of_devices * 100                        
                        else:
                            total_plan_days = (org_plan.expiry_date - last_renewal).days
                            amount_per_day = stripe_subscription.plan.amount / total_plan_days # assuming the plan is yearly
                            prorated_amount = int(amount_per_day * no_of_devices * remaining_days)

                    if interval == "day":
                        last_renewal = org_plan.expiry_date
                        plan_price = stripe.Price.retrieve(
                            org_plan.stripe_price.stripe_price_id
                        )
                        prorated_amount = plan_price['unit_amount'] * no_of_devices

                    # remaining_days = (datetime.fromtimestamp(stripe_subscription['current_period_end']) - datetime.now()).days
                    

                    # if org_plan.subscription_plan.plan_type == "MONTHLY":
                    #     amount_per_hour = stripe_subscription.plan.amount / 30 / 24  # assuming the plan is monthly

                    # if org_plan.subscription_plan.plan_type == "YEARLY":
                    #     amount_per_hour = stripe_subscription.plan.amount / 365 / 24 # assuming the plan is yearly
                    # prorated_amount = int(amount_per_hour * no_of_devices * remaining_days * 24)
                    
                    stripe_product_obj = StripeProduct.objects.first().stripe_product_id

                    price = stripe.Price.create(
                        unit_amount = prorated_amount,
                        currency = 'usd',
                        recurring = None,
                        product = stripe_product_obj
                    )

                    session = stripe.checkout.Session.create(
                        mode = 'payment',
                        payment_method_types = ["card"],
                        customer = stripe_subscription.customer,
                        line_items=[
                            {
                                "price": price,
                                "quantity": 1,
                            }
                        ],
                        metadata = {
                            "session_type":'add_devices',
                            'org_id': str(org.id),
                            'org_plan_id':str(org_plan.id),
                            'org_name':org.name,
                            'user_id':str(request.user.id),
                            'plan_id':str(org_plan.subscription_plan.id),
                            'stripe_subscription_id':stripe_subscription.id,
                            'no_of_devices':str(no_of_devices)
                        },
                        invoice_creation = {"enabled": True},

                        success_url = f"{settings.CLIENT_FRONTEND_URL}/thankyou/",
                        cancel_url = f"{settings.CLIENT_FRONTEND_URL}/error/"
                    )
                    
                    return Response({'url': session.url}, status = status.HTTP_200_OK)
                return Response({'error':"You are not subscribed to this plan."}, status = status.HTTP_400_BAD_REQUEST)

            else:
                return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)

    

    @action(methods = ['GET'], detail = True, url_path = "devices")
    def get_devices(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.is_owner:
            org = Organization.objects.get(user=request.user)
            devices = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True)
            device_count = devices.count()
            org_plans = OrganizationPlan.objects.filter(id = pk, is_plan_active = True)
            if org_plans.exists():
                org_plan = org_plans.first()
            else:
                return Response({"error":"You are not subscribed to this plan."}, status = status.HTTP_400_BAD_REQUEST)
            org = Organization.objects.get(name = request.user.org)
            registered_devices = Device.objects.filter(Q(org = org) & Q(is_subscribed = True) & Q(soft_delete = False))
            id_set = set()
            for d in registered_devices:
                id_set.add(d.id)
            registered_devices = Device.objects.filter(id__in = list(id_set), soft_delete = False, is_subscribed = True)

            if bool(request.query_params):
                if 'search' in request.query_params:
                    search = request.query_params['search'].strip()
                    registered_devices = registered_devices.filter(device_name__istartswith = search)

            unused_count = org_plan.device_limit - device_count
            serializer = DeviceDashboardSerializer(registered_devices, many = True, context = {'org':org})
            return Response({"results":serializer.data, "total_counts":org_plan.device_limit, 'count':registered_devices.count(),'unused_device':unused_count}, status = status.HTTP_200_OK)
            
        else:
            return Response({"error":"You are not authorized."}, status = status.HTTP_403_FORBIDDEN)


    @action(methods = ['PUT'], detail = True, url_path = "reduce-devices")
    def reduce_devices(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.is_owner:

            if "device_ids" in request.data:
                no_of_unutilized_devices = request.data['unutilized']
                device_ids = [int(id) for id in request.data['device_ids']]                

            org_plans = OrganizationPlan.objects.filter(id = pk, is_plan_active = True)
            org = Organization.objects.get(name = request.user.org)
            if org_plans.exists():
                org_plan = org_plans.first()
                if not org_plan.auto_renewal:
                    return Response({'error':'You have stopped auto renewal of your subscripton.'}, status = status.HTTP_400_BAD_REQUEST)
                if org_plan.is_paused:
                    return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                unused = org_plan.device_limit - org_plan.utilized_limit
                if not no_of_unutilized_devices <= unused:
                    return Response({'error':"You don't have unused devices"}, status=status.HTTP_400_BAD_REQUEST)

                devices = Device.objects.filter(org = org, id__in = device_ids, soft_delete = False)
                id_set = set()
                for d in devices:
                    id_set.add(d.id)
                devices = Device.objects.filter(id__in = list(id_set), soft_delete = False)
                remove_devices = len(devices)
                new_quantity = org_plan.device_limit - remove_devices - no_of_unutilized_devices

                if new_quantity <= 0:
                    return Response({'error':'Invalid number of devices to be reduced.'}, status=status.HTTP_400_BAD_REQUEST)

                for device in devices:
                    if not device.soft_delete:
                        device.soft_delete = True
                        device.is_active = False
                        device.is_subscribed = False
                        service = device.services.all().first()
                        subservices = SubService.objects.filter(service = service)
                        subservices.delete()
                        service.delete()
                        device.save()


                stripe_subscription = stripe.Subscription.retrieve(
                    id = org_plan.stripe_subscription_id
                )


                stripe.Subscription.modify(
                    stripe_subscription.id,
                    proration_behavior = 'none',
                    billing_cycle_anchor = "unchanged",
                    items = [{"id": stripe_subscription['items']['data'][0]['id'], "quantity": new_quantity}],
                )
                per_device_price = org_plan.price / org_plan.device_limit
                org_plan.device_limit = new_quantity
                org_plan.utilized_limit -= remove_devices
                org_plan.price = new_quantity * per_device_price
                org_plan.save()
                org.licence = new_quantity
                org.save()

                client_log(request, org, f"Removed {remove_devices + no_of_unutilized_devices} devices from your current {'annual' if org_plan.subscription_plan.plan_type == 'YEARLY' else 'monthly'} subscription plan.")

                return Response({'message':"Successfully reduced the device limit."}, status = status.HTTP_200_OK)


            return Response({'error':"You are not subscribed to this plan."}, status = status.HTTP_400_BAD_REQUEST)

        else:
            return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    @action(methods = ['PUT'], detail = True, url_path = "cancel-subscription")
    def cancel_subscription(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.is_owner:

            org = Organization.objects.get(user = request.user)

            org_plans = OrganizationPlan.objects.filter(organization = org, id = pk, is_plan_active = True)

            if org_plans.exists():
                    
                org_plan = org_plans.first()
                
                if not org_plan.auto_renewal :
                    return Response({"error":"You've already unsubscribed this plan."}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)
                
                stripe.Subscription.modify(
                    org_plan.stripe_subscription_id,
                    cancel_at_period_end = True
                )

                org_plan.auto_renewal = False
                org_plan.cancel_reason = request.data['reason']
                org_plan.cancelled_on = datetime.now()
                org_plan.save()

                client_log(request, org, f"Cancelled renewal of current {'annual' if org_plan.subscription_plan.plan_type == 'YEARLY' else 'monthly'} subscription plan of {org_plan.device_limit} devices.")

                return Response({'message':"Your subscription won't be auto-renewed nowon."}, status = status.HTTP_200_OK)
            else:
                return Response({'error':"Organization plan does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.is_owner:
            org_plans = OrganizationPlan.objects.filter(id = pk, is_plan_active = True)
            if org_plans.exists():
                org_plan = org_plans.first()

                stripe_subscription = stripe.Subscription.retrieve(
                    id = org_plan.stripe_subscription_id
                )

            return Response({"subscription":stripe_subscription})
        else:
            return Response({'error':"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


from rest_framework.throttling import AnonRateThrottle
class WebHookView(APIView):

    def get_throttles(self):
        # Get the default throttles applied to the view
        throttles = super().get_throttles()

        # Remove the AnonRateThrottle if it exists in the default throttles
        throttles = [throttle for throttle in throttles if not isinstance(throttle, AnonRateThrottle)]

        return throttles

    def post(self, request):
        event = None
        payload = request.body.decode('utf-8')
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError as e:
            # Invalid payload
            raise e
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            raise e
        
        if event['type'] == "product.created":
            if not event_exists(event['id']):
                event_data = event['data']
                stripe_prod_id = event_data['data']['id']
                stripe_prod_name = event_data['data']['name']
                stripe_product = StripeProduct.objects.create(
                    stripe_product_id = stripe_prod_id,
                    stripe_prod_name = stripe_prod_name
                )
                create_event(event['id'], event['type'])
        
        if event['type'] == "price.created":
            if not event_exists(event['id']):
                event_data = event['data']
                price_type = event_data['object']['type']
                stripe_prod_id = event_data['object']['product']
                if price_type == "recurring":
                    interval = event_data['object']['recurring']['interval']
                    interval_count = event_data['object']['recurring']['interval_count']

                    if interval == "month" and interval_count == 1:
                        stripe_product = StripeProduct.objects.get(stripe_product_id = stripe_prod_id)
                        unit_amount = event_data['object']['unit_amount']
                        new_price = StripePrice.objects.create(
                            stripe_price_id = event_data['object']['id'],
                            product = stripe_product,
                            recurring_type = interval,
                            price = unit_amount,
                            interval_count = interval_count
                        )
                        subscription_plan = SubscriptionPlan.objects.get(plan_type = "MONTHLY")
                        old_price = subscription_plan.stripe_price
                        old_price.is_live = False
                        old_price.save()
                        subscription_plan.stripe_price = new_price
                        subscription_plan.save()


                    elif interval == "year" and interval_count == 1:
                        stripe_product = StripeProduct.objects.get(stripe_product_id = stripe_prod_id)
                        unit_amount = event_data['object']['unit_amount']
                        new_price = StripePrice.objects.create(
                            stripe_price_id = event_data['object']['id'],
                            product = stripe_product,
                            recurring_type = interval,
                            price = unit_amount,
                            interval_count = interval_count
                        )
                        subscription_plan = SubscriptionPlan.objects.get(plan_type = "YEARLY")
                        old_price = subscription_plan.stripe_price
                        old_price.is_live = False
                        old_price.save()
                        subscription_plan.stripe_price = new_price
                        subscription_plan.save()

                    elif interval == "day" and interval_count == 1:
                        stripe_product = StripeProduct.objects.get(stripe_product_id = stripe_prod_id)
                        unit_amount = event_data['object']['unit_amount']
                        new_price = StripePrice.objects.create(
                            stripe_price_id = event_data['object']['id'],
                            product = stripe_product,
                            recurring_type = interval,
                            price = unit_amount,
                            interval_count = interval_count
                        )
                        subscription_plan = SubscriptionPlan.objects.get(plan_type = "DAILY")
                        old_price = subscription_plan.stripe_price
                        old_price.is_live = False
                        old_price.save()
                        subscription_plan.stripe_price = new_price
                        subscription_plan.save()

                    else:
                        stripe_product = StripeProduct.objects.get(stripe_product_id = stripe_prod_id)
                        unit_amount = event_data['object']['unit_amount']
                        new_price = StripePrice.objects.create(
                            stripe_price_id = event_data['object']['id'],
                            product = stripe_product,
                            recurring_type = interval,
                            price = unit_amount,
                            interval_count = interval_count
                        )  
                    create_event(event['id'], event['type'])
            

        if event['type'] == 'checkout.session.completed':
            if not event_exists(event['id']):
                # Retrieve the session. If you require line items in the response, you may include them by expanding line_items.
                try:
                    session = stripe.checkout.Session.retrieve(
                        event['data']['object']['id'],
                        expand=['line_items'],
                    )

                    session_type = session['metadata']['session_type']

                    payment_status = session["payment_status"]

                    if payment_status == "paid":
                        if session_type == 'add_devices':
                            add_devices_to_existing_plan(session)

                        if session_type == "new_plan":
                            create_new_plan(session)

                    elif payment_status == "failed":
                        if session_type == 'add_devices':
                            create_transaction(session, payment_status)

                    elif payment_status == 'canceled':
                        if session_type == 'add_devices':
                            create_transaction(session, payment_status)

                    create_event(event['id'], event['type'])
                except Exception as e:
                    pass


        if event['type'] == "invoice.paid":
            if not event_exists(event['id']):
                reason = event['data']['object']['billing_reason']
                collection_method = event['data']['object']["collection_method"]
                invoice = event['data']['object']['invoice_pdf']
                amount = event['data']['object']['amount_paid'] / 100
                quantity = event['data']['object']['lines']['data'][0]['quantity']
                is_paid = event['data']['object']['paid'] #bool
                payment_intent = event['data']['object']['payment_intent']
                date = event['data']['object']['status_transitions']['finalized_at']
                sid = event['data']['object']['subscription']
                next_renewal = event['data']['object']['lines']['data'][0]['period']['end']

                next_renewal_date = datetime.utcfromtimestamp(next_renewal)

                if is_paid and reason == "subscription_cycle" and collection_method == "charge_automatically":
                    org_plan_qs = OrganizationPlan.objects.filter(stripe_subscription_id = sid)
                    if org_plan_qs.exists():
                        org_plan = org_plan_qs.first()
                        org_plan.expiry_date = next_renewal_date
                        org_plan.last_renewal_date = datetime.utcfromtimestamp(date)
                        if org_plan.is_paused:
                            org_plan.is_paused = False
                        org_plan.save()

                        org = org_plan.organization
                        owner = org.user.filter(is_owner = True).first()

                        intent = payment_intent = stripe.PaymentIntent.retrieve(
                            id = payment_intent
                        )

                        pm_id = intent['payment_method']
                        payment_method = stripe.PaymentMethod.retrieve(
                            id = pm_id
                        )

                        card = payment_method['card']

                        Transaction.objects.create(
                            organization = org,
                            user = owner,
                            subscription_plan = org_plan.subscription_plan,
                            organization_plan = org_plan,
                            status = "Complete",
                            invoice_link = invoice,
                            date = datetime.utcfromtimestamp(date),
                            no_of_device = quantity,
                            amount = amount,
                            payment_method_id = pm_id,
                            payment_method = card['brand'] + " " + card['last4']
                        )

                        # updatig time of next renewal for all the services and subservices
                        org_service = OrgnisationService.objects.filter(orginstion = org).first()
                        org_service.service_active = True
                        org_service.expire_on = next_renewal_date
                        org_service.Subscribed = True
                        org_service.save()

                        devices = Device.objects.filter(org = org, is_subscribed = True)
                        if devices.exists():
                            for device in devices:
                                service = device.services.all().first()
                                service.Expire_on = next_renewal_date
                                service.save()
                                sub_services = SubService.objects.filter(service = service)
                                sub_services.update(Expire_on = next_renewal_date)

                create_event(event['id'], event['type'])

        if event['type'] == "invoice.payment_failed":
            if not event_exists(event['id']):
                event_data = event['data']
                stripe_subscription_id = event_data['object']['subscription']
                plans = OrganizationPlan.objects.filter(stripe_subscription_id = stripe_subscription_id)
                if plans.exists():
                    plan = plans.first()
                    org_plan.is_paused = True
                    org_plan.save()

                    #getting devices registered under that organization
                    devices = Device.objects.filter(org = plan.organization, is_subscribed = True, soft_delete = False)
                    for device in devices:

                        # getting services existing with device
                        services = device.services.all()
                        for service in services:
                            sub_services = service.subservice_set.all()

                            # getting subservices under each service of the device
                            # deactivating and unsubscribing every service and sub service.
                            for sub_service in sub_services:
                                sub_service.is_active = False
                                sub_service.save()
                            
                            service.service_active = False
                            service.save()
                        
                        data = {
                            'service_change': False, # True when execute_now or crontime update
                            'device_details_change': False,
                            'reauthenticate': False,
                            'code_change': False,
                            'device_status_change':True, # when device status change we need to send it true
                            'service_status_change':False, # when service change send true
                        }
                        device.call_config_types = data
                        device.is_active = False # deactivating the device
                        device.is_online = False
                        device.save()

                create_event(event['id'], event['type'])


        if event['type'] == "customer.subscription.deleted":
            if not event_exists(event['id']):
                event_data = event['data']
                stripe_subscription_id = event_data['object']['id']
                stripe_subscription_status = event_data['object']['status'] # incomplete, incomplete_expired, trialing, active, past_due, canceled, or unpaid

                # If the first invoice is not paid within 23 hours, 
                # the subscription transitions to incomplete_expired. 
                # This is a terminal state, the open invoice will be 
                # voided and no further invoices will be generated.

                if stripe_subscription_status == "canceled":
                    plans = OrganizationPlan.objects.filter(stripe_subscription_id = stripe_subscription_id)
                    if plans.exists():
                        plan = plans.first()
                        organization = plan.organization
                        plan.is_plan_active = False
                        plan.save()
                        organization.licence = 0
                        organization.save()

                        #getting devices registered under that organization
                        devices = Device.objects.filter(org = organization)
                        for device in devices:

                            # getting services existing with device
                            services = device.services.all()
                            for service in services:
                                sub_services = service.subservice_set.all()

                                # getting subservices under each service of the device
                                # deactivating and unsubscribing every service and sub service.
                                for sub_service in sub_services:
                                    sub_service.is_active = False
                                    sub_service.subscribe = False
                                    sub_service.save()
                                
                                service.service_active = False
                                service.save()
                            
                            data = {
                                'service_change': False, # True when execute_now or crontime update
                                'device_details_change': False,
                                'reauthenticate': False,
                                'code_change': False,
                                'device_status_change':True, # when device status change we need to send it true
                                'service_status_change':False, # when service change send true
                            }
                            data = data
                            device.call_config_types = data
                            device.save()
                            device.is_active = False # deactivating the device
                            device.is_online = False
                            device.is_subscribed = False
                            device.save()
                        

                        # getting organization services and related sub-services
                        org_services = OrgnisationService.objects.filter(orginstion = organization)                    
                        for org_service in org_services:

                            # reactivating the services and subservices
                            org_service.Subscribed = False
                            org_service.service_active = False
                            org_service.save()
                            org_sub_services = org_service.orgnisationsubservice_set.all()
                            for org_sub_service in org_sub_services:
                                org_sub_service.is_active = False
                                org_sub_service.save()
                        
                        # reactivating all the users except the owner                    
                        org_users = organization.user.filter(is_owner = False)
                        for user in org_users:
                            user.is_active = False
                            user.save()


                        # reactivating locations
                        locations = Location.objects.filter(organization = organization)
                        for location in locations:
                            location.is_active = False
                            location.save()

                create_event(event['id'], event['type'])            


        return Response({"success":"True"})


def add_devices_to_existing_plan(session):
    org_plan_id = int(session['metadata']['org_plan_id'])
    no_of_devices = int(session['metadata']['no_of_devices'])
    org = Organization.objects.get(id = int(session['metadata']['org_id']))
    user = User.objects.get(id = int(session['metadata']['user_id']))
    org_plan = OrganizationPlan.objects.get(id = org_plan_id)
    new_no_of_devices = no_of_devices + org_plan.device_limit
    plan = SubscriptionPlan.objects.get(id = int(session['metadata']['plan_id']))


    stripe_subscription = stripe.Subscription.retrieve(
        id = session['metadata']['stripe_subscription_id']
    )


    updated_subscription = stripe.Subscription.modify(
        stripe_subscription.id,
        proration_behavior = 'none',
        billing_cycle_anchor = "unchanged",
        items = [{"id": stripe_subscription['items']['data'][0]['id'], "quantity": new_no_of_devices}],
    )

    payment_intent = stripe.PaymentIntent.retrieve(
        session['payment_intent']
    )

    payment_method = stripe.PaymentMethod.retrieve(
        payment_intent['payment_method']
    )

    card = payment_method['card']

    stripe_cards = StripeCard.objects.filter(fingerprint = card['fingerprint'], user = user)
    if stripe_cards.exists():
        stripe_card = stripe_cards.first()
        stripe_card.holder_name = payment_method['billing_details']['name']
        stripe_card.country = card['country']
        
        stripe_card.last_used_date = datetime.utcfromtimestamp(payment_intent['created'])
        stripe_card.save()

    else:
        stripe_card = StripeCard.objects.create(
            user = user,
            payment_method_id = payment_method.id,
            fingerprint = card['fingerprint'],
            brand = card['brand'],
            country = card['country'],
            funding = card['funding'],
            last4 = card['last4'],
            exp_month = card['exp_month'],
            exp_year = card['exp_year'],
            customer = payment_method['customer'],
            holder_name = payment_method['billing_details']['name'],
            last_used_date = datetime.utcfromtimestamp(payment_intent['created'])
        )


    invoice = stripe.Invoice.retrieve(
        session['invoice']
    )

    stripe_customers = StripeCustomer.objects.filter(user = user, organization = org)

    transaction = Transaction.objects.create(
        organization = org,
        user = user,
        subscription_plan = plan,
        organization_plan = org_plan,
        stripe_checkout_session = session['id'],
        payment_method = card['brand'] + " " + card['last4'],
        payment_method_id = payment_method['id'],
        status = 'Complete',
        invoice_link = invoice['invoice_pdf'],
        date = datetime.utcfromtimestamp(invoice['created']),
        no_of_device = no_of_devices,
        amount = invoice['amount_paid'] / 100,
    )


    org_plan.device_limit = new_no_of_devices
    org_plan.price = new_no_of_devices * updated_subscription['items']['data'][0]['price']['unit_amount'] / 100
    org_plan.save()
    org.licence = new_no_of_devices
    org.save()


    devices = Device.objects.filter(org = org, soft_delete = False, is_subscribed = False)
    if (org_plan.device_limit - org_plan.utilized_limit) >= devices.count():
        if devices.exists():
            for device in devices:
                # getting services existing with device
                services = device.services.all()
                for service in services:
                    sub_services = service.subservice_set.all()

                    # getting subservices under each service of the device
                    # reactivating and unsubscribing every service and sub service.
                    for sub_service in sub_services:
                        sub_service.is_active = True
                        sub_service.subscribe = True
                        sub_service.Expire_on = org_plan.expiry_date
                        sub_service.save()
                    
                    service.service_active = True
                    service.Expire_on = org_plan.expiry_date
                    service.save()
                device.is_subscribed = True
                device.is_active = True # reactivating the device
                device.save()
            org_plan.utilized_limit += len(devices)
            org_plan.save()

    LogModel.objects.create(
        org = org,
        action = f"Added {no_of_devices} devices in your current {'annual' if org_plan.subscription_plan.plan_type == 'YEARLY' else 'monthly'} subscription plan.",
        actor_id = user.id
    )


def manage_renewal(subscription_id):
    stripe_subscription = stripe.Subscription.retrieve(
        subscription_id
    )

    new_expiry_date = datetime.utcfromtimestamp(stripe_subscription['current_period_end'])

    client_subscription = OrganizationPlan.objects.get(stripe_subscription_id = subscription_id)

    org = client_subscription.organization

    if new_expiry_date > client_subscription.expiry_date:
        client_subscription.expiry_date = new_expiry_date
        client_subscription.save()
        org_services = OrgnisationService.objects.filter(orginstion = org)
        org_services.update(expire_on = new_expiry_date, is_active = True)
        org_subservices = OrgnisationSubService.objects.filter(orginstion = org)
        org_subservices.update(is_active = True)
        devices = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True)
        for device in devices:
            services = device.services.all()
            for service in services:
                subservices = service.subservice_set.all()
                subservices.update(Expire_on = new_expiry_date, subscribe = True)
                service.Expire_on = new_expiry_date
                service.save()



def create_new_plan(session):
    subscription = stripe.Subscription.retrieve(
        id = session['subscription']
    )

    subscription = stripe.Subscription.modify(
        sid = session['subscription'],
        proration_behavior = "none",
        billing_cycle_anchor = 'unchanged',
    )
    org = Organization.objects.get(id = session['metadata']['org_id'])
    user = User.objects.get(id = int(session['metadata']['user_id']))
    plan = SubscriptionPlan.objects.get(id = int(session['metadata']['plan_id']))

    payment_method = stripe.PaymentMethod.retrieve(
        subscription['default_payment_method']
    )

    stripe_card = payment_method['card']

    stripe_cards = StripeCard.objects.filter(user = user, fingerprint = stripe_card['fingerprint'])

    if stripe_cards.exists():
        card = stripe_cards.first()
        card.holder_name = payment_method['billing_details']['name']
        card.country = stripe_card['country']
        card.last_used_date = datetime.utcfromtimestamp(subscription['current_period_start'])
        card.save()

    else:
        card = StripeCard.objects.create(
            user = user,
            payment_method_id = payment_method.id,
            fingerprint = stripe_card['fingerprint'],
            brand = stripe_card['brand'],
            country = stripe_card['country'],
            funding = stripe_card['funding'],
            last4 = stripe_card['last4'],
            exp_month = stripe_card['exp_month'],
            exp_year = stripe_card['exp_year'],
            customer = payment_method['customer'],
            holder_name = payment_method['billing_details']['name'],
            last_used_date = datetime.utcfromtimestamp(subscription['current_period_start'])
        )        


    trail_plan = OrganizationPlan.objects.filter(organization = org, is_plan_active = True, subscription_plan__plan_type__in = ["TRIAL"])
    if trail_plan.exists():

        trial = trail_plan.first()
        trial.is_plan_active = False
        trial.save()
        devices = Device.objects.filter(org = org, soft_delete = False)
        if devices.exists():
            for device in devices:
                services = device.services.all()
                for service in services:
                    sub_services = service.subservice_set.all()

                    # getting subservices under each service of the device
                    # reactivating and unsubscribing every service and sub service.
                    for sub_service in sub_services:
                        sub_service.is_active = False
                        sub_service.subscribe = False
                        sub_service.save()
                    
                    service.service_active = False
                    service.save()
                device.is_subscribed = False
                device.is_active = False
                device.is_online = False
                device.save()


        ## check this 
        org_services = OrgnisationService.objects.filter(orginstion = org)
        if org_services.exists():
            org_services.delete()


    stripe_price_obj = StripePrice.objects.filter(stripe_price_id = subscription['items']['data'][0]['price']['id'])[0]
    stripe_prod_obj = StripeProduct.objects.filter(stripe_product_id = subscription['items']['data'][0]['price']['product'])[0]

    org_plan = OrganizationPlan.objects.create(
        device_limit = session['line_items']['data'][0]['quantity'],
        stripe_subscription_id = session['subscription'],
        utilized_limit = 0,
        price = session['line_items']['data'][0]['amount_total'] / 100,
        is_plan_active = True,
        commencing_date = datetime.utcfromtimestamp(subscription['current_period_start']),
        plan_updated_date = datetime.utcfromtimestamp(subscription['created']),
        expiry_date = datetime.utcfromtimestamp(subscription['current_period_end']),
        organization = org,
        subscription_plan = plan,
        stripe_price = stripe_price_obj,
        stripe_product = stripe_prod_obj
    )



    invoice = stripe.Invoice.retrieve(
        session['invoice']
    )


    transaction = Transaction.objects.create(
        organization = org,
        user = user,
        subscription_plan = plan,
        organization_plan = org_plan,
        stripe_checkout_session = session['id'],
        payment_method = stripe_card['brand'] + " " + stripe_card['last4'],
        payment_method_id = payment_method['id'],
        status = 'Complete',
        invoice_link = invoice['invoice_pdf'],
        date = datetime.utcfromtimestamp(invoice['created']),
        no_of_device = org_plan.device_limit,
        amount = invoice['amount_paid'] / 100,
    )


    service_ids = session['metadata']['service_ids']
    service_ids = [int(i) for i in service_ids.split()]
    org.licence = session['line_items']['data'][0]['quantity']
    org.save()
    services = MasterService.objects.filter(id__in = service_ids)
    org_plan.services.add(*services)
    org_plan.save()

    if not OrgnisationService.objects.filter(orginstion = org).exists():
        for service in services:
            organization_service = OrgnisationService.objects.create(
                name = service.name,
                create_on = org_plan.commencing_date.date(),
                expire_on = org_plan.expiry_date.date(),
                service_active = True,
                Subscribed = True,
                orginstion = org,
                price = service.price
            )
            if not service.standalone:
                master_subservices = service.mastersubsevice_set.all()
                for sub_service in master_subservices:
                    org_sub_service = OrgnisationSubService.objects.create(
                        name = sub_service.sub_service_name,
                        service = organization_service,
                        orginstion = org,
                        executionTime = sub_service.default_execution_time,
                        raw_executionTime = sub_service.raw_default_execution_time
                    )
    reactivate_organization(org, org_plan)

    url = invoice['invoice_pdf']
    recipient_list = [user.username]
    message = get_template("subscription/subscription_confirmation.html").render({
        'owner_name': user.get_full_name(),
        'amount' : float(invoice['amount_paid']) / 100,
        'invoice_url': url
    })
    subject = 'Subscription Confirmation'
    send_subscription_email_task(recipient_list, subject, message, url)


    LogModel.objects.create(
        actor_id = user.id,
        action = f"Purchased {'annual' if org_plan.subscription_plan.plan_type == 'YEARLY' else 'monthly'} subscription plan for {org_plan.device_limit} devices.",
        org = org
    )


def create_transaction(session, payment_status):
    subscription = stripe.Subscription.retrieve(
        id = session['subscription']
    )
    org_plan_id = int(session['metadata']['org_plan_id'])
    no_of_devices = int(session['metadata']['no_of_devices'])
    org = Organization.objects.get(id = session['metadata']['org_id'])
    user = User.objects.get(id = int(session['metadata']['user_id']))
    plan = SubscriptionPlan.objects.get(id = int(session['metadata']['plan_id']))
    org_plan = OrganizationPlan.objects.get(id = org_plan_id)
    invoice = stripe.Invoice.retrieve(
        session['invoice']
    )

    stripe_subscription = stripe.Subscription.retrieve(
        id = session['metadata']['stripe_subscription_id']
    )

    payment_method = stripe.PaymentMethod.retrieve(
        stripe_subscription['default_payment_method']
    )

    stripe_card = payment_method['card']

    transaction = Transaction.objects.create(
        organization = org,
        user = user,
        subscription_plan = plan,
        organization_plan = org_plan,
        stripe_checkout_session = session['id'],
        payment_method = stripe_card['brand'] + " " + stripe_card['last4'],
        payment_method_id = payment_method['id'],
        status = payment_status,
        invoice_link = invoice['invoice_pdf'],
        date = datetime.utcfromtimestamp(invoice['created']),
        no_of_device = no_of_devices,
        amount = invoice['amount_paid'] / 100,
    )


class TransactionView(ModelViewSet):
    serializer_class = TransactionSerializer
    # pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        org = Organization.objects.get(name = self.request.user.org)
        self.queryset = Transaction.objects.filter(organization = org).order_by('id')

        if bool(self.request.query_params):
            qs = self.queryset
            query = self.request.query_params
              
            #search filter
            if 'year' in query:                
                qs = qs.filter(Q(date__year = int(query['year']))).order_by('-id')
                
            return qs

        return self.queryset.order_by('-id')
    
    def list(self, request, *args, **kwargs):
        subscription_flag = False
        org = Organization.objects.get(user = request.user)
        no_of_devices = Device.objects.filter(org = org, soft_delete = False, is_subscribed = False).count()
        if OrganizationPlan.objects.filter(organization = org, is_plan_active = True).exists():
            subscription_flag = True

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(self.get_queryset(), request) 
        if page is not None:
            serializer = self.get_serializer(page, many = True)
            return paginator.get_paginated_response(serializer.data, subscription_flag = subscription_flag, no_of_devices = no_of_devices)

        serializer = self.get_serializer(self.queryset, many = True)
        return Response({"data":serializer.data, "subscription_flag" : subscription_flag}, status=status.HTTP_200_OK)

    
    def update(self, request, *args, **kwargs):
        pass

    def partial_update(self, request, *args, **kwargs):
        pass

    def destroy(self, request, *args, **kwargs):
        pass




def create_order(session):
    # TODO: fill me in
    pass

def email_customer_about_failed_payment(session):
    # TODO: fill me in
    pass

def event_exists(event_id):
    return StripeEvent.objects.filter(event_id = event_id).exists()

def create_event(event_id, event_name):
    StripeEvent.objects.create(event_id = event_id, event_name = event_name)