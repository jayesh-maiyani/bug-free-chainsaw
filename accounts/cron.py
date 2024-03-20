
from datetime import datetime, timedelta
from django.utils import timezone
from django.template.loader import get_template
import accounts.models
from accounts.serializers import NotificationSerializer
from accounts.tasks import send_info_email_task
import subscription.models 

from .views import SendNotification


def record_users_and_devices():
    organizations = accounts.models.Organization.objects.filter(is_active = True)
    today_date = datetime.now() - timedelta(days = 1)
    for organization in organizations:
        users = accounts.models.User.objects.filter(org = organization.name)
        user_analytics = accounts.models.UserAnalytics(
            active_users = users.filter(is_active = True).count(),
            inactive_users = users.filter(is_active = False).count(),
            organization = organization,
            reported_date = today_date
        )
        user_analytics.save()

        devices = accounts.models.Device.objects.filter(org = organization, soft_delete = False)
        device_analytics = accounts.models.DeviceAnalytics(
            active_devices = devices.filter(is_active = True).count(),
            inactive_devices = devices.filter(is_active = False).count(),
            organization = organization,
            reported_date = today_date
        )
        device_analytics.save()


def send_mail_of_renewal():
    organizations = accounts.models.Organization.objects.filter(is_active = True)
    for organization in organizations:
        try:
            owner = accounts.models.User.objects.get(username = organization.owner.lower().strip())
            org_plan_qs = subscription.models.OrganizationPlan.objects.filter(organization = organization, auto_renewal = True, is_plan_active = True, subscription_plan__id__in = [2,3,4])
            try:
                if org_plan_qs.exists():
                    org_plan = org_plan_qs.first()
                    try:
                        expiry_in = (org_plan.expiry_date.date() - datetime.now().date()).days
                    except:
                        expiry_in = (org_plan.expiry_date.date() - timezone.now().date()).days
                    if expiry_in == 7:
                        try:
                            recipient_list = [owner.username]
                            message = get_template("accounts/subscription_renewal.html").render({
                                'name': owner.get_full_name(),
                                'date': org_plan.expiry_date.date()
                            })
                            subject = 'Upcoming renewal of your FDS subscription.'
                            send_info_email_task(recipients=recipient_list, subject=subject, message=message)
                            message = "Your plan will be renewed in 7 days."
                            user_id = owner.id
                            tag_name = "user_id"
                            heading = "Subscription Renewal"
                            notification = accounts.models.Notification.objects.create(
                                organization = organization,
                                type = 5,
                                heading = "Subscription Renewal",
                                message = "Your plan will be renewed in 7 days.",
                                plan = org_plan,
                                role = "owner",
                                affected_user = owner
                            )
                            data = NotificationSerializer(notification).data
                            SendNotification(message,user_id,tag_name, heading, data)
                        except Exception as e:
                            pass
            except Exception as e:
                pass
        except Exception as e:
            pass


def send_mail_of_expiration():
    organizations = accounts.models.Organization.objects.filter(is_active = True)
    for organization in organizations:
        try:
            owner = accounts.models.User.objects.get(username = organization.owner.lower().strip())
            org_plan_qs = subscription.models.OrganizationPlan.objects.filter(organization = organization, auto_renewal = False, is_plan_active = True, subscription_plan__id__in = [2,3,4])
            if org_plan_qs.exists():
                org_plan = org_plan_qs.first()
                try:
                    expiry_in = (org_plan.expiry_date.date() - datetime.now().date()).days
                except:
                    expiry_in = (org_plan.expiry_date.date() - timezone.now().date()).days
                if expiry_in == 7:
                    try:
                        recipient_list = [owner.username]
                        message = get_template("accounts/subscription_renewal.html").render({
                            'name': owner.get_full_name(),
                            'date': org_plan.expiry_date.date()
                        })
                        subject = 'Your plan will expire soon.'
                        send_info_email_task(recipients=recipient_list, subject=subject, message=message)
                        message = "Your plan will expire in 7 days."
                        user_id = owner.id
                        tag_name = "user_id"
                        heading = "Your plan will expire soon."

                        notification = accounts.models.Notification.objects.create(
                            organization = organization,
                            type = 5,
                            heading = "Data Privacy Protection",
                            message = "Your plan will expire in 7 days.",
                            plan = org_plan,
                            role = "owner",
                            affected_user = owner
                        )
                        data = NotificationSerializer(notification).data
                        SendNotification(message,user_id,tag_name, heading, data)

                    except Exception as e:
                        pass
        except Exception as e:
            pass


def expire_subscriptions():
    organizations = accounts.models.Organization.objects.filter(is_active = True)
    for organization in organizations:
        try:
            org_plan_qs = subscription.models.OrganizationPlan.objects.filter(organization = organization, is_plan_active = True, auto_renewal = False)
            if org_plan_qs.exists():
                org_plan = org_plan_qs.first()

                #getting plan which is expiring today
                if (org_plan.expiry_date.date() - datetime.now().date()).days <= 0:
                    org_plan.is_plan_active = False
                    org_plan.save()
                    organization.licence = 0
                    organization.save()

                    #getting devices registered under that organization
                    devices = accounts.models.Device.objects.filter(org = organization)
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
                    org_services = accounts.models.OrgnisationService.objects.filter(orginstion = organization)                    
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
                    locations = accounts.models.Location.objects.filter(organization = organization)
                    for location in locations:
                        location.is_active = False
                        location.save()

        except Exception as e:
            pass



def reactivate_organization(organization, org_plan):
    devices = accounts.models.Device.objects.filter(org = organization, soft_delete = False, is_subscribed = False)
    if devices.count() <= (org_plan.device_limit - org_plan.utilized_limit):

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
        org_plan.utilized_limit = len(devices)
        org_plan.save()
    else:
        org_plan.utilized_limit = 0
        org_plan.save()
    
    organization.licence = org_plan.device_limit
    organization.save()

    # getting organization services and related sub-services
    org_services = accounts.models.OrgnisationService.objects.filter(orginstion = organization) 
    if org_services.exists():
        for org_service in org_services:

            # reactivating the services and subservices
            org_service.Subscribed = True
            org_service.service_active = True
            org_service.expire_on = org_plan.expiry_date
            org_service.save()
            org_sub_services = org_service.orgnisationsubservice_set.all()
            for org_sub_service in org_sub_services:
                org_sub_service.is_active = True
                org_sub_service.save()
    
    # deactivating all the users except the owner                    
    org_users = organization.user.filter(is_owner = False)
    if org_users.exists():
        for user in org_users:
            user.is_active = True
            user.save()

    # deactivating locations
    locations = accounts.models.Location.objects.filter(organization = organization)
    if locations.exists():
        for location in locations:
            location.is_active = True
            location.save()



def pause_renewals():
    organizations = accounts.models.Organization.objects.filter(is_active = True)
    for organization in organizations:
        try:
            org_plan_qs = subscription.models.OrganizationPlan.objects.filter(organization = organization, is_plan_active = True, is_paused = False, auto_renewal = True)
            if org_plan_qs.exists():
                org_plan = org_plan_qs.first()

                #getting plans which are not renewed
                try:
                    if org_plan.expiry_date <= datetime.now():
                        org_plan.is_paused = True
                        org_plan.save()

                        #getting devices registered under that organization
                        devices = accounts.models.Device.objects.filter(org = organization, is_subscribed = True, soft_delete = False)
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
                            data = data
                            device.call_config_types = data
                            device.is_active = False # deactivating the device
                            device.is_online = False
                            device.save()
                except:
                    if org_plan.expiry_date <= timezone.now():
                        org_plan.is_paused = True
                        org_plan.save()

                        #getting devices registered under that organization
                        devices = accounts.models.Device.objects.filter(org = organization, is_subscribed = True, soft_delete = False)
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
                            data = data
                            device.call_config_types = data
                            device.is_active = False # deactivating the device
                            device.is_online = False
                            device.save()                    

        except Exception as e:
            pass
