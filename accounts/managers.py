# from django.db.models import QuerySet
from datetime import datetime

import lazy_import
from django.db.models import Manager
import pytz
utc = pytz.UTC

from accounts.exceptions import DeviceNotFound, LocationNotFound
from accounts.exceptions import QRCodeExpired


class DeviceManager(Manager):

    def device_by_org_location(self, org, location):
        try:
            return self.filter(org = org, location = location, soft_delete = False)
        except Exception as e:
            raise LocationNotFound()
        
    def device_by_qr_code(self, qr_code_token):
        try:
            device = self.get(qr_code_token=qr_code_token)
            diff = (datetime.now(utc) - device.qr_code_generated_on).total_seconds() / 60.0
            if int(diff) > 10:
                raise QRCodeExpired()
            return device
        except self.model.DoesNotExist as e:
            raise DeviceNotFound()

    def device_by_auth_token(self, authentication_token):
        try:
            return self.get(authentication_token=authentication_token, is_active=True)
        except:
            raise DeviceNotFound()

    def device_by_authorization_token(self, authorization_token): # duplicate of device_by_auth_token
        try:
            return self.get(authorization_token=authorization_token, is_active=True)
        except:
            raise DeviceNotFound()

    def device_by_payload(self, payload):

        try:
            return self.get(
                serial_number=payload.get("serial_number"),
                mac_address=payload.get("mac_address"),
                authorization_token=payload.get("authorization_token")                
            )
        except self.model.DoesNotExist as e:
            return None




class LocationManager(Manager):
    def location_by_org(self, user):
        Organization = lazy_import.lazy_class('accounts.models.Organization')
        orgs = Organization.objects.filter(user__in=[user], is_active=True)
        return self.filter(organization__in=orgs, is_active=True)

    def location_by_user(self, user):
        return self.filter(user__in = [user], is_active = True)

    def location_by_id(self, id):
        try:
            return self.get(id=id, is_active=True)
        except self.model.DoesNotExist as e:
            raise LocationNotFound()

    


class OrganizationManager(Manager):

    def orgs_by_user(self, user):
        return self.filter(user__in=[user], is_active=True)
