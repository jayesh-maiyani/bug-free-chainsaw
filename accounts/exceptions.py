from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException


class BadRequest(APIException):
    def __init__(self, **kwargs):
        if kwargs.get('message'):
            self.default_detail = kwargs.get('message')
        super(BadRequest, self).__init__()

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Bad Request')
    default_code = '400'


class InsufficientDataException(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = _('Information Not Sufficient.')
    default_code = '406'


class DeviceNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("Device Not Found Or Expired QR Code.")
    default_code = 404


class SubServiceNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("SubService Not Found.")
    default_code = 404


class SubServiceCodeNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("SubServiceCode Not Found Or C# code not added for Service.")
    default_code = 404


class LocationNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("Location Not Found.")
    default_code = 404


class QRCodeExpired(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = _("QR Code Expired or Invalid.")
    default_code = 406


class UserNotMapedWithOrg(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = _("User is not mapped with any organization, please contact admin.")
    default_code = 406


class PayloadDecryptError(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = _("Not authenticated/Payload decryption error")
    default_code = 406

class UnAuthorizedException(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("You are unauthorized.")
    default_code = 401
