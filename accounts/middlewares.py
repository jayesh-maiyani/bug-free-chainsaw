import ipaddress
import threading
from django.contrib.auth.middleware import get_user

import jwt
from django.http import JsonResponse
_thread_locals = threading.local()
from .models import AccessTokensBlackList, User

try:
    from ipware.ip2 import get_client_ip
except ImportError:
    from ipware.ip import get_client_ip

from django.conf import settings
from django.http import Http404
from django.utils.deprecation import MiddlewareMixin



# above here are ip middelware
import json
from logging import getLogger

from django.http import HttpResponseNotFound

logger = getLogger(__name__)

import threading

_thread_locals = threading.local()


def get_current_user():
    return getattr(get_current_request(), 'user', None)


def get_current_request():
    return getattr(_thread_locals, 'request', None)


def reset_current_request():
    setattr(_thread_locals, 'request', None)







class RequestMiddleware:
    """
        This Middleware classe is used to append the current
        requested user to response .so when ever we required
        the requested user we can get usig this Middleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _thread_locals.request = request
        response = self.get_response(request)
        reset_current_request()
        if isinstance(response, HttpResponseNotFound):
            response_data = {'detail': 'Not found.'}
            return HttpResponseNotFound(json.dumps(response_data), content_type="application/json")
        return response


def get_current_request():
    return getattr(_thread_locals, 'request', None)
def get_current_user():
    return getattr(get_current_request(), 'user', None)

class AccessMiddleWare:
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        if hasattr(request, "META"):
            auth_header =  request.META.get('HTTP_AUTHORIZATION', None)

            if auth_header is not None:
                token = auth_header.split(' ')[1] if 'Bearer' in auth_header else None
            
                if token is not None:
                        decoded_data = jwt.decode(token, None, False)
                        queryset = AccessTokensBlackList.objects.filter(jti = decoded_data["jti"])
                        if queryset.exists():
                            return JsonResponse({"Error": "Login Required!!"})
                        
        response = self.get_response(request)
        return response
                



# here is the middeleware

class SWAGGERIPRestrictorMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        self.get_response = get_response
        restrict_swagger = getattr(
            settings,
            'RESTRICT_SAWGGER',
            False
        )
        trust_private_ip = getattr(
            settings,
            'TRUST_PRIVATE_IP',
            False
        )
        self.trust_private_ip = self.parse_bool_envars(
            trust_private_ip
        )
        self.restrict_swagger = self.parse_bool_envars(
            restrict_swagger
        )
        allowed_swagger_ips = getattr(
            settings,
            'ALLOWED_SWAGGER_IPS',
            []
        )
        self.allowed_swagger_ips = self.parse_list_envars(
            allowed_swagger_ips
        )
        allowed_swagger_ip_ranges = getattr(
            settings,
            'ALLOWED_SWAGGER_IP_RANGES',
            []
        )
        self.allowed_swagger_ip_ranges = self.parse_list_envars(
            allowed_swagger_ip_ranges
        )
        restricted_app_names = getattr(
            settings,
            'RESTRICTED_SWAGGER_NAMES',
            []
        )
        self.restricted_app_names = self.parse_list_envars(
            restricted_app_names
        )
        self.restricted_app_names.append('swagger')
    
    @staticmethod
    def parse_bool_envars(value):
        if value in ('true', 'True', '1', 1):
            return True
        return False

    @staticmethod
    def parse_list_envars(value):
        if type(value) == list:
            return value
        else:
            return value.split(',')

    def is_blocked(self, ip):
        """Determine if an IP address should be considered blocked."""
        blocked = True

        if self.trust_private_ip:
            if ipaddress.ip_address(ip).is_private:
                blocked = False

        if ip in self.allowed_swagger_ips:
            blocked = False

        for allowed_range in self.allowed_swagger_ip_ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(allowed_range):
                blocked = False

        return blocked

    def get_ip(self, request):
        client_ip, is_routable = get_client_ip(request)
        assert client_ip, 'IP not found'
        if not self.trust_private_ip:
            assert is_routable, 'IP is private'
        return client_ip

    def process_view(self, request, view_func, view_args, view_kwargs):
        app_name = request.resolver_match.url_name
        is_restricted_app = app_name in self.restricted_app_names
        if self.restrict_swagger and is_restricted_app:
            ip = self.get_ip(request)
            if self.is_blocked(ip):
                raise Http404()

        return None




