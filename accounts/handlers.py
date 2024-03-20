import logging

from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler

logger = logging.getLogger(__file__)


def fusiontech_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if isinstance(exc, APIException):
        response.data = {'error': response.data['detail']}  # set the custom response data on response object
    return response
