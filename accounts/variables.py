class DictHolder(dict):
    """
    A simple model that wraps mongodb document
    """
    __getattr__ = dict.get
    __delattr__ = dict.__delitem__
    __setattr__ = dict.__setitem__


DEVICE_DECORATORS = DictHolder({
    'start': {
        "method": 'start',
        "summary": "Device Registration",
        "description": "### Registering Device with Client Organization",
    },
    'exchange': {
        "method": 'exchange',
        "summary": "Device Key Exchange",
        "description": "### Public Private keyExchange",
    },
    'reauth': {
        "method": 'reauth',
        "summary": "Device Re-Authentication",
        "description": "### Device authentication Service.",
    },
    'details': {
        "method": 'details',
        "summary": "Retrieve Device Information",
        "description": "### This service will retrieve device info with all running services",
    },
    "lastseen": {
        "method": 'lastseen',
        "summary": "Retrive Device last seen",
        "description": "### This service will retrieve device last seen",
    },
    "lastseen_update": {
        "method": 'lastseen_update',
        "summary": "Update Device last seen ",
        "description": "### This service will update device last seen",
    },
    "pushdata": {
        "method": 'pushdata',
        "summary": "Set Service Count",
        "description": "### Set Service Count",
    },
    "check": {
        "method": 'check',
        "summary": "Device Checking",
        "description": "### Authentication Device with QR Code",
    },
    "post": {
        "method": 'post',
        "summary": "User Login",
        "description": "### Authenticate and provice JWT access token and refresh token",
    },
    "activate": {
        "method": 'activate',
        "summary": "Device Activate",
        "description": "### Activating Device by Registered User",
    },
    "deviceinfo": {
        "method": 'deviceinfo',
        "summary": "Device Information",
        "description": "### Retrieve Device Information",
    }
})
