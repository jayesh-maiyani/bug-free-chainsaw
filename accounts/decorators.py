from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from accounts import exceptions


def check_qr_code_token(func):
    def inner(view, request, *args, **kwargs):
        if 'qr_code_token' not in request.data:
            raise exceptions.BadRequest(message="QR Code Token Does Not exist")
        return func(view, request, *args, **kwargs)
    return inner

def get_string_field(description, **kwargs):
    return openapi.Schema(
        type=openapi.TYPE_STRING,
        description=description,
        **kwargs
    )


def device_crud(method=None, **kwargs):
    if method == 'start':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'mac_address': get_string_field('mac address of device'),
                    'serial_number': get_string_field('serial number of device'),
                    'device_type': get_string_field('Type of Device', enum=[1, 2]),
                    'device_name': get_string_field('Device Name')
                },
                required=['mac_address', 'serial_number', 'device_type', 'device_name']
            ),
            responses={
                201: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'qr_code_token': get_string_field('QR Code')
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.InsufficientDataException.default_detail)
                    }
                )
            })

    if method == 'check':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'qr_code_token': get_string_field('qr code received from server')
                },
                required=['qr_code_token']
            ),
            responses={
                201: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'authorization_token': get_string_field('Authorization token'),
                        'authentication_token': get_string_field('Authentication Token'),
                        'public_key': get_string_field('RSA-512 Public Key Created by Server'),
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.InsufficientDataException.default_detail)
                    }
                ),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'exchange':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authentication_token': get_string_field("authentication_token for device"),
                    'payload': get_string_field('public key encrypted payload')
                },
                required=['authentication_token', 'payload']
            ),
            responses={
                201: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            description="request success"
                        ),
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="error message"
                        )
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field('not authenticated/ payload decryption')
                    }
                ),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })
    if method == 'reauth':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authorization_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="authorization_token for device"
                    ),
                    'payload': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="public key encrypted payload"
                    )
                },
                required=['authorization_token', 'payload']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'authentication_token': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Device authentication token"
                        )
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field('not authenticated/ payload decryption')
                    }
                ),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'details':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authentication_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="authentication_token of device"
                    ),
                    'payload': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="public key encrypted payload"
                    )
                },
                required=['authentication_token', 'payload']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'serial_number': get_string_field("Device Serial Number"),
                        'mac_address': get_string_field("Device Mac Address"),
                        'device_type': get_string_field("Device Type Number", enum=['1', '2']),
                        'device_name': get_string_field("Device Name"),
                        'services': get_string_field("Device Running Services"),
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field('not authenticated/ payload decryption')
                    }
                ),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'lastseen':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authentication_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="authentication_token for device"
                    )
                },
                required=['authentication_token']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'last_seen': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Device last seen"
                        )
                    }),
                400: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field(exceptions.BadRequest.default_detail)
                    }
                ),
                406: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field('not authenticated/ payload decryption')
                    }
                ),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'lastseen_update':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authentication_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="authentication_token for device"
                    )
                },
                required=['authentication_token']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            description="true if no error found"
                        ),
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Error Detail"
                        )
                    }),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'pushdata':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'authentication_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="authentication_token for device"
                    )
                },
                required=['authentication_token']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description="message from service"
                        )}),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })

    if method == 'activate':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'qr_code_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="qr_code_token of device"
                    ),
                    'location_id': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="location of device need to be added"
                    )
                },
                required=['qr_code_token', 'location_id']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="message from service"
                        ),
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='error Detail'
                        )
                    }),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })
    if method == 'deviceinfo':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'qr_code_token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="qr_code_token of device"
                    )
                },
                required=['qr_code_token', 'location_id']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'serial_number': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Device Serial Number"
                        ),
                        'mac_address': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Device Mac Address"
                        ),
                        'device_type': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description="Device Type Number",
                            enum=['1', '2']
                        ),
                        'device_name': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Device Name"
                        ),
                        'is_authenticated': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            description="Authentication flag",
                        )
                    }),
                404: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': get_string_field("Not Found")
                    }
                )
            })
    if method == 'post':
        return swagger_auto_schema(
            operation_summary=kwargs.get('summary', ''),
            operation_description=kwargs.get('description', ''),
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'username': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="User name"
                    ),
                    'password': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="Password"
                    )
                },

                required=['username', 'password']
            ),
            responses={
                200: openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="JWT access Token"
                        ),
                        'refresh': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="JWT refresh Token"
                        )
                    }),
            })
