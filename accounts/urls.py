from django.urls import path, include

from .views import *

from rest_framework.routers import DefaultRouter

router = DefaultRouter()

router.register('client/details', ClientDashboard, basename="clientdevice") #Client Dashboard
router.register('client/user', ClientUserView, basename="clientuser") #Client User

#MJ Users / Kristin Watson in figma for client app
router.register('client/users-location', ClientUserLocation, basename = "client-users-location")# list, assign and delete locations.

#MJ the separate Location section
router.register('client/locations', ClientLocation, basename = "locations")
# router.register('client/services', MasterServiceView, basename = "services")

router.register('user/organization', OrganizationView, basename = 'organization')
router.register('user/profile', UserProfileView , basename = 'userprofile')


router.register('device', DeviceView, basename='device')
router.register('user/device', DeviceAuthenticationView, basename = 'user-device')

router.register('master-registration', MasterRegistrationAPIView, basename = "master-registration")

router.register('client/device/services', ClientDeviceServices, basename = 'device-services')
router.register('device/sub-services', ClientDeviceSubServices, basename = "device-sub-services")
router.register('devices/whitelisted-domains', ClientDeviceWhitelistedDomain, basename = 'device-whitelisted-domains')

router.register('organization/whitelisted-domains', ClientOrgWhitelistedDomain, basename = 'org-whitelisted-domains')

router.register('client/services', ClientOrganizationServices, basename = 'services')
router.register('client/subservice', ClientOrganizationSubService, basename = 'subservices')

router.register('resetpassword', ResetPassword , basename='forgotpassword') #Login
router.register("invite", SendInvite, basename = "user-invite")

# Device Online
router.register('online/device', DeviceOnline, basename='device_online')
# device log
router.register('log/device', DeviceLogView, basename='device_log')
router.register('log/sub-service', OrgSubServicesLogView, basename = 'sub-service-logs')

router.register('notification', NotificationAPIView, basename = 'notifications')

# from .socket_app import socketio_connect, socketio_disconnect, socketio_receive


urlpatterns = [
    path('api/', include(router.urls)),
    path('api/sendotp/', SendOtp.as_view(),name='sendotp'), #Login
    path('api/change-password/', ChangePasswordView.as_view(),name='change-password'), #Login
    path('api/logs/client/<int:pk>/', ClientLogListView.as_view(), name = "client-log"),
    path('api/client/user-devices/<int:pk>/', ClientDeviceListView.as_view(), name = 'device-services'),
    path('api/client/user-analytics/', UserAnalyticsYearlyReport.as_view(), name = 'user-analytics'),
    path('api/client/device-analytics/', DeviceAnalyticsYearlyReport.as_view(), name = 'device-analytics'),
    path('api/contact-us/', ContactUs.as_view(), name = 'contact-us'),
    path('api/location/', CountryDataAPIView.as_view(), name='location_data'),
    path('api/device-logs/', DeviceSpecificLog.as_view(), name = "device-log"),
    path('api/has-subscription/', HasSubscription.as_view(), name = "has-subscription"),
    # path('api/logs/device/<int:pk>/', DeviceLogListView.as_view(), name = "device-log"),
    # path('api/logs/subservice/<int:pk>/', SubServiceLogListView.as_view(), name = "subservice-log")
]

# urlpatterns += [
#     path('socket.io/', socketio_receive),
#     path('socket.io/connect/', socketio_connect),
#     path('socket.io/disconnect/', socketio_disconnect),
# ]

# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
# else:
#     urlpatterns += staticfiles_urlpatterns()
