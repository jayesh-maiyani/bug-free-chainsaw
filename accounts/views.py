import asyncio
from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.contrib.auth.models import Permission
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.utils import timezone
from django.template.loader import get_template
from captcha.fields import ReCaptchaField


from rest_framework import status, mixins, viewsets, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import action


from .tasks import send_info_email_task, send_otp_email_task, otp_mail_connection

from .pagination import StandardResultsSetPagination
from .helpers import bytest_to_kb, can_avail_trial, client_log, has_active_subscription, has_active_trial, has_active_plan, is_current_plan_paused
from .variables import DEVICE_DECORATORS
from .decorators import device_crud
from .models import *
from .serializers import *  
from .permissions import FusionClient, MasterRegisterer
from .exceptions import DeviceNotFound, LocationNotFound, QRCodeExpired, UnAuthorizedException
from .utils import JSONEncoder

from datetime import datetime, timedelta
import math, json, random, pytz, jwt, csv, re
from .socket_app import get_socketio_app



###################################################################
sio = get_socketio_app()

async def send_socketio_event(data, room):
    await sio.emit('user_permission', data, room)

async def send_socketio_plan_limits(plan_data, room):
    await sio.emit('plan_limits', plan_data, room)


# import pandas as pd

utc = pytz.UTC

roles_map = {
    'client_user': 'client user',
    'client_admin': 'client administrator',
    'client_reader': 'client reader'
}


service_file_type_map = {
    "Web Tracking Protecting": "files",
    "Web Session Protection": "cookies",
    "Web Cache Protection": "KBs",
    "DNS Cache Protection": "files",
    "Windows Registry Protection": "files",
    "Free Storage Protection": "files",
    "Trash Data Protection": "files"
}

######################################### Cron Converter ########################################################################################

def cron_converter(data):
    try:
        cron_data=data
        if "every_year_days" in cron_data:
            cron_time=" "
            if cron_data["every_year_days"]["formate"]=="am":
                if cron_data["every_year_days"]["hours"]==12:
                   hour=int(cron_data["every_year_days"]["hours"])-int(12)
                else:
                    hour=int(cron_data["every_year_days"]["hours"])
                cron_time=cron_time+f'{cron_data["every_year_days"]["minutes"]} '+f'{hour} '
            else:
                if cron_data["every_year_days"]["hours"]==12:
                    hour=int(cron_data["every_year_days"]["hours"])
                else:
                    hour=int(cron_data["every_year_days"]["hours"])+int(12)
                cron_time=cron_time+f'{cron_data["every_year_days"]["minutes"]} '+f'{hour} '
            if "days" in  cron_data["every_year_days"]:
                if cron_data["every_year_days"]["days"]:
                    days=''
                    day=cron_data["every_year_days"]["days"]
                    for i  in range(len(day)):
                        if i==len(day)-1:
                            days=days+f'{day[i]} '
                        else:
                            days=days+f'{day[i]},'
                    cron_time=cron_time+days
            else:
                cron_time=cron_time+"* "
            if "month" in cron_data["every_year_days"]:
                if cron_data["every_year_days"]["month"]:
                    months=''
                    month=cron_data["every_year_days"]["month"]
                    for i  in range(len(month)):
                        if i==len(month)-1:
                            months=months+f'{month[i]} '
                        else:
                            months=months+f'{month[i]},'
                    cron_time=cron_time+months
            else:
                cron_time=cron_time+"* "
            if "week" in cron_data["every_year_days"]:
                if cron_data["every_year_days"]["week"]:
                    weeks=''
                    week=cron_data["every_year_days"]["week"]
                    for i  in range(len(week)):
                        if i==len(week)-1:
                            weeks=weeks+f'{week[i]} '
                        else:
                            weeks=weeks+f'{week[i]},'
                    cron_time=cron_time+weeks
            else:
                cron_time=cron_time+"*"
            return cron_time
        return (False)
    except Exception as E:
        return (False)


################################### CSV validation ######################################################################


vulnerable_pattern = r"=|\*|\"|'|<|>|\\|\/|\b(OR|AND)\b"

def check_for_vulnerabilities(csv_row):
    for value in csv_row:
        if re.search(vulnerable_pattern, value):
            return -1
        if value[0] == "@":
            return -1
        
    return None


def check_location_format(locations):
    if locations[0] != '[' or locations[-1] != ']':
        return False
    return True

def check_locations(user_locs, locations):    
    locations = locations.replace('[', '').replace(']', '').split('&')
    if bool(locations):
        for loc in locations:
            l = loc.strip()
            if not user_locs.filter(location_name__iexact = l).exists():
                return l
    else:
        return None    
    return None
        
def check_roles(user_role, role):
    given_role = role.strip().lower()
    if user_role:
        status = False
        valid_roles = ['client administrator', 'client reader', 'client user']
        for r in valid_roles:
            if given_role == r:
                status = True

        if status == False:
            return -1
        
    else:
        status = False
        valid_roles = ['client reader', 'client user']
        for r in valid_roles:
            if given_role == r:
                status = True

        if status == False:
            return -2
        
    return None


###################################################################################################################################################


class HasSubscription(APIView):

    def get(self, request):
        org = Organization.objects.get(name = request.user.org)
        has_subscription = has_active_subscription(org) or has_active_trial(org)
        return Response({'has_subscription':has_subscription})


##################### Dashboard ###################################################################################################

class ClientDashboard(viewsets.ModelViewSet):
    """
    
    """
    permission_classes = IsAuthenticated, FusionClient
    serializer_class = UserDashboardSerializer

    #MJ returns whole data on dashboard except analytics
    def list(self, request, pk = None):
        try: 
            org = Organization.objects.get(user = request.user)
            users = User.objects.filter(org = org.name).order_by('-id')
            locations = Location.objects.filter(organization = org).order_by('-id')
            device = Device.objects.filter(org = org, soft_delete = False).order_by('-id')
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        queryset = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        if queryset.exists():
            plan = queryset.first()
            plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
            plan.save()

        statistics = {
            "no_of_location":locations.count(),
            "no_of_user":users.count(),
            "no_of_device":device.count(),
        }

        
        is_mobile = request.META.get('HTTP_X_IS_MOBILE', None) == 'True'
        
        org_plan_qs = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        
        device_limit = 0
        utilized_limit = 0
        if org_plan_qs.exists():
            plan = org_plan_qs.first()
            device_limit = plan.device_limit
            utilized_limit = plan.utilized_limit

        if not is_mobile:
            try:
                device_type_counts = dict()
                device_type_counts["limit"] = device_limit
                device_type_counts["total_registered"] = utilized_limit
                device_type_counts["windows"] = device.filter(device_type = "1").count()
                device_type_counts["mac"] = device.filter(device_type = "2").count()
                device_type_counts["android"] = device.filter(device_type = "3").count()
                device_type_counts["ios"] = device.filter(device_type = "4").count()
                
                serializer = self.get_serializer(users, many = True)
                userdata = serializer.data
                device_serializer = DeviceDashboardSerializer(device, many = True)

                context = {
                    "organization_name":org.name,
                    "addresh": f"{org.city}, {org.country}",
                    "statistics": statistics,
                    "user_data": userdata,
                    "device_data": device_serializer.data,
                    "device_counts": device_type_counts,
                }
                return Response(context, status = status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
        else:
            devices = Device.objects.filter(org = org, soft_delete = False).order_by('-id')
            try:
                if len(users) > 4:
                    users = users[0:3]
                if len(devices) > 4:
                    devices = devices[0:3]
                serializer = self.get_serializer(users, many = True)
                userdata = serializer.data
                device_serializer = ClientDeviceSerializer(devices, many = True)
                context = {
                    "organization_name":org.name,
                    "organization_type":org.organisation_type,
                    "statistics": statistics,
                    "user_data": userdata,
                    "device_data": device_serializer.data,
                    "no_of_device":utilized_limit,
                    "device_limit": device_limit,
                    'active_devices': device.filter(is_active = True).count(),
                    'inactive_devices': device.filter(is_active = False).count(),
                    'notification_counts':10,
                }
                return Response(context, status = status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"error": str(e)})
                

    
    # returns devices at "pk = id" location under the same organization
    def retrieve(self,request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        organization = Organization.objects.get(user = request.user)
        
        location = Location.objects.filter(organization = organization, id = pk)
        if location.exists():
            device = Device.objects.filter(location = location[0], soft_delete = False)
            serializer = LocationDevicesSerializer(device, many = True)
            return Response(serializer.data, status = status.HTTP_200_OK)
        return Response({"error":"Access unauthorized."}, )
    
    
    @action(detail = False, methods = ['GET'])
    def get_analytics(self, request):
        users = dict()
        
        users['months'] = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        users["active"] = [32, 44, 55, 57, 56, 61, 58, 63, 60, 66, 65, 72]
        users["inactive"] = [65, 76, 85, 101, 98, 87, 105, 91, 114, 94, 96, 90]

        devices = dict()
        devices['months'] = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        devices["active"] = [32, 44, 55, 57, 56, 61, 58, 63, 60, 66, 65, 72]
        devices["inactive"] = [65, 76, 85, 101, 98, 87, 105, 91, 114, 94, 96, 90]

        analytics = {
            'user' : users,
            'device' : devices
        }

        return Response({"analytics":analytics}, status = status.HTTP_200_OK)
    

    def update(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass


############################### Users #########################################################################################

class ClientUserView(viewsets.ModelViewSet):
    permission_classes = IsAuthenticated, FusionClient
    # parser_classes = [MultiPartParser]


    def get_serializer_class(self):
        if self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
            self.serializer_class = UserDashboardSerializer
        else:
            self.serializer_class = ClientUserSerializer
        return self.serializer_class


    def get_queryset(self):
        
        self.queryset = User.objects.filter(org = self.request.user.org)
        
        #filters --> will only execute if there are query parameters in the request
        if bool(self.request.query_params):
            qs = self.queryset
            query = self.request.query_params

            #role filter
            if "role" in query:
                roles = query.getlist('role')
                permissions = {
                    "admin":'client_admin',
                    "user":'client_user',
                    "reader":'client_reader'
                }
                qs = qs.filter(Q(user_permissions__codename__in=[permissions[role] for role in roles]))
                

            #activity filter
            if "active" in query:
                if query['active'] == 'true':
                    qs = qs.filter(Q(is_active = True))
                else:
                    qs = qs.filter(Q(is_active = False))


            #location filter
            if "location" in query:
                locations = query.getlist('location') # returns list of 'id' strings
                org = Organization.objects.get(name = self.request.user.org)
                locs = Location.objects.filter(organization = org, id__in = [int(i) for i in locations])
                users = set()
                for i in range(len(locs)):
                    users = users.union(set([user.id for user in locs[i].user.all()]))
                
                qs = qs.filter(id__in = users)
                

            #search filter
            if 'search' in query:
                
                qs = qs.filter(
                    Q(first_name__istartswith = query['search']) | 
                    Q(last_name__istartswith = query['search'])
                )
                
            return qs

        return self.queryset


    def list(self, request): 
        try:
            queryset = User.objects.filter(org = self.request.user.org)
            result = self.get_queryset().order_by("id")
                
            paginator = StandardResultsSetPagination()

            page = paginator.paginate_queryset(result, request) 
            if page is not None:
                serializer = self.get_serializer(page, many = True)
                return paginator.get_paginated_response(serializer.data, total_counts = queryset.count() - 1)

            serializer = self.get_serializer(result, many = True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({"error": UnAuthorizedException}, status = status.HTTP_403_FORBIDDEN)


    @action(detail = False, methods = ['GET'], url_path = "all-users")
    def all_users(self, request):
        try:
            users = self.get_queryset().exclude(is_owner = True)
            
            if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                if users.exists():
                    serializer = self.get_serializer(users, many = True)
                    return Response({'result':serializer.data})
                else:
                    return Response({'result':[]})
            else:
                if users.exists():
                    serializer = UserListSerializer(users, many = True, context = {'request':request})
                    return Response({'data':serializer.data})
                else:
                    return Response({'data':[]})
            
        except:
            return Response({'error':'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

    #MJ user profile
    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            userid = get_user_model().objects.get(id = pk)
        except:
            return Response({'error':'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.org == userid.org:
            serializer = ClientUserDetailSerializer(userid)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    # download csv format for user detail entries to follow
    @action(methods=["GET"], detail = False, url_path = "csv-format")
    def download_csv_format(self, request):
        if request.user.has_perm("accounts.client_admin"):

            csv_path = os.path.join(settings.STATIC_ROOT, 'csv/users.csv')
            # create a response object with CSV content-type
            response = HttpResponse(content_type='text/csv')
            # set the content-disposition header to force a download
            response['Content-Disposition'] = 'attachment; filename="users.csv"'
            # read the CSV file and write it to the response
            with open(csv_path, 'r') as csv_file:
                response.write(csv_file.read())
            return response
            
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    # create organization users in bulk by just uploading a csv in format provided by above api.
    @action(methods=['POST'], detail = False, url_path="bulk-create")
    def create_bulk_users(self, request):
        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_plan(org):
            return Response({'error':'Please consider subscribing to one of our plans.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            org = Organization.objects.get(user = request.user)

            try: 
                org = Organization.objects.get(
                    name = request.user.org
                )
                csv_file = request.data['file']
                decoded_file = csv_file.read().decode('utf-8')
                csv_reader = csv.DictReader(decoded_file.splitlines())
                created_users = 0
                user_locs = Location.objects.location_by_user(request.user)
                
                rc = 0

                for row in csv_reader:
                    rc += 1
                    
                    flag = check_for_vulnerabilities(row)
                    if flag is not None:
                        return Response({
                            "error":f"Values can not contain any of [/, \", <, >, \\, OR, AND, ', *, =, ] and must not start with '@'. Error at row number {rc}."
                            }, status = status.HTTP_400_BAD_REQUEST
                        )

                    loc_field = row["locations"].strip()
                    if len(loc_field) > 2:
                        if check_location_format(loc_field):
                            flag = check_locations(user_locs, loc_field)
                            if flag is not None:
                                return Response({
                                    "error":f"Location {flag} is not available. Error at row number {rc}."
                                    }, status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response({"error":f"Please enter locations in this format: '[san jose & infinity tower]'. Error at row number {rc}."}, status = status.HTTP_400_BAD_REQUEST)
                    
                    flag = check_roles(user_role = request.user.is_owner, role = row['role'])
                    if flag is not None:
                        if flag == -1:
                            Response({
                                    "error":f"Role can only be one of Client Administrator, Client Reader or Client User. Error at row number {rc}."
                                }, status=status.HTTP_400_BAD_REQUEST
                            )
                        if flag == -2:
                            return Response({
                                "error":f"Role can only be Client Reader or Client User. Error at row number {rc}"
                                }, status=status.HTTP_400_BAD_REQUEST
                            )

                    user_qs = User.objects.filter(username = row['email'].lower())
                    if user_qs.exists():
                        existing_user = user_qs.first()
                        if existing_user.org == request.user.org:
                            return Response({"error":f"User at row {rc} is already registered."}, status=status.HTTP_400_BAD_REQUEST)
                        else:
                            return Response({"error":f"User at row {rc} is registered with different organization."}, status=status.HTTP_400_BAD_REQUEST)

                rc = 0 # row count flag

                csv_reader = csv.DictReader(decoded_file.splitlines())
                for row in csv_reader:
                    locations = row.pop('locations')
                    role = str(row.pop('role')).lower()
                    row['org'] = request.user.org
                    row['email'] = row['email'].lower()
                    row['username'] = row['email']
                    row['addresh'] = row['address']
                    if row['phone_code'][0] != "+":
                        row['phone_code'] = "+" + row['phone_code']

                    user = BulkUserSerializer(data = row)
                    if user.is_valid():
                        instance = user.save()
                        created_users += 1
                        rc += 1
                        instance.created_by = request.user
                        flink = uuid.uuid4()
                        instance.password = uuid.uuid4()
                        instance.forgotlink = flink
                        instance.forgotlinktime = datetime.now() + timedelta(minutes = 15)
                        instance.save()


                        recipient_list = [instance.username]
                        message = get_template("accounts/new_user.html").render({
                            'user_name': instance.get_full_name(),
                            'link': f'{settings.CLIENT_FRONTEND_URL}/resetpassword/{flink}/'
                        })
                        subject = 'Welcome to Fusion Data Secure.'
                        send_info_email_task(recipients=recipient_list, subject=subject, message=message)



                        roles = {
                            "client administrator":'client_admin',
                            "client user":'client_user',
                            "client reader":'client_reader'
                        }
                    
                        permissions = Permission.objects.filter(
                            codename = roles[role]
                        )
                        if permissions.exists():
                            permission = permissions[0]
                        else:
                            permission = Permission.objects.filter(
                                codename = "client_reader"
                            )[0]
                        instance.user_permissions.add(permission)

                        instance.save() 

                        org.user.add(instance)
                        

                        if len(locations) != 0:
                            locations = locations.replace('[', '').replace(']', '').split('&')
                            for loc_name in locations:
                                try:
                                    location = Location.objects.filter(organization = org, location_name__iexact = loc_name.strip())
                                    if location.exists():
                                        location = location[0]
                                        location.user.add(instance)

                                except Location.DoesNotExist as e:
                                    return Response({"error": str(e)}, status = 400)
                        client_log(request, org, "Added a new User: _user_", user = instance)
                            

                    else:
                        errors = user.errors
                        try:
                            for _, messages in errors.items():
                                for message in messages:
                                    return Response({"error":message.replace("field",_)}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

                
                if created_users > 0:
                    return Response({"message":f"{created_users} {'users' if created_users > 1 else 'user'} created successfully." }, status = status.HTTP_200_OK)
                else:
                    return Response({"error":"No new users were created, please check the csv data."}, status = status.HTTP_400_BAD_REQUEST)
            
            except Exception as e:
                return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)

        else:
            return Response({"error":"You are unauthorized."}, status = status.HTTP_400_BAD_REQUEST)

    #MJ for creating a client user
    def create(self, request):

        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)

        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm('accounts.client_admin'):
            try:
                request.data['username'] = request.data["username"].strip().lower()

                flag = check_roles(user_role = request.user.is_owner, role = roles_map[request.data['role']])
                if flag is not None:
                    if flag == -1:
                        Response({
                                "error":f"Role can only be one of Client Administrator, Client Reader or Client User."
                            }, status=status.HTTP_400_BAD_REQUEST
                        )
                    if flag == -2:
                        return Response({
                            "error":f"Role can only be Client Reader or Client User."
                            }, status=status.HTTP_400_BAD_REQUEST
                        )

                username = request.data['username']
                if not User.objects.filter(username = username).exists():
                    request.data['email'] = username
                    organization = request.user.org
                    request.data['org'] = organization
                    serializer = UserSerializer(data = request.data)
                    
                    if serializer.is_valid():
                        instance = serializer.save()
                        instance.created_by = request.user
                        flink = uuid.uuid4()
                        instance.password = uuid.uuid4()
                        instance.forgotlink = flink
                        instance.forgotlinktime = datetime.now() + timedelta(minutes = 15)
                        instance.save()
                        locations = request.data["locations"]
                        
                        recipient_list = [instance.username]

                        message = get_template("accounts/new_user.html").render({
                            'user_name': instance.get_full_name(),
                            'link': f'{settings.CLIENT_FRONTEND_URL}/resetpassword/{flink}/'
                        })


                        subject = 'Welcome to Fusion Data Secure.'
                        send_info_email_task(recipients=recipient_list, subject=subject , message=message)

                        #MJ assgning role 
                        role = request.data['role']
                        permissions = Permission.objects.filter(
                            codename = role
                        )
                        if permissions.exists():
                            permission = permissions[0]
                        else:
                            permission = Permission.objects.filter(
                            codename = "client_reader"
                        )[0]
                        
                        instance.user_permissions.add(permission)
                        instance.save()
                        org = Organization.objects.get(
                            name = organization
                        )
                        
                        org.user.add(instance)

                        #MJclientlog
                        

                        if bool(locations):
                            for location in locations:
                                loc = Location.objects.get(
                                    organization = org, 
                                    id = location
                                )
                                loc.user.add(instance)

                        client_log(request, org, "Added a new User: _user_", user = instance)
                        return Response(
                            {"message": "User created successfully"}, 
                            status=status.HTTP_200_OK
                        )
                    
                    else:
                        errors = serializer.errors
                        try:
                            for _, messages in errors.items():
                                for message in messages:
                                    return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
                
                return Response({"error" : "User already exists."}, status = status.HTTP_400_BAD_REQUEST) 
            except Exception as e:
                return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        
        return Response({"error": "You are unauthorized."}, status = status.HTTP_400_BAD_REQUEST)

        
    #mj delete a client user by using the id field
    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)

        if request.user.is_owner and pk != request.user.id:
            try:
                userid = get_user_model().objects.get(id = pk)
                if request.user.org == userid.org:

                    #MJclientlog
                    client_log(request, org, f"Removed {userid.get_full_name()} from Organization.", user = userid)

                    userid.delete()
                    return Response({"message":"User deleted successfully."},  status = status.HTTP_200_OK)
            except:
                return Response({"error":"This user is not mapped to your organization"}, status = status.HTTP_400_BAD_REQUEST)
            
        return Response({"error":"You are unauthorized."}, status = status.HTTP_400_BAD_REQUEST)
        
    
    @action(methods=['DELETE'], detail = False, url_path = "multiple-delete")
    def multiple_delete(self, request):

        org = Organization.objects.get(user = request.user)

        if request.user.is_owner:
            try:
                delete_ids = request.data["ids"]
                print(delete_ids)
            except:
                return Response({'error':'Provide "ids" of the users to be deleted.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if request.user.id in delete_ids:
                delete_ids.remove(request.user.id)

            delete_users = User.objects.filter(id__in = delete_ids, org = request.user.org)
            print(delete_users)
            if delete_users.exists():
                delete_users.delete()
            else:
                return Response({'error':'Users do not exist.'}, status=status.HTTP_400_BAD_REQUEST)
            client_log(request, org, f"Deleted {len(delete_ids)} {'user' if len(delete_ids) == 1 else 'users'} from Organization.")
            return Response({'message':f"{'User' if len(delete_ids) == 1 else 'Users'} deleted successfully."}, status=status.HTTP_200_OK)

        else:
            return Response({"error": UnAuthorizedException}, status=status.HTTP_403_FORBIDDEN)


    @action(methods=['PUT'], detail = False, url_path = 'multiple-loc-assign')
    def assign_multiple_location(self, request):

        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if request.user.has_perm("accounts.client_admin"):
            user_ids = request.data["user_ids"]
            location_ids = request.data["location_ids"]
            
            users = User.objects.filter(id__in = user_ids, org = request.user.org)
            if len(user_ids) != users.count() or len(user_ids) == 0:
                return Response({'error':'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            
            loc_qs = Location.objects.filter(id__in = location_ids, organization = org)
            if len(location_ids) != loc_qs.count() or len(location_ids) == 0:
                return Response({'error':'Location does not exist'}, status=status.HTTP_400_BAD_REQUEST)            
            
            for user in users:
                for location in loc_qs:
                    if user in location.user.all():
                        return Response({'error':'Location is already assigned.'}, status=status.HTTP_400_BAD_REQUEST)
                    
            for id in location_ids:
                loc = Location.objects.get(id = id)
                try:
                    client_log(request, org, f"Assigned Location {loc.location_name} to {len(user_ids)} users.")
                    
                    tag_name="user_id"
                    heading='New location has been assigned'
                    for user in users:
                        if user not in loc.user.filter(is_active = True):
                            loc.user.add(user)
                            message=f'{request.user.get_full_name()} has assigned the location {loc.location_name} to {user.get_full_name()}.'
                            notification = Notification.objects.create(
                                organization = org,
                                type = 2,
                                heading = heading,
                                message = message,
                                location = loc,
                                actor_user = request.user,
                                affected_user = user,
                                role = "admin"
                            )
                            data = NotificationSerializer(notification).data
                            if user != request.user:
                                SendNotification(message, user.id, tag_name, heading, data)

                except Exception as e:
                    return Response({"error":"User is already assigned to that location"}, status = status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(users, many = True)
            return Response({'message':"Locations assigned successfully.", 'data':serializer.data}, status = status.HTTP_200_OK)
        return Response({"error": UnAuthorizedException}, status = status.HTTP_403_FORBIDDEN)
    

    @action(methods=['PUT'], detail = False, url_path = 'update-multiple-activity')
    def update_multiple_activity(self, request):
        try:
            
            org = Organization.objects.get(user = request.user)
            if not has_active_plan(org):
                return Response({'error':'Please consider subscribing to one of our plans.'}, status = status.HTTP_400_BAD_REQUEST)
            if request.user.is_owner:

                user_ids = request.data["ids"]
                for id in user_ids:
                    try:
                        if not id.isnumeric():
                            return Response({'error':'ids must contain valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        if not isinstance(id, int):
                            return Response({'error':'ids must be valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                
                if not isinstance(request.data['is_active'], bool):
                    return Response({'error':'is_active must be a valid boolean value.'}, status=status.HTTP_400_BAD_REQUEST)
                
                if request.user.id in user_ids:
                    user_ids.remove(request.user.id)
                activity_status = request.data['is_active']
                new_status = "activated" if activity_status else "deactivated"
                
                users = User.objects.filter(id__in = user_ids)
                if users.count() != len(user_ids):
                    return Response({'error':'User does not exist.'}, status = status.HTTP_400_BAD_REQUEST)
                
                users = users.exclude(is_active = activity_status)
                data = []
                if users.exists():
                    users.update(is_active = activity_status)
                client_log(request, org, f"{new_status} {len(user_ids)} users.")
                users = User.objects.filter(id__in = user_ids)
                data = self.get_serializer(users, many = True).data
                return Response({'message':f"Users {new_status} successfully.", 'data': data}, status = status.HTTP_200_OK)
        except Exception as e:
            return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
        return Response({"error": UnAuthorizedException}, status=status.HTTP_403_FORBIDDEN)
    
    def update(self, request, pk = id): #Edit User 
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.has_perm('accounts.client_admin'):
            
            org = Organization.objects.get(user = request.user)
                
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)


            if "is_active" in request.data and not request.user.is_owner:
                request.data.pop('is_active')
                # return Response({"error":"Only owner can perform activate/deactivate action."}, status=status.HTTP_403_FORBIDDEN)

            if request.data is None or len(request.data) == 0:
                return Response({'error':'Please pass a valid payload.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if request.user.id == pk:
                return Response(
                    {"error": "You are updating your 'Own' account."}, 
                    status = status.HTTP_400_BAD_REQUEST
                )
            
            if "username" in request.data or "email" in request.data:
                return Response({"error": "You can not update your username"}, status = status.HTTP_400_BAD_REQUEST)
            
            org = Organization.objects.get(name = request.user.org)
            try:
                user = User.objects.get(id = pk)
            except:
                return Response({"error":"User Does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.has_perm("accounts.client_admin") and not request.user.is_owner:
                return Response(
                    {"error":"You can not update other admin's profile."}, 
                    status = status.HTTP_403_FORBIDDEN
                )


            #MJ assigning or removing locations
            if 'locations' in request.data:
                existing_locations = [location.id for location in Location.objects.filter(user__in=[user])]
                new_locations = request.data['locations']
                for id in new_locations:
                    try:
                        if not id.isnumeric():
                            return Response({'error':'locations must contain valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        if not isinstance(id, int):
                            return Response({'error':'locations must be valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                        
                add = set(new_locations) - set(existing_locations)
                remove = set(existing_locations) - set(new_locations)

                for location in add:
                    try:
                        loc = Location.objects.get(
                            id = location, is_active = True
                        )
                    except:
                        return Response({'error':"You can not assign an inactive location."}, status = status.HTTP_400_BAD_REQUEST)
                    
                    loc.user.add(user)
                    client_log(request, org, f"Assigned Location {loc.location_name} to _user_.", user = user)
                    message = f'{request.user.get_full_name()} has assigned you the location {loc.location_name}.'
                    tag_name = "user_id"
                    heading = 'New location has been assingned'
                    notification = Notification.objects.create(
                        organization = org,
                        type = 2,
                        heading = heading,
                        message = message,
                        location = loc,
                        actor_user = request.user,
                        affected_user = user,
                        role = "admin"
                    )
                    data = NotificationSerializer(notification).data
                    org_users = loc.user.filter(is_active = True)
                    for org_user in org_users:
                        if org_user != request.user:
                            SendNotification(message, org_user.id, tag_name, heading, data)


                for location in remove:
                    try:
                        loc = Location.objects.get(
                            id = location,
                        )

                        loc.user.remove(user)
                        client_log(request, org, f"Removed _user_ from Location {loc.location_name}", user = user)
                    except:
                        pass
                   

            #MJ updating role of the user
            if 'role' in request.data:
                if request.user.has_perm('accounts.client_admin'): #MJ only Owner can update roles.
                    role = request.data['role']
                    user.user_permissions.clear() # removing existing permissions
                    
                    permissions = Permission.objects.filter(
                        codename = role
                    )
                    if permissions.exists():
                        permission = permissions[0]
                    else:
                        permission = Permission.objects.filter(
                        codename = "client_reader"
                    )[0]
                    user.user_permissions.add(permission)
                    user.save()
                    client_log(request, org, f"Changed role of _user_ to {roles_map[role]}.", user = user)

                    data = {
                        'user_id':user.id,
                        'permission':role,
                    }

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(send_socketio_event(data, room = str(org.id)))


                else:
                    return Response({"error": UnAuthorizedException}, status=status.HTTP_403_FORBIDDEN)
                
            if "is_active" in request.data:
                is_active = request.data['is_active']
                if not isinstance(is_active, bool):
                    return Response({'error':'is_active must be a valid boolean value.'}, status=status.HTTP_400_BAD_REQUEST)
                if is_active != user.is_active:
                    user_status = "activated" if is_active else "deactivated"
                    client_log(request, org, f"{user_status} the user _user_", user = user)
                    user.profileupdateon = datetime.now()
                    user.is_active = is_active
                    user.save()
            

            serializer = ClientUserUpdateSerializer(
                instance = user, 
                data = request.data, 
                partial = True,
            )
            if serializer.is_valid():
                user.profileupdateon = datetime.now()
                instance = serializer.save()
                #MJclientlog
                client_log(request, org, f"Updated the user _user_", user = instance)

                if self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                    data = [self.get_serializer(instance).data]
                else:
                    data = self.get_serializer(instance).data

                return Response({"message": "Updated user successfully.", 'data':data}, status = status.HTTP_200_OK)
                
            else:
                errors = serializer.errors
                try:
                    for _, messages in errors.items():
                        for message in messages:
                            return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST) 
        
        return Response(
            {"error":"You are unauthorized."}, 
            status = status.HTTP_403_FORBIDDEN
        )


class ClientDeviceListView(generics.RetrieveAPIView):
    permission_classes = IsAuthenticated, FusionClient
    serializer_class = DeviceDashboardSerializer

    def get(self, request, pk, *args, **kwargs):
        try:
            user = User.objects.get(id = pk)
        except:
            return Response({'error':"User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        qs = Device.objects.filter(authenticated_by = user, soft_delete = False)

        if 'search' in request.query_params:
            qs = qs.filter(device_name__istartswith = request.query_params['search'])

        serializer = self.get_serializer(qs, many = True)

        return Response({"data":serializer.data}, status=status.HTTP_200_OK)


######################### Location ################################################################################################
#MJ created for getting information of the location at which the user is working.
#MJ anyone from the organization can use this.

class ClientUserLocation(viewsets.ModelViewSet): #Users / Kristin Watson in figma for client app
    permission_classes = IsAuthenticated, FusionClient
    serializer_class = LocationSerializer


    #MJ lists all the locations a person is working at
    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            try:
                user = User.objects.get(id = pk)
            except:
                return Response({'error':'User does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
            
            org = Organization.objects.get(name = user.org)
            locations = Location.objects.location_by_user(pk).order_by('id')
            
            if 'search' in request.query_params:
                locations = locations.filter(location_name__istartswith = request.query_params['search'])
            
            role = None
            if user.is_owner:
                role = "Administrator Owner"
            elif user.has_perm('accounts.client_admin'):
                role = 'Client Administrator'
            elif user.has_perm('accounts.client_user'):
                role = 'Client User'
            else:
                role = 'Client Reader'

            data = {
                "data": self.get_serializer(locations, many = True, context = {'org':org}).data, 
                "user_name":user.get_full_name(),
                "role":role
            }
            return Response(data, status = status.HTTP_200_OK)
        
        except Exception as e:
            raise LocationNotFound()
        

    #MJ assigns new locations to the user
    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm('accounts.client_admin'):
            try:
                try:
                    user = User.objects.get(id = pk)
                except:
                    return Response({'error':"User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
                
                #updated
                if "locations" in request.data:
                    for id in request.data["locations"]:
                        try:
                            if not id.isnumeric():
                                return Response({'error':'locations must contain valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            if not isinstance(id, int):
                                return Response({'error':'locations must be valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                            
                    locations = Location.objects.filter(id__in = request.data["locations"], organization = org)
                    if not locations.exists() or len(locations) != len(request.data["locations"]):
                        return Response({'error':'Location does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"error":"Please pass the 'locations' argument."}, status = status.HTTP_400_BAD_REQUEST)


                for location in locations:
                    if user in location.user.all():
                        return Response({'error':'Location already assigned'}, status=status.HTTP_400_BAD_REQUEST)

                for loc in locations: 
                    tag_name="user_id"
                    heading='New location has been assingned'
                    if user not in loc.user.filter(is_active = True):
                        loc.user.add(user)
                        client_log(request, org, f"Assigned Location {loc.location_name} to _user_.", user = user)
                        
                        message=f'{request.user.get_full_name()} has assigned the location {loc.location_name} to {user.get_full_name()}.'
                        notification = Notification.objects.create(
                            organization = org,
                            type = 2,
                            heading = heading,
                            message = message,
                            location = loc,
                            actor_user = request.user,
                            affected_user = user,
                            role = "admin"
                        )
                        data = NotificationSerializer(notification).data
                        if user != request.user:
                            SendNotification(message, user.id, tag_name, heading, data)                   
                        
                return Response({"message":"Locations assigned successfully."},status = status.HTTP_200_OK)

            except Exception as e:
                return Response(
                    {"error":str(e)},
                    status = status.HTTP_400_BAD_REQUEST
                )

        else:
            return Response(
                {"error":UnAuthorizedException}, 
                status = status.HTTP_403_FORBIDDEN
            )
        
    #MJ removes user from list of locations
    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)

        if request.user.is_owner:
            try:
                try:
                    user = User.objects.get(id = pk)
                except:
                    return Response({'error':"User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
                locations = Location.objects.filter(pk__in = request.data["locations"])

                if len(locations) != len(request.data['locations']):
                    return Response({'error':'Location does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
                
                for location in locations:
                    location.user.remove(user)
                    location.save() 

                    client_log(request, org, f"Removed _user_ from Location {location.location_name}", user)


                return Response(
                    {"message":"Asked Locations Removed Successfully."},
                    status = status.HTTP_200_OK
                )

            except Exception as E:
                return Response(
                    {"error":str(E)},
                    status = status.HTTP_400_BAD_REQUEST
                )

        else:
            return Response(
                {"error":UnAuthorizedException}, 
                status = status.HTTP_403_FORBIDDEN
            )
        

    def create(self, request, *args, **kwargs):
        pass


######################### Location ################################################################################################
#MJ for separate Location section
class ClientLocation(viewsets.ModelViewSet):
    permission_classes = IsAuthenticated, FusionClient

    def get_queryset(self):

        org = Organization.objects.get(name = self.request.user.org)
        self.queryset = Location.objects.filter(organization = org)
        
        #filters --> will only execute if there are query parameters in the request
        if bool(self.request.query_params):
            qs = self.queryset 
            query = self.request.query_params
            #activity filter
            if "active" in query:
                if query['active'] == 'true':
                    qs = qs.filter(Q(is_active = True))
                else:
                    qs = qs.filter(Q(is_active = False))
                
            #search filter
            if 'search' in query:
                qs = qs.filter(Q(location_name__istartswith = query['search']))
            
            if 'ordering' in query:
                if query['ordering'] == 'desc':
                    qs = qs.order_by('-location_name')
                elif query['ordering'] == 'asc':
                    qs = qs.order_by('location_name')

            return qs

        return self.queryset


    @action(detail = False, methods = ['GET'], url_path='all-locations')
    def all_locations(self, request):
        organization = Organization.objects.get(user = request.user)
        qs = Location.objects.filter(organization = organization)               
        serializer = DashboardUserLocationSerializer(qs, many = True)
        data = serializer.data
        if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
            return Response({"results":data}, status=status.HTTP_200_OK)
        return Response({"data":data}, status.HTTP_200_OK) 
    
    
    def list(self, request, pk = None):    
        try:

            org = Organization.objects.get(user = request.user)
            org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
            subscription_flag = org_plans.exists()

            result = self.get_queryset().order_by('-id')

            paginator = StandardResultsSetPagination()

            page = paginator.paginate_queryset(result, request)
            if page is not None:
                if self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                    serializer = LocationSerializer(page, many = True, context = {'org':org})
                else:
                    serializer = LocationWebSerializer(page, many = True, context = {'org':org})
                return paginator.get_paginated_response(serializer.data, total_counts = Location.objects.filter(organization = org).count(), subscription_flag = subscription_flag)

            return Response({"data":serializer.data}, status = status.HTTP_200_OK)
            
        except:
            return Response({"error": UnAuthorizedException}, status = status.HTTP_403_FORBIDDEN)


    @action(methods = ['GET'], detail = False, url_path = 'active')
    def active_locations(self, request):
        org = Organization.objects.get(user = request.user)
        locations = Location.objects.filter(organization = org, is_active = True)
        data = DashboardUserLocationSerializer(locations, many = True).data
        return Response({"data":data}, status = status.HTTP_200_OK)



    @action(methods = ['GET'], detail = True, url_path = 'location-devices')
    def location_devices(self, request, pk = id):
        try:
            if not pk.isnumeric():
                return Response({'error':'id must be a valid integer.'}, status=status.HTTP_400_BAD_REQUEST)
            org = Organization.objects.get(user = request.user)
            location = Location.objects.get(id = pk, organization = org)
            devices = location.device_set.filter(soft_delete = False)
            serializer = DeviceDashboardSerializer(devices, many = True)
            return Response({"data":serializer.data}, status = status.HTTP_200_OK)
        except:
            return Response({'error':'Location not found.'}, status=status.HTTP_400_BAD_REQUEST)


    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(name = request.user.org)
        try:
            try:
                location = Location.objects.get(id = pk, organization = org)
            except:
                return Response({'error':"Location does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            
            if not self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                return Response(LocationDetailSerializer(location).data, status=status.HTTP_200_OK)
            else: 
                data = LocationMobileDetailSerializer(location, context = {'request':request}).data
                return Response(data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error":"The location does not exist."}, status=status.HTTP_403_FORBIDDEN)


    def create(self, request, pk = None):

        request_org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(request_org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(request_org) and not has_active_trial(request_org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm('accounts.client_admin'):
            user = User.objects.get(username = request.user)
            request_org = Organization.objects.get(name = user.org)
            owner = User.objects.get(org = request_org.name, is_owner = True)
            try:
                match = re.match("^[#.0-9a-zA-Z\s,-]+$", request.data["location_name"])
                if match is None:
                    return Response({'error':'Please enter a suitable location name.'}, status = status.HTTP_400_BAD_REQUEST)
                data = {
                    "location_name":request.data["location_name"],
                    "is_active":True,
                }

                
                serializer = LocationSerializer(data = data, partial = True)
                context = dict()
                if serializer.is_valid():
                    if Location.objects.filter(location_name__iexact = request.data['location_name'].strip(), organization = request_org).exists():
                        return Response({"error":"Location with the same name exists for this organization."}, status = status.HTTP_403_FORBIDDEN)
                    new_instance = Location.objects.create(
                        location_name = data['location_name'],
                        is_active = True
                    )
                    try:
                        new_instance.save()
                    except Exception as e:
                        pass
                    try:
                        new_instance.organization = request_org
                        new_instance.created_by = user
                        new_instance.user.add(user)
                        if user.id != owner.id:
                            new_instance.user.add(owner)
                            context["users_added"] = [user.id, owner.id]
                        else:
                            context["users_added"] = [user.id]
                    except Exception as e:
                        return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
                    
                    new_instance.save()
                    client_log(request, request_org, f"Created a new location: {new_instance.location_name}.")

                    context['created'] = f"Location {new_instance.location_name} created successfully."
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

                if 'users' in request.data:
                    location_users = request.data['users']
                    for id in location_users:
                        try:
                            if not id.isnumeric():
                                return Response({'error':'users must contain valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            if not isinstance(id, int):
                                return Response({'error':'users must be valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)

                    if user.id in location_users:
                        location_users.remove(user.id)

                    
                    for user_id in location_users:
                        try:
                            userl = User.objects.get(Q(id = user_id) & Q(org = user.org))
                            new_instance.user.add(userl)
                            new_instance.save()
                            #MJclientlog
                            client_log(request, request_org, f"Assigned _user_ to location: {new_instance.location_name}.", userl)

                        except:
                            context["error"] = f"{user_id} does not belong to your organization."
                            return Response(context, status = status.HTTP_400_BAD_REQUEST)
                        context['users_added'].append(user_id)
                    context['message'] = "Location created successfully."

                    heading = "New location added"
                    message = f"{user.get_full_name()} created {new_instance.location_name} location."
                    tag_name = "user_id"
                    data = LocationWebSerializer(new_instance).data
                    context['data'] = data
                    org_users = request_org.user.filter(is_active = True)
                    
                    notification = Notification.objects.create(
                        organization = request_org,
                        type = 3,
                        heading = heading,
                        message = message,
                        location = new_instance,
                        actor_user = request.user,
                        role = "admin"
                    )
                    notification_data = NotificationSerializer(notification).data

                    for user in org_users:
                        if user != request.user:
                            SendNotification(message, user.id, tag_name, heading, notification_data)

                    userl = User.objects.filter(id__in = location_users)
                    heading='New location has been assigned'
                    for user in userl:
                        message=f'{request.user.get_full_name()} has assigned the location {new_instance.location_name}  to {user.get_full_name()}.'
                        notification = Notification.objects.create(
                            organization = request_org,
                            type = 2,
                            heading = heading,
                            message = message,
                            location = new_instance,
                            actor_user = request.user,
                            affected_user = user,
                            role = "admin"
                        )
                        data = NotificationSerializer(notification).data
                        if user != request.user:
                            SendNotification(message, user.id, tag_name, heading, data)
                return Response(context, status = status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
            

    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.is_owner:
            
            org = Organization.objects.get(user = request.user)

            try:
                location = Location.objects.get(
                    id = pk,
                    organization = org
                )
                location.user.clear()

                client_log(request, org, f"Deleted the location: {location.location_name}.")

                location.delete()

            except:
                return Response({"error":"Location does not exist."}, status = status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Location deleted successfully."}, status = status.HTTP_200_OK)

        return Response({"error": "You are unauthorized."}, status = status.HTTP_400_BAD_REQUEST)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm('accounts.client_admin'):
            
            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            try:
                try:
                    location = Location.objects.get(id = pk)
                except:
                    return Response({'error':"The location does not exist."}, status=status.HTTP_400_BAD_REQUEST)
                
                current_status = location.is_active
                
                new_status = request.data['is_active']
                if not isinstance(new_status, bool):
                    return Response({'error':'is_active must be a valid boolean value.'}, status=status.HTTP_400_BAD_REQUEST)
                
                active_status = None
                if current_status != new_status :
                    active_status = "Activated" if new_status else "Deactivated"
                    location.is_active = new_status

                    location.save()
                    data = LocationWebSerializer(location).data
                    client_log(request, org, f"{active_status} the location {location.location_name}.")

                    return Response({'message':f"{active_status} location successfully.", "data":data}, status = status.HTTP_200_OK)
                
                else:
                    return Response({'error':'Status is same as before.'}, status = status.HTTP_304_NOT_MODIFIED)
                
            except:
                return Response({'error':'Only active status can be changed.'}, status = status.HTTP_304_NOT_MODIFIED)
            
        else:
            return Response({"error": "You are unauthorized."}, status = status.HTTP_400_BAD_REQUEST)
        

    @action(methods=['DELETE'], detail = False, url_path = "multiple-delete")
    def multiple_delete(self, request):
        if request.user.is_owner:
            try:
                
                org = Organization.objects.get(user = request.user)
                    
                if can_avail_trial(org):
                    return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
                
                if not has_active_subscription(org) and not has_active_trial(org):
                    return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

                delete_ids = request.data["ids"]
                for id in delete_ids:
                    try:
                        if not id.isnumeric():
                            return Response({'error':'ids must contain valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        if not isinstance(id, int):
                            return Response({'error':'ids must be valid integer values.'}, status=status.HTTP_400_BAD_REQUEST)
                

                delete_locations = Location.objects.filter(id__in = delete_ids, organization = org)

                for location in delete_locations:
                    location.user.clear()
                    all_devices = location.device_set.filter(soft_delete = False)

                    for device in all_devices:
                        device.soft_delete = True
                        device.is_active = False
                        device.is_online = False
                        device.is_subscribed = False
                        data = {
                            'service_change': False, # True when execute_now or crontime update
                            'device_details_change': True,
                            'reauthenticate': False,
                            'code_change': False,
                            'device_status_change':True, # when device status change we need to send it true
                            'service_status_change':False, # when service change send true
                        }
                        data = data
                        device.call_config_types = data
                        device.save()

                    location.delete()

                org_plan_qs = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
                if org_plan_qs.exists():
                    org_plan = org_plan_qs.first()
                    org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                    org_plan.save()

                client_log(request, org, f"Deleted {len(delete_locations)} locations.")
                return Response({'message':"Locations deleted successfully."}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)    
        

    @action(methods=['PUT'], detail = False, url_path = "multiple-active")
    def multiple_active(self, request):
        
        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            try:
                ids = request.data["ids"]
                active_status = request.data['is_active']
                new_status = "activated" if active_status else "deactivated"

                locations = Location.objects.filter(id__in = ids)
                
                if len(ids) != locations.count():
                    return Response({'error':'Location does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                org_service_flag = False
                if OrgnisationService.objects.filter(orginstion = org, service_active = True, Subscribed = True).exists():
                    org_service_flag = True
                for location in locations:
                    location.is_active = active_status
                    location.save()
                    devices = location.device_set.all()
                    for device in devices:
                        device.is_active = active_status
                        device.is_online = active_status
                        data = {
                            'service_change': False, # True when execute_now or crontime update
                            'device_details_change': False,
                            'reauthenticate': False,
                            'code_change': False,
                            'device_status_change':True, # when device status change we need to send it true
                            'service_status_change':False, # when service change send true
                        }
                        data = data

                        services = device.services.all()
                        if services.exists() and org_service_flag:
                            service = services.first()
                            ss = SubService.objects.filter(service = service)
                            ss.update(is_active = active_status)
                            service.service_active = active_status
                            service.save()
                            data['service_status_change'] = True
                        device.call_config_types = data
                        device.save()

                locations = Location.objects.filter(id__in = ids)
                data = LocationWebSerializer(locations, many = True).data
                client_log(request, org, f"{new_status} {'locations' if len(ids) > 1 else 'location'}.")
                return Response({'message':f"{len(ids)} locations {new_status} successfully.", "data":data}, status=status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
            
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)



#################################### need a review ends ##########################################################


# I don't know what are these for
class FModalViewSet(mixins.CreateModelMixin,
                    mixins.RetrieveModelMixin,
                    mixins.ListModelMixin,
                    GenericViewSet):
    pass


############################ Login and OTP ######################################################################################
@method_decorator(name = 'post', decorator = device_crud(**DEVICE_DECORATORS.post))
class UserTokenObtainView(TokenObtainPairView):
    throttle_classes = AnonRateThrottle,
    serializer_class = TokenSerializer

    def post(self, request, *args, **kwargs):
        is_captcha_valid = False

        try:
            if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                is_captcha_valid = True
            else:
                captcha_response = request.data.get('captcha', None)
                if not captcha_response:
                    return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

                captcha = ReCaptchaField()
                try:
                    if not captcha.clean(captcha_response):
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        is_captcha_valid = True
                except:
                    return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)

        if is_captcha_valid:
            try:
                request.data["username"] = request.data["username"].lower().strip()
                user = User.objects.get(username = request.data["username"])
            except Exception as e:
                return  Response({"error":f'Invalid credentials.'}, status = status.HTTP_400_BAD_REQUEST)
            try:
                currenttime = datetime.now(utc)
                vaildtime = user.otpgenerationTime
                
                key = f"login_attempts_{request.data['username']}_{request.META['REMOTE_ADDR']}"
                attempts = cache.get(key, 0)
                if attempts >= 4:
                    return Response({'error':'Please try again after a few minutes.'}, status = status.HTTP_400_BAD_REQUEST)
                else:
                    attempts += 1
                    cache.set(key, attempts, timeout = 1800)

                if vaildtime >= currenttime:
                    if int(request.data["otp"]) == int(user.otp):                       
                        if user.failedLoginCount <= 3:
                            user.failedLoginCount = 0
                            user.otp = generateOTP()
                            user.last_login = datetime.now()
                            user.save()
                            
                            ## deleting cache on successfull login
                            key = f"otp_attempts_{ request.data['username'] }_{request.META['REMOTE_ADDR']}"
                            cache.delete(key)
                            key = f"login_attempts_{ request.data['username'] }_{request.META['REMOTE_ADDR']}"
                            cache.delete(key)
                            
                            org = Organization.objects.get(user = user)
                            #MJclientlog
                            client_log(request, org, "Logged In.", actor_id = user.id)
                            
                            return super(UserTokenObtainView, self).post(request, *args, *kwargs)
                        
                        else:
                            return Response({"error": "This OTP has been expired, please generate again."}, status = status.HTTP_400_BAD_REQUEST)
                
                    user.failedLoginCount = user.failedLoginCount + 1
                    user.save()
                    return Response({"error":"Invalid OTP."}, status = status.HTTP_400_BAD_REQUEST)
                return Response({"error":"This OTP has been expired, please generate again."}, status = status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return  Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error':'Captcha is invalid.'}, status = status.HTTP_400_BAD_REQUEST)


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            if serializer.is_valid():
                return Response(serializer.validated_data, status=status.HTTP_200_OK)
            else:
                return Response({'error':'Either your account is inactive or deleted by the administrator.'}, status=401)
        except Exception as e:
            return Response({'error':'Either your account is inactive or deleted by the administrator.'}, status=401)


class UserLogoutView(APIView):

    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            token = RefreshToken(request.data.get('refresh'))
            access_token = request.META.get('HTTP_AUTHORIZATION', None).split()[1]
            decoded_data = jwt.decode(access_token, None, False)
            jti = decoded_data['jti']
            expiry = datetime.fromtimestamp(decoded_data['exp'])

            AccessTokensBlackList.objects.create(
                jti = jti,
                user = request.user,
                expires_at = expiry,
                token = access_token
            )

            token.blacklist()

            org = Organization.objects.get(name = request.user.org)
            #MJclientlog
            client_log(request, org, "Logged out.")

            return Response({"message": "Logged out successfully."}, status = status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': "Token is invalid or expired"}, status = status.HTTP_403_FORBIDDEN)
    

# OTP generation 
def generateOTP():

    digits = "0123456789"
    OTP = ""

    for i in range(6):
        OTP += digits[math.floor(random.random() * 10)]

    return OTP

# otp = generateOTP()
class SendOtp(APIView):
    
    def post(self, request):
        data = request.data
        username = data.get("username")
        password = data.get("password")

        try:
            user = User.objects.get(username = username)
        except:
            user = User.objects.get(email = username)

        key = f"otp_attempts_{username}_{request.META['REMOTE_ADDR']}"
        attempts = cache.get(key, 0)
        if attempts >= 4:
            return Response({'error':'Please try again after a few minutes.'}, status = status.HTTP_400_BAD_REQUEST)
        else:
            attempts += 1
            cache.set(key, attempts, timeout = 300)

        if user.is_staff:
            return Response({'error':"Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.is_active:
            return Response({"error":"Invalid credentials."}, status = status.HTTP_400_BAD_REQUEST)
        
        orgs = org = Organization.objects.filter(user = user)
        
        if not orgs.exists():
            Response({"error": "Invalid credentials."}, status = status.HTTP_400_BAD_REQUEST)
        
        else:  
            org = orgs.first()

            if not org.is_active:
                return Response({"error":"Invalid credentials."}, status = status.HTTP_400_BAD_REQUEST)

        if user.check_password(password):
            email = user.username
            if username == "gautam.crawlapps+4@gmail.com":
                otp = 455462
            else:
                otp = generateOTP()
            
            user.otp = otp
            recipient_list = [email]
            message = get_template("accounts/otp.html").render({
                'user': user.get_full_name(),
                'otp': otp
            })

            subject = 'Otp verification'
            send_otp_email_task(recipients=recipient_list, subject=subject, message=message)

            user.otpgenerationTime = datetime.now() + timedelta(minutes = 5)
            user.failedLoginCount = 0
            user.save()
            #MJclientlog
            client_log(request, org, "OTP generated", actor_id = user.id)   
            return Response({"message": "OTP sent successfully."}, status.HTTP_200_OK)
        return Response({"error": "Invalid credentials."}, status = status.HTTP_400_BAD_REQUEST)



############################ Password ###########################################################################################
class ResetPassword(viewsets.ViewSet):

    def retrieve(self, request, pk = id):
        try:
            users = User.objects.filter(forgotlink = str(pk), is_staff = False)
            if not users.exists():
                return Response({'error':'This link is expired use recent one or try to generate new one.'}, status = status.HTTP_400_BAD_REQUEST)
            user = users.first()
            if user.forgotlinktime < datetime.now():
                return Response({'error':'This link is expired use recent one or try to generate new one.'}, status = status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message':'OK'})
        except:
            return Response({'error':'You are unauthorized.'}, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, pk = None):

        is_captcha_valid = False
        if request.user.is_authenticated:
            is_captcha_valid = True
        else:
            try:
                if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                    is_captcha_valid = True
                else:
                    captcha_response = request.data.get('captcha', None)
                    if not captcha_response:
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

                    captcha = ReCaptchaField()
                    try:
                        if not captcha.clean(captcha_response):
                            return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
                        else:
                            is_captcha_valid = True
                    except:
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)

        if is_captcha_valid:
            try:
                username = request.data["username"]
                user = User.objects.none()
                
                try:
                    user = User.objects.get(username = username, is_staff = False, is_active = True)

                except:
                    try:
                        user = User.objects.get(email = username, is_staff = False, is_active = True)

                    except:
                        return Response({"error":"Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)
                    
                try: 
                    key = f"reset_password_attempts_{request.data['username']}_{request.META['REMOTE_ADDR']}"
                    attempts = cache.get(key, 0)
                    if attempts >= 4:
                        return Response({'error':'Please try again after a few minutes.'}, status = status.HTTP_400_BAD_REQUEST)
                    else:
                        attempts += 1
                    cache.set(key, attempts, timeout = 300)

                    user.forgotlink = uuid.uuid4()
                    user.forgotlinktime = datetime.now() + timedelta(minutes = 15)
                    user.save()

                    recipient_list = [username]

                    message = get_template("accounts/reset_password.html").render({
                        'user_name': user.get_full_name(),
                        'link': f'{settings.CLIENT_FRONTEND_URL}/resetpassword/{user.forgotlink}/'
                    })

                    subject = 'Reset Password'
                    send_otp_email_task(recipients=recipient_list, subject=subject, message=message)

                    org = Organization.objects.get(name = user.org)
                    client_log(request, org, "Requested for resetting the password.", actor_id = user.id)

                    
                    return Response({"message":f"A password reset link is sent successfully."}, status = status.HTTP_200_OK)
                
                except Exception as e:
                    return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)
                
            except Exception as e:
                return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error':'Captcha is invalid'}, status = status.HTTP_400_BAD_REQUEST)
            

    def update(self, request, pk = id):                
        try:
            users = User.objects.filter(forgotlink = str(pk), is_staff = False, is_active = True)
            if not users.exists():
                return Response({'error':'This link is expired use recent one or try to generate new one.'}, status = status.HTTP_400_BAD_REQUEST)
            
            is_captcha_valid = False
            
            user = users.first()

            org = Organization.objects.get(user = user)

            try:
                if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                    is_captcha_valid = True
                else:
                    captcha_response = request.data.get('captcha', None)
                    if not captcha_response:
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

                    captcha = ReCaptchaField()
                    try:
                        if not captcha.clean(captcha_response):
                            return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
                        else:
                            is_captcha_valid = True
                    except:
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)

            if is_captcha_valid:
                data = {
                    "password":request.data["password"],
                    "confirm_password":request.data["confirm_password"],
                    "username":user.username,
                }
                if user:
                    currenttime = datetime.now()
                    currenttime = currenttime.replace(tzinfo=utc)
                    if user.forgotlinktime >= currenttime:
                        if data["password"] == data["confirm_password"]:
                            
                            r_p = re.compile('^(?=\S{6,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])')
                                
                            if len(request.data["password"]) <= 8:
                                return Response({"error": "Password is short."}, status=status.HTTP_400_BAD_REQUEST)
                            
                            if not r_p.match(request.data["password"]):
                                return Response({'error':'Password must contain one lowercase, one uppercase, one number, and a special character.'}, status = status.HTTP_400_BAD_REQUEST)

                            data['forgotlink'] = None
                            data['forgotlinktime'] = None
                            serializer = ResetPasswordSerializer(instance = user, data = data, partial = True)
                            if serializer.is_valid():
                                
                                key = f"reset_password_attempts_{data['username']}_{request.META['REMOTE_ADDR']}"
                                cache.delete(key)

                                serializer.save()
                                
                                client_log(request, org, "Reset the Password", actor_id = user.id)

                                return Response({"message":"Password changed successfully."}, status = status.HTTP_200_OK)
                        else:
                            return Response({'error':'Passwords did not match.'},status = status.HTTP_400_BAD_REQUEST)
                    return Response({"error":"The link has been expired."}, status = status.HTTP_408_REQUEST_TIMEOUT)
            else:
                return Response({'error':'Captcha is invalid'}, status = status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):


        org = Organization.objects.get(user = request.user)

        self.object = self.get_object()
        serializer = self.get_serializer(data = request.data)

        if serializer.is_valid():
            r_p = re.compile('^(?=\S{6,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])')

            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"error":"You have entered wrong current password."}, status=status.HTTP_400_BAD_REQUEST)
            
            if request.data["old_password"] == request.data["new_password"]:
                return Response({"error": "Your new password is same as the old one."}, status=status.HTTP_400_BAD_REQUEST)
            
            if len(request.data["new_password"]) <= 8:
                return Response({"error": "Password is short."}, status=status.HTTP_400_BAD_REQUEST)
            
            if not r_p.match(request.data["new_password"]):
                return Response({'error':'Password must contain one lowercase, one uppercase, one number and a special character.'}, status = status.HTTP_400_BAD_REQUEST)
            
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()

            org = Organization.objects.get(name = self.object.org)

            #MJclientlog
            client_log(request, org, "Changed Password.")            


            response = {
                'message': 'Password updated successfully.',
            }

            return Response(response, status = status.HTTP_200_OK)

        else:
            errors = serializer.errors
            try:
                for _, messages in errors.items():
                    for message in messages:
                        return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
            except:
                return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
 


#########################################################################################################################
# ---------------------------------> Device <----------------------------------------------------------------------------

@method_decorator(name='start', decorator=device_crud(**DEVICE_DECORATORS.start))
@method_decorator(name='exchange', decorator=device_crud(**DEVICE_DECORATORS.exchange))
@method_decorator(name='reauth', decorator=device_crud(**DEVICE_DECORATORS.reauth))
@method_decorator(name='details', decorator=device_crud(**DEVICE_DECORATORS.details))
@method_decorator(name='lastseen', decorator=device_crud(**DEVICE_DECORATORS.lastseen))
@method_decorator(name='lastseen_update', decorator=device_crud(**DEVICE_DECORATORS.lastseen_update))
@method_decorator(name='pushdata', decorator=device_crud(**DEVICE_DECORATORS.pushdata))
@method_decorator(name='check', decorator=device_crud(**DEVICE_DECORATORS.check))
class DeviceView(viewsets.ModelViewSet):
    permission_classes = IsAuthenticated, FusionClient
    serializer_class = DeviceSerializer

    def get_queryset(self):
        org = Organization.objects.get(user = self.request.user)
        self.queryset = Device.objects.filter(Q(org = org) & Q(soft_delete = False))
        
        #filters --> will only execute if there are query parameters in the request
        if bool(self.request.query_params):
            qs = self.queryset
            query = self.request.query_params
            #online/offline filter
            if "online" in query:
                if query['online'] == 'true':
                    qs = qs.filter(Q(is_online = True))
                if query['online'] == 'false':
                    qs = qs.filter(Q(is_online = False))
            
            #activity filter
            if "active" in query:
                if query['active'] == 'true':
                    qs = qs.filter(Q(is_active = True))
                else:
                    qs = qs.filter(Q(is_active = False))

            #location filter
            if "location" in query:
                locations = query.getlist('location') 
                qs = qs.filter(location__id__in = [int(i) for i in locations])

            #location filter
            if "type" in query:
                types = query.getlist('type')
                qs = qs.filter(device_type__in = types)
                
                
            #search filter
            if 'search' in query:                
                qs = qs.filter(
                    Q(device_name__istartswith = query['search']) | 
                    Q(mac_address__icontains = query['search'])
                )
                
            return qs

        return self.queryset    


    def list(self, request):
        try:
            org = Organization.objects.get(user = request.user)
            queryset = Device.objects.filter(Q(org = org) & Q(soft_delete = False)).order_by('-id')
            result = self.get_queryset().order_by('-id')

            org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
            subscription_flag = org_plans.exists()

            paginator = StandardResultsSetPagination()

            page = paginator.paginate_queryset(result, request)

            if page is not None:
                serializer = ClientDeviceSerializer(page, many = True)
                return paginator.get_paginated_response(serializer.data, total_counts = queryset.count(), subscription_flag = subscription_flag)
            
            serializer = ClientDeviceSerializer(result, many = True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except:
            return Response({"error": UnAuthorizedException}, status = status.HTTP_403_FORBIDDEN)


    def retrieve(self, request, pk = id):

        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        try:
            org = Organization.objects.get(user = request.user)
            device = Device.objects.get(id = pk, soft_delete = False, org = org)
        except:
            return Response({}, status = status.HTTP_200_OK)
        device_data = ClientDeviceSerializer(device).data
        return Response(device_data, status = status.HTTP_200_OK)
    

    @action(methods = ['PUT'], detail = False, url_path="subscribe-devices")
    def subscribe_devices(self, request):
        org = Organization.objects.get(user = request.user)
        org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        if org_plans.exists():
            org_plan = org_plans.first()


            devices = Device.objects.filter(org = org, soft_delete = False)
            devices = devices.filter(id__in = request.data['ids'], is_subscribed = False)

            if org_plan.is_paused:
                return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)

            if devices.count() != (org_plan.device_limit - org_plan.utilized_limit):
                return Response({'error':f"Please select {org_plan.device_limit - org_plan.utilized_limit} {'device' if org_plan.device_limit == 1 else 'devices'}"}, status = status.HTTP_400_BAD_REQUEST)
            
            devices = Device.objects.filter(org = org, id__in = request.data['ids'], is_subscribed = False, soft_delete = False)
            if devices.exists():
                for device in devices:
                    device.is_subscribed = True
                    device.is_active = True # reactivating the device
                    device.save()
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
                    data = {
                        'service_change': False,
                        'device_details_change': True,
                        'reauthenticate': False,
                        'code_change': False,
                        'service_status_change':True,
                        'device_status_change':True
                    }
                    data = data
                    device.call_config_types = data
                    device.save()
                org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                org_plan.save()
                return Response({'message':'Activated devices successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error':'No devices were selected.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error':'No active plan was found.'}, status=status.HTTP_400_BAD_REQUEST)


    

    @action(methods = ['PUT'], detail = False, url_path="assign-location")
    def assign_location(self, request):
        if request.user.has_perm("accounts.client_admin"):
            
            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            ids = request.data["ids"]
            location_id = request.data['location_data']
            devices = Device.objects.filter(id__in = ids, org = org, soft_delete = False)
            if devices.count() != len(ids):
                return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            unsubscribed = devices.filter(is_subscribed = False)
            if unsubscribed.exists():
                return Response({'error':'This device is not covered under your subscription.'}, status = status.HTTP_400_BAD_REQUEST)
            try:
                location = Location.objects.get(id = location_id, organization = org)
            except:
                return Response({"error":"Location is not available."}, status = status.HTTP_400_BAD_REQUEST)


            if not location.is_active:
                return Response({"error":"Device can not be assigned to an inactive location."}, status=status.HTTP_400_BAD_REQUEST)

            for device in devices:
                if device.location == location:
                    return Response({'error':'Device is already assigned to the location.'}, status=status.HTTP_400_BAD_REQUEST)

            if devices.exists():
                try:
                    data = {
                        'service_change': False,
                        'device_details_change': True,
                        'reauthenticate': False,
                        'code_change': False,
                        'service_status_change':False,
                        'device_status_change':False
                    }
                    devices.update(location = location)
                    devices.update(call_config_types=data)
                    serializer = ClientDeviceSerializer(devices, many = True)
                    
                    for device in devices:
                        heading = f"Device relocated."
                        message = f"{device.device_name} assigned to {location.location_name} by {request.user.get_full_name()}."
                        data = LocationWebSerializer(location).data
                        notification = Notification.objects.create(
                            organization = org,
                            type = 4,
                            heading = heading,
                            message = message,
                            location = location,
                            actor_user = request.user,
                            device = device
                        )
                        data = NotificationSerializer(notification).data

                        users = org.user.filter(is_active = True)
                        for user in users:
                            if user.has_perm('accounts.client_admin') and user != request.user:
                                SendNotification(message, user.id, "user_id", heading, data = data)

                        DeviceChangesLog.objects.create(
                            changed_by = request.user.username,
                            title = f"Assigned to location {location.location_name} by {request.user.get_full_name()}",
                            device_serial_no = device.serial_number,
                            organization = org,
                            device_id = str(device.id)
                        )
                    return Response({"message":f"{len(ids)} {'devices' if len(ids) > 1 else 'device'} assigned to {location.location_name}.", 'data':serializer.data}, status = status.HTTP_200_OK)
                except Exception as e:
                    return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
            return Response({"error":"No devices were found."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin"):
            org = Organization.objects.get(user = request.user)


            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
            

            if "is_active" in request.data and request.user.is_owner == False:
                return Response({"error":"Only owner can perform activate/deactivate action."}, status=status.HTTP_403_FORBIDDEN)
            
            try:
                device = self.get_queryset().get(id = pk, org = org, soft_delete = True)
            except:
                return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            if not device.is_subscribed:
                return Response({'error':'This device is not covered under your subscription.'}, status = status.HTTP_400_BAD_REQUEST)
            if device:
                if not device.location.is_active:
                    return Response({"error":"Please activate the assigned location to update the status of the device."}, status=status.HTTP_400_BAD_REQUEST)
                serializer = ClientDeviceSerializer(instance = device, data = request.data, partial = True)
                if serializer.is_valid():
                    serializer.save()
                    
                    # device_log(instance, org, action = "Updated by _user_", user = request.user)
                    client_log(request, org, action = f"Updated the device {device.device_name}")
                
                return Response({"message":"Device updated successfully.", "data":serializer.data}, status = status.HTTP_202_ACCEPTED)
            else:
                return Response(DeviceNotFound, status = status.HTTP_404_NOT_FOUND)
        else:
            return Response({"error": "unauthorized"}, status = status.HTTP_403_FORBIDDEN)
        

    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.is_owner:

            org = Organization.objects.get(user = request.user)

            try:
                device = Device.objects.get(id = pk, org = org, soft_delete = False)
            except:
                return Response({"error":"The device does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            client_log(
                request, org, action = f"Removed the device {device.device_name}."
            )
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
            device.soft_delete = True
            device.is_active = False
            device.is_subscribed = False
            device.save()
            device_notifications = Notification.objects.filter(device = device)
            for dn in device_notifications:
                dn.delete()
            org_plan = OrganizationPlan.objects.get(organization = org, is_plan_active = True)
            org_plan.utilized_limit = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False).count()
            org_plan.un_used_devices.add(device)
            org_plan.save()  
            return Response({"message": "Device deleted successfully."}, status = status.HTTP_200_OK)
        return Response({"error": "You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    @action(methods=['DELETE'], detail = False, url_path = "multiple-delete")
    def multiple_delete(self, request):
        if request.user.is_owner:
            
            org = Organization.objects.get(user = request.user)
            
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            org_plan = OrganizationPlan.objects.get(organization = org, is_plan_active = True)
            try:
                delete_ids = request.data["ids"]
                delete_devices = Device.objects.filter(id__in = delete_ids, org = org, soft_delete = False)
                if delete_devices.count() != len(request.data['ids']):
                    return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
                
            except:
                return Response({'error':'No devices were selected for deletion.'}, status = status.HTTP_403_FORBIDDEN)
    
            delete_devices = Device.objects.filter(id__in = delete_ids, org = org, soft_delete = False)
            for device in delete_devices:
                device.soft_delete = True
                device.is_active = False
                device.is_subscribed = False
                data = {
                    'service_change': False, # True when execute_now or crontime update
                    'device_details_change': False,
                    'reauthenticate': False,
                    'code_change': False,
                    'device_status_change':True, # when device status change we need to send it true
                    'service_status_change':True, # when service change send true
                }
                data = data
                device.call_config_types = data
                device.save()
                services = device.services.all()
                for service in services:
                    subservices=SubService.objects.filter(service=service)
                    subservices.delete()
                    service.delete()
                #device.services.remove(*device.services.all())
                device.save()

                notifications = Notification.objects.filter(device = device)
                notifications.delete()

            nd = len(delete_ids)
            org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
            #org_plan.un_used_devices.add(*delete_devices)
            org_plan.save()   

            client_log(
                request, org, action = f"Removed {nd} {'devices' if nd > 1 else 'device'}."
            )

            return Response({'message': f"{nd} {'devices' if nd > 1 else 'device'} deleted successfully."}, status=status.HTTP_200_OK)
        return Response({"error": UnAuthorizedException}, status=status.HTTP_403_FORBIDDEN)

    
        
    @action(methods=['PUT'], detail = False, url_path = "multiple-active")
    def multiple_active(self, request):
        if request.user.is_owner:
            try:
                ids = request.data["ids"]
                active_status = bool(request.data['is_active'])
                new_status = "activated" if active_status else "deactivated"
                
                org = Organization.objects.get(user = request.user)
                
                if can_avail_trial(org):
                    return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
                
                if not has_active_subscription(org) and not has_active_trial(org):
                    return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

                devices = Device.objects.filter(id__in = ids, org = org, soft_delete = False)
                if devices.count() != len(request.data['ids']):
                    return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

                for device in devices:
                    if not device.location.is_active:
                        return Response({'error':'Location is inactive.'}, status=status.HTTP_400_BAD_REQUEST)

                org_plan = OrganizationPlan.objects.filter(organization = org, is_plan_active = True).first()

                if org_plan.is_paused:
                    return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)

                unsubscribed = devices.filter(is_subscribed = False)
                if unsubscribed.exists():
                    us = unsubscribed.count()
                    remaining_limit = org_plan.device_limit - org_plan.utilized_limit
                    if us <= remaining_limit and active_status:
                        for device in unsubscribed:
                            device.is_subscribed = True
                            service = device.services.first()
                            org_service = OrgnisationService.objects.filter(orginstion = org, Subscribed = True, name = service.name).first()  
                            service.Expire_on = org_service.expire_on
                            service.save()
                            subservices = SubService.objects.filter(service = service)

                            for ss in subservices:
                                ss.subscribe = True
                                ss.Expire_on = org_service.expire_on
                                ss.save()
                            data = {
                                'service_change': False, # True when execute_now or crontime update
                                'device_details_change': True,
                                'reauthenticate': False,
                                'code_change': False,
                                'device_status_change':False, # when device status change we need to send it true
                                'service_status_change':False, # when service change send true
                            }
                            data = data
                            device.call_config_types = data
                            device.save()
 
                        org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                        org_plan.save()

                        plan_data = {
                            'device_limit' : org_plan.device_limit if org_plan is not None else 0,
                            'utilized_limit': org_plan.utilized_limit if org_plan is not None else 0,
                            'registered_devices': Device.objects.filter(org = org, soft_delete = False).count()
                        }

                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(send_socketio_plan_limits(plan_data, room = str(org.id)))
                        

                    else:
                        return Response({'error':f'{"This device is" if len(ids) == 1 else "Some of the devices are"} not covered under your subscription.'}, status = status.HTTP_400_BAD_REQUEST)

                devices = Device.objects.filter(id__in = ids, org = org, soft_delete = False, is_subscribed = True)
                for device in devices:
                    if not active_status:
                        device.is_online = False
                    try:
                        if device.is_active != active_status:
                            device.is_active = active_status
                            service = device.services.first()
                            org_service = OrgnisationService.objects.filter(orginstion = org, Subscribed = True, name = service.name).first()
                            if org_service.service_active:
                                service.service_active = active_status
                                service.save()
                                subservices = SubService.objects.filter(service = service)
                                
                                for ss in subservices:
                                    ss.is_active = active_status
                                    ss.save()
                                
                                data = {
                                    'service_change': False, # True when execute_now or crontime update
                                    'device_details_change': False,
                                    'reauthenticate': False,
                                    'code_change': False,
                                    'device_status_change':True, # when device status change we need to send it true
                                    'service_status_change':True, # when service change send true
                                }
                                device.call_config_types = data
                                device.save()
                    except:
                        if device.is_active != active_status:
                            device.is_active = active_status
                            
                            service = device.services.first()
                            org_service = OrgnisationService.objects.filter(orginstion = org, Subscribed = True, name = service.name).first()
                            if org_service.service_active:
                                service.service_active = active_status
                                service.save()
                                subservices = SubService.objects.filter(service = service)
                                for ss in subservices:
                                    ss.is_active = active_status
                                    ss.save()
                                data = {
                                    'service_change': False, # True when execute_now or crontime update
                                    'device_details_change': False,
                                    'reauthenticate': False,
                                    'code_change': False,
                                    'device_status_change':True, # when device status change we need to send it true
                                    'service_status_change':True, # when service change send true
                                }
                                device.call_config_types = data
                                device.save()
                    device.save()
                nd = len(ids)  
                client_log(
                    request, org, action = f"{new_status} {nd} {'devices' if nd > 1 else 'device'}."
                )
                devices = Device.objects.filter(id__in = ids, org = org, soft_delete = False)
                serializer = ClientDeviceSerializer(devices, many = True)
                return Response({'message':f"{nd} {'devices' if nd > 1 else 'device'} {new_status} successfully.", "data":serializer.data}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)

    def initial(self, request, *args, **kwargs):
        if request.get_full_path().rfind('services/retrieve') != -1:
            self.serializer_class = DeviceServiceSerializer
        super(DeviceView, self).initial(request, *args, **kwargs)


    # noinspection PyMethodMayBeStatic
    def check_device_by_payload(self, request):

        if 'authentication_token' not in request.data:
            raise BadRequest(message = "device authentication token not provided")
        
        if 'payload' not in request.data:
            raise BadRequest(message = "payload is not provided")
        
        authentication_token = request.data.get("authentication_token")
        payload_encrypted = request.data.get("payload")
        device = Device.objects.device_by_auth_token(authentication_token = authentication_token)
        payload = device.decode(payload_encrypted)

        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            raise PayloadDecryptError()
        
        check_device = Device.objects.device_by_payload(payload)

        if device == check_device:
            return device, payload
        else:
            raise DeviceNotFound()


    @action(detail = False, methods = ['POST'], url_path = 'configuration/check')
    def configuration(self, request, *args, **kwargs):
        
        device, payload = self.check_device_by_payload(request)
        data = {'config_change': device.call_config, 'call_api': device.call_config_types}
        
        data = json.dumps(data)
        enc_data = device.encode_for_device(data, payload.get('public_key'))
        return Response(
            data = {'data': enc_data},
            status = status.HTTP_202_ACCEPTED
        )


    #MJ device is being created here.
    @action(detail = False, methods = ['POST'], url_path = 'auth/start')
    def start(self, request, *args, **kwargs):
        
        data = {
            "mac_address": request.data["mac_address"],
            "serial_number": request.data["serial_number"],
            "device_type": request.data["device_type"],
            "device_name": request.data["device_name"],
        }

        serializer = DeviceSerializer(data = data)
        if serializer.is_valid(raise_exception=True):
            instance = serializer.save() #MJ device is being created here.
            org = Organization.objects.get(name = request.user.org)

            if not OrganizationPlan.objects.filter(organization = org, is_plan_active = True).exists() and not request.user.is_owner:
                return Response({'error':"No active organization plan was found."}, status=status.HTTP_400_BAD_REQUEST)
            
            client_log(
                request, org, action = f"Started Authentication for device {instance.device_name}",
            )


        else:
            errors = serializer.errors
            try:
                for _, messages in errors.items():
                    for message in messages:
                        return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
            except:
                return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

        data = {'qr_code_token': serializer.data['qr_code_token']}

        return Response(data = data, status = status.HTTP_201_CREATED)


    @action(detail=False, methods = ['POST'], url_path = 'auth/check')
    def check(self, request, *args, **kwargs):
        if 'qr_code_token' not in request.data:
            raise BadRequest(message="QR Code Token Does Not exist")
        qr_code_token = request.data.get('qr_code_token')
        device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
        if device.is_authenticated and device.credentials_shared is False:  # and not device.credentials_shared:
            data = {
                'authentication_token': device.authentication_token,
                'authorization_token': device.authorization_token,
                'public_key': device.public_key_server
            }
            device.credentials_shared = True
            device.save()

            org = Organization.objects.get(name = request.user.org)
            client_log(
                request, org, action = f"Started Authentication check for device {device.device_name}"
            )


            return Response(data = data, status = status.HTTP_200_OK)
        else:
            # we need to add this 
            # device.delete()
            return Response(data = {'error': 'Not Authenticated'}, status=status.HTTP_403_FORBIDDEN)


    @action(detail=False, methods=['POST'])
    def encode(self, request, *args, **kwargs):
        # qr_code_token = request.data.get('qr_code_token')
        authorization_token = request.data.get('authentication_token')
        data = request.data.get('message')
        device = Device.objects.device_by_auth_token(authentication_token=authorization_token)
        d = device.encode(data)

        org = Organization.objects.get(name = request.user.org)
        client_log(
            request, org, action = f"Started encoding for device {device.device_name}"
        )


        return Response(data = {'payload': d}, status = status.HTTP_200_OK)



    @action(detail=False, methods=['POST'])
    def decode(self, request, *args, **kwargs):
        authorization_token = request.data.get('authentication_token')
        data = request.data.get('message')
        device = Device.objects.device_by_auth_token(authentication_token=authorization_token)
        d = device.decode_for_device(data, request.data.get('private_key'))

        org = Organization.objects.get(name = request.user.org)
        client_log(
            request, org, action = f"Started decoding for device {device.device_name}"
        )


        return Response(data={'payload': d}, status=status.HTTP_200_OK)

    @action(detail = False, methods = ['POST'], url_name = 'key-exchange', url_path='key-exchange')
    def exchange(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request)
        # if device:
        # if device.credentials_keyExchange is False:
        
        device.add_agent_public_key(payload.get('public_key'))
        data = json.dumps({'success': True})
            
        enc_data = device.encode_for_device(data, payload.get('public_key'))
            # device.credentials_keyExchange = True
            # device.save()

        org = Organization.objects.get(name = request.user.org)
        client_log(
            request, org, action = f"Exchanged keys for the device: {device.device_name}"
        )


        return Response(data={'data': enc_data},
                            status=status.HTTP_202_ACCEPTED)


    @action(detail=False, methods=['POST'], url_path='auth/reauth')
    def reauth(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request)
        # if device.authorization_token.__str__() == payload.get('authorization_token'):
        device.reauth()
        enc_data = device.encode_for_device(json.dumps({'success': True}))

        org = Organization.objects.get(name = request.user.org)
        client_log(
            request, org, action = f"Re-authenticated {device.device_name}"
        )


        return Response(data = {'data': enc_data}, status = status.HTTP_200_OK)
        

    @action(detail = False, methods = ['POST'])
    def details(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request)
        # if device.authorization_token.__str__() == payload.get('authorization_token'):
        serializer = DeviceSerializer(device)
        
        filtered_data = {
            "device_name": serializer.data["device_name"],
            "device_location": serializer.data["location"]["location_name"],
            "serial_number": serializer.data["serial_number"],
            "updated_on": datetime.now().strftime("%Y-%m-%d,%H:%M:%S")
        }

        data = json.dumps(filtered_data)
        enc_data = device.encode_for_device(data)
        return Response(data={'data': enc_data}, status=status.HTTP_200_OK)


    @action(detail=False, methods=['POST'], url_path='last-seen')
    def lastseen(self, request, *args, **kwargs):
        if 'authentication_token' not in request.data:
            raise BadRequest(message="Authentication token not Provided")
        authentication_token = request.data.get("authentication_token")
        device = Device.objects.device_by_auth_token(authentication_token=authentication_token)
        data = {
            "last_seen": device.last_seen
        }
        return Response(data=data, status=status.HTTP_204_NO_CONTENT)


    @action(detail=False, methods=['POST'], url_path='last-seen/update')
    def lastseen_update(self, request, *args, **kwargs):
        
        if 'authentication_token' not in request.data:
            raise BadRequest(message="Authentication token not Provided")
        
        authentication_token = request.data.get("authentication_token")
        device = Device.objects.device_by_auth_token(authentication_token=authentication_token)
        device.last_seen = datetime.now()
        device.save()

        return Response(data={
            "success": "last seen updated"
        }, status=status.HTTP_200_OK)


    @action(detail=False, methods=['POST'], url_path='services/log')
    def pushdata(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request=request)
        device.save_service_log(payload)
        data = json.dumps({'success': True})
        return Response({'data': device.encode_for_device(data)}, status=status.HTTP_200_OK)


    @action(detail=False, methods=['POST'], url_path='health')
    def health(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request=request)

        data = json.dumps(device.get_call_config())
        return Response({'data': device.encode_for_device(data)}, status=status.HTTP_200_OK)


    @action(detail=False, methods=['POST'], url_path='services/retrieve')
    def services(self, request, *args, **kwargs):
        device, payload = self.check_device_by_payload(request)

        data = json.dumps(self.serializer_class(device).data, cls=JSONEncoder)
        enc_data = device.encode_for_device(data)
        return Response(data={'data': enc_data}, status=status.HTTP_200_OK)
    

    def create(self, request, *args, **kwargs):
        pass

#################################### Master Registration Flow #######################################################################################################################

class MasterRegistrationAPIView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, MasterRegisterer]
    queryset = Device.objects.all()

    def list(self, request):
        orgs = Organization.objects.exclude(licence = 0)
        plans = OrganizationPlan.objects.filter(is_plan_active = True, organization__in = orgs)
        org_ids = [plan.organization.id for plan in plans if plan.device_limit != plan.utilized_limit]
        orgs = Organization.objects.filter(id__in = org_ids)
        serializer = MasterRegistrationOrganizationSerializer(orgs, many = True)
        return Response({'data':serializer.data}, status = status.HTTP_200_OK)


    def create(self, request):
        try:
            org = Organization.objects.get(id = request.data['org_id'])
            org_owner_account = org.user.filter(is_owner = True)[0]
        except:
            return Response({'error':'Organization does not exists.'}, status = status.HTTP_400_BAD_REQUEST)

        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        try:
            device = Device.objects.get(
                qr_code_token=request.data.get('qr_code_token')
            )
        except:
            return Response({'error':'Either the entered QR code is invalid or expired.'}, status = status.HTTP_400_BAD_REQUEST)
        org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        if not org_plans.exists():
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':'You need to activate or buy a subscription plan first.'}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)
        org_plan = org_plans.first()
        if org_plan.is_paused:
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
        
        org_plan.utilized_limit = self.queryset.filter(org = org, is_subscribed = True, soft_delete = False).count()
        org_plan.save()
        if org_plan.device_limit <= org_plan.utilized_limit:
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':"You have reached the maximum device limit for your plan."}, status = status.HTTP_400_BAD_REQUEST)

        noofdevice = Device.objects.filter(
            org=org, 
            soft_delete = False,
            is_subscribed = True
        )
        if device.org == None:
            if org_plan.device_limit > noofdevice.count():
                if 'qr_code_token' not in request.data:
                    raise BadRequest(message="QR Token not provided.")
                if 'location_id' not in request.data:
                    raise BadRequest(message="Location id not provided.")
                if 'code_version' not in request.data:
                    raise BadRequest(message='Code version is required.')
                desktop_code_version=Desktop_code_version.objects.all().order_by("-id").first()
                qr_code_token = request.data.get('qr_code_token')
                location_id = request.data.get('location_id')
                user_id = org_owner_account
                device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
                user_locations = Location.objects.location_by_user(org_owner_account)
                try:
                    location = user_locations.get(id=location_id)
                except Exception as e:
                    raise UnAuthorizedException()
                ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
                user_agent = request.user_agent
                if device.authenticate():
                    device.location = location
                    device.authenticated_by = user_id
                    device._user_agent = user_agent
                    device._ip = ip
                    device.org=(org)
                    device.is_online = False
                    device.soft_delete = False
                    device.is_subscribed = True
                    device.save()
                    org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                    org_plan.save()
                    
                    heading = "New device has been authenticated"
                    message = f"Has authenticated by {org_owner_account.get_full_name()}."

                    notifications = Notification.objects.filter(device = device).order_by("-id")
                    if notifications.exists():
                        notifications.delete()

                    notification = Notification.objects.create(
                        organization = org,
                        type = 4,
                        heading = heading,
                        message = message,
                        device = device,
                        location = location,
                        actor_user = org_owner_account,
                        role = "admin"
                    )

                    data = NotificationSerializer(notification).data
                    users = org.user.filter(is_active = True)
                    for user in users:
                        if user.has_perm('accounts.client_admin'):
                            SendNotification(message, user.id, "user_id", heading, data = data)


                    DeviceChangesLog.objects.create(
                        changed_by = org_owner_account.username,
                        title = f"Authenticated by {org_owner_account.get_full_name()}",
                        device_serial_no = device.serial_number,
                        organization = org,
                        device_id = str(device.id)
                    )

                    services = device.services.all().order_by("-id")
                    if services.count() > 1:
                        services = services.exclude(id = services.first().id)
                        for service in services:
                            ss = SubService.objects.filter(service = service)
                            ss.delete()
                        services.delete()

                    return Response(data={'message': 'Device registered successfully.'}, status=status.HTTP_200_OK)
                else:
                    raise QRCodeExpired()
            device.soft_delete = True
            device.is_subscribed = False
            device.save()            
            return Response({"error":"Number of device limit exceeded."}, status = status.HTTP_400_BAD_REQUEST)
        else:
            if 'qr_code_token' not in request.data:
                    raise BadRequest(message="QR Token not provided.")
            if 'location_id' not in request.data:
                raise BadRequest(message="Location Id not provided.")
            if 'code_version' not in request.data:
                raise BadRequest(message='OS version is required.')
            desktop_code_version=Desktop_code_version.objects.all().order_by("-id").first()
            qr_code_token = request.data.get('qr_code_token')
            location_id = request.data.get('location_id')
            user_id = org_owner_account
            device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
            user_locations = Location.objects.location_by_user(org_owner_account)
            try:
                location = user_locations.get(id=location_id)
            except Exception as e:
                raise UnAuthorizedException()
            ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
            user_agent = request.user_agent
            if device.org!=org:
                onlinedevice=DeviceOnlineStatus.objects.filter(device_id=device.id)
                onlinedevice.delete()
                devicelog = DeviceChangesLog.objects.filter(device_id = device.id)
                devicelog.delete()
            if device.authenticate():
                device.location = location
                device.authenticated_by = user_id
                device._user_agent = user_agent
                device._ip = ip
                device.org = (org)
                device.is_online = False
                device.soft_delete = False
                device.is_subscribed = True
                device.save()
                org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                org_plan.save()

                heading = "New device has been authenticated"
                message = f"Has authenticated by {org_owner_account.get_full_name()}."
                
                notifications = Notification.objects.filter(device = device).order_by("-id")
                if notifications.exists():
                    notifications.delete()
                
                notification = Notification.objects.create(
                    organization = org,
                    type = 4,
                    heading = heading,
                    message = message,
                    device = device,
                    location = location,
                    actor_user = org_owner_account,
                    role = "admin"
                )
                data = NotificationSerializer(notification).data

                users = org.user.filter(is_active = True)
                for user in users:
                    if user.has_perm('accounts.client_admin'):
                        SendNotification(message, user.id, "user_id", heading, data = data)
                
                DeviceChangesLog.objects.create(
                    changed_by = org_owner_account.username,
                    title = f"Authenticated by {org_owner_account.get_full_name()}",
                    device_serial_no = device.serial_number,
                    organization = org,
                    device_id = str(device.id)
                )

                services = device.services.all().order_by("-id")
                if services.count() > 1:
                    services = services.exclude(id = services.first().id)
                    for service in services:
                        ss = SubService.objects.filter(service = service)
                        ss.delete()
                    services.delete()

                return Response(data = {'message': 'Device registered successfully.'}, status=status.HTTP_200_OK)
            else:
                raise QRCodeExpired()


    # to add a new location if the new organization does not have any active location
    @action(detail=False, methods=['POST'], url_path='add-location')
    def add_location(self, request, *args, **kwargs):
        try:
            request_org = Organization.objects.get(id = request.data['org_id'])
            
            if can_avail_trial(request_org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(request_org) and not has_active_trial(request_org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            if request.user.has_perm('accounts.client_admin'):
                owner = request_org.user.filter(is_owner = True)[0]
                match = re.match("^[#.0-9a-zA-Z\s,-]+$", request.data["location_name"])
                if match is None:
                    return Response({'error':'Please enter a suitable location name.'}, status = status.HTTP_400_BAD_REQUEST)
                data = {
                    "location_name":request.data["location_name"],
                    "is_active":True,
                }
                
                serializer = LocationSerializer(data = data, partial = True)
                if serializer.is_valid():
                    if Location.objects.filter(location_name__iexact = request.data['location_name'].strip(), organization = request_org).exists():
                        return Response({"error":"Location with the same name exists for this organization."}, status = status.HTTP_400_BAD_REQUEST)
                    new_instance = Location.objects.create(
                        location_name = data['location_name'],
                        is_active = True
                    )
                    try:
                        new_instance.organization = request_org
                        new_instance.created_by = owner
                        new_instance.user.add(owner)
                    except Exception as e:
                        return Response({"error": str(e)}, status = status.HTTP_400_BAD_REQUEST)
                    
                    new_instance.save()

                    heading = "New location added"
                    message = f"{owner.get_full_name()} created {new_instance.location_name} location."
                    tag_name = "user_id"
                    data = LocationWebSerializer(new_instance).data
                    
                    notification = Notification.objects.create(
                        organization = request_org,
                        type = 3,
                        heading = heading,
                        message = message,
                        location = new_instance,
                        actor_user = request.user,
                        role = "admin"
                    )
                    notification_data = NotificationSerializer(notification).data
                    SendNotification(message, owner.id, tag_name, heading, notification_data)

                    return Response({"message":f"Location {new_instance.location_name} created successfully.", "data":{'location_name':new_instance.location_name, 'id':new_instance.id}}, status = status.HTTP_200_OK)
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)

####################################################################################################################################################################

@method_decorator(name='activate', decorator=device_crud(**DEVICE_DECORATORS.activate))
@method_decorator(name='deviceinfo', decorator=device_crud(**DEVICE_DECORATORS.deviceinfo))
class DeviceAuthenticationView(GenericViewSet):
    serializer_class = DeviceSerializer
    queryset = Device.objects.all()
    permission_classes = IsAuthenticated, FusionClient,
            
    @action(detail=False, methods=['POST'])
    def activate(self, request, *args, **kwargs):

        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        try:
            device = Device.objects.get(
                qr_code_token=request.data.get('qr_code_token')
            )
        except:
            return Response({'error':'Either the entered QR code is invalid or expired.'}, status = status.HTTP_400_BAD_REQUEST)
        org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        if not org_plans.exists():
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':'You need to activate or buy a subscription plan first.'}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)
        org_plan = org_plans.first()
        if org_plan.is_paused:
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
        
        org_plan.utilized_limit = self.queryset.filter(org = org, is_subscribed = True, soft_delete = False).count()
        org_plan.save()
        if org_plan.device_limit <= org_plan.utilized_limit:
            device.soft_delete = True
            device.is_subscribed = False
            device.save()
            return Response({'error':"You have reached the maximum device limit for your plan."}, status = status.HTTP_400_BAD_REQUEST)

        noofdevice = Device.objects.filter(
            org=org, 
            soft_delete = False,
            is_subscribed = True
        )
        if device.org == None:
            if org_plan.device_limit > noofdevice.count():
                if 'qr_code_token' not in request.data:
                    raise BadRequest(message="QR token not Provided.")
                if 'location_id' not in request.data:
                    raise BadRequest(message="Location id not Provided.")
                if 'code_version' not in request.data:
                    raise BadRequest(message='Code version is required.')
                desktop_code_version=Desktop_code_version.objects.all().order_by("-id").first()
                qr_code_token = request.data.get('qr_code_token')
                location_id = request.data.get('location_id')
                user_id = request.user
                device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
                user_locations = Location.objects.location_by_user(request.user)
                try:
                    location = user_locations.get(id=location_id)
                except Exception as e:
                    raise UnAuthorizedException()
                ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
                user_agent = request.user_agent
                if device.authenticate():
                    device.location = location
                    device.authenticated_by = user_id
                    device._user_agent = user_agent
                    device._ip = ip
                    device.org=(org)
                    device.is_online = False
                    device.soft_delete = False
                    device.is_subscribed = True
                    device.save()
                    org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                    org_plan.save()
                    
                    heading = "New device has been authenticated"
                    message = f"Has authenticated by {request.user.get_full_name()}."

                    notifications = Notification.objects.filter(device = device).order_by("-id")
                    if notifications.exists():
                        notifications.delete()

                    notification = Notification.objects.create(
                        organization = org,
                        type = 4,
                        heading = heading,
                        message = message,
                        device = device,
                        location = location,
                        actor_user = request.user,
                        role = "admin"
                    )

                    data = NotificationSerializer(notification).data
                    users = org.user.filter(is_active = True)
                    for user in users:
                        if user.has_perm('accounts.client_admin') and user != request.user:
                            SendNotification(message, user.id, "user_id", heading, data = data)


                    DeviceChangesLog.objects.create(
                        changed_by = request.user.username,
                        title = f"Authenticated by {request.user.get_full_name()}",
                        device_serial_no = device.serial_number,
                        organization = org,
                        device_id = str(device.id)
                    )

                    services = device.services.all().order_by("-id")
                    if services.count() > 1:
                        services = services.exclude(id = services.first().id)
                        for service in services:
                            ss = SubService.objects.filter(service = service)
                            ss.delete()
                        services.delete()

                    return Response(data={'message': 'Device registered successfully.'}, status=status.HTTP_200_OK)
                else:
                    raise QRCodeExpired()
            device.soft_delete = True
            device.is_subscribed = False
            device.save()            
            return Response({"error":"Number of device limit exceeded."}, status = status.HTTP_400_BAD_REQUEST)
        else:
            if 'qr_code_token' not in request.data:
                    raise BadRequest(message="QR token not provided.")
            if 'location_id' not in request.data:
                raise BadRequest(message="Location id not provided.")
            if 'code_version' not in request.data:
                raise BadRequest(message='OS version is required')
            desktop_code_version=Desktop_code_version.objects.all().order_by("-id").first()
            qr_code_token = request.data.get('qr_code_token')
            location_id = request.data.get('location_id')
            user_id = request.user
            device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
            user_locations = Location.objects.location_by_user(request.user)
            try:
                location = user_locations.get(id=location_id)
            except Exception as e:
                raise UnAuthorizedException()
            ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
            user_agent = request.user_agent
            if device.org!=org:
                onlinedevice=DeviceOnlineStatus.objects.filter(device_id=device.id)
                onlinedevice.delete()
                devicelog = DeviceChangesLog.objects.filter(device_id = device.id)
                devicelog.delete()
            if device.authenticate():
                device.location = location
                device.authenticated_by = user_id
                device._user_agent = user_agent
                device._ip = ip
                device.org = (org)
                device.is_online = False
                device.soft_delete = False
                device.is_subscribed = True
                device.save()
                org_plan.utilized_limit = Device.objects.filter(org = org, soft_delete = False, is_subscribed = True).count()
                org_plan.save()

                heading = "New device has been authenticated"
                message = f"Has authenticated by {request.user.get_full_name()}."
                
                notifications = Notification.objects.filter(device = device).order_by("-id")
                if notifications.exists():
                    notifications.delete()
                
                notification = Notification.objects.create(
                    organization = org,
                    type = 4,
                    heading = heading,
                    message = message,
                    device = device,
                    location = location,
                    actor_user = request.user,
                    role = "admin"
                )
                data = NotificationSerializer(notification).data

                users = org.user.filter(is_active = True)
                for user in users:
                    if user.has_perm('accounts.client_admin') and user != request.user:
                        SendNotification(message, user.id, "user_id", heading, data = data)
                
                DeviceChangesLog.objects.create(
                    changed_by = request.user.username,
                    title = f"Authenticated by {request.user.get_full_name()}",
                    device_serial_no = device.serial_number,
                    organization = org,
                    device_id = str(device.id)
                )

                services = device.services.all().order_by("-id")
                if services.count() > 1:
                    services = services.exclude(id = services.first().id)
                    for service in services:
                        ss = SubService.objects.filter(service = service)
                        ss.delete()
                    services.delete()

                return Response(data = {'message': 'Device registered successfully.'}, status=status.HTTP_200_OK)
            else:
                raise QRCodeExpired()
    
    @action(detail=False, methods=['POST'])
    def deviceinfo(self, request, *args, **kwargs):
        if 'qr_code_token' not in request.data:
            raise BadRequest(message="QR token not provided.")
        qr_code_token = request.data.get('qr_code_token')
        try:
            device = Device.objects.device_by_qr_code(qr_code_token=qr_code_token)
        except:
            return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        
        is_authenticated = False
        if device.is_authenticated and not device.soft_delete:
            is_authenticated = True
        
        data = {
            'device_type': device.device_type,
            'device_name': device.device_name,
            'mac_address': device.mac_address,
            'serial_number': device.serial_number,
            'is_authenticated': is_authenticated
        }
        return Response(data=data, status=status.HTTP_200_OK)
    

    @action(detail = False, methods = ['GET'], url_path='active-locations')
    def user_active_locations(self, request):
        organization = Organization.objects.get(name = request.user.org)
        qs = Location.objects.location_by_user(request.user).filter(organization = organization)
        if bool(request.query_params):
            query = request.query_params
            
            #search filter
            if 'search' in query and query['search'] != None:             
                qs = qs.filter(Q(location_name__istartswith = query['search']))
                
        serializer = DashboardUserLocationSerializer(qs, many = True)
        data = serializer.data
        if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
            return Response({"results":data}, status=status.HTTP_200_OK)
        return Response({"data":data}, status.HTTP_200_OK)                

    
class ClientDeviceServices(viewsets.ModelViewSet):
    serializer_class = ClientDeviceServicesSerializer
    permission_classes = IsAuthenticated, FusionClient

    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)

        org = Organization.objects.get(user = request.user)

        try:
            device = Device.objects.get(id = pk, soft_delete = False, org = org)
        except:
            return Response({"error":"Device does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        
        ### to handle multiple service creation
        qs = device.services.all().order_by("-id")
        if qs.count() > 1:
            qs = qs.exclude(qs = qs.first().id)
            for service in qs:
                ss = SubService.objects.filter(service = service)
                ss.delete()
            qs.delete()
            qs = device.services.all().order_by("-id")
        
        if bool(self.request.query_params):
            query = request.query_params
            if 'search' in query: 
                qs = qs.filter(name__istartswith = query['search']) 

        serializer = self.get_serializer(qs, many = True)

        if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
            return Response({"data":serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.data, status = status.HTTP_200_OK)
    
    
    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin"):

            org = Organization.objects.get(user = request.user)
            
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)

            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            try:
                service = Service.objects.get(id = pk, orgnization = org)
            except:
                return Response({"error":"Service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            devices = service.device_set.all()
            
            if not devices.exists():
                return Response({'error':'Device does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
            device = devices[0]
            
            if not device.is_active or not device.is_subscribed:
                return Response({'error':'Device is deactivated.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not device.is_subscribed:
                return Response({'error':'Device is not covered under subscription.'}, status = status.HTTP_400_BAD_REQUEST)


            if 'service_active' in request.data:
                if is_current_plan_paused(org):
                    return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                
                org_service = OrgnisationService.objects.filter(orginstion = org, Subscribed = True, name = service.name).first()
                if not org_service.service_active:
                    return Response({'error':'Organization service is deactivated.'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    service.service_active = request.data['service_active']
                    service.save()
                except:
                    return Response({'error':'Value must be of type boolean.'}, status=status.HTTP_400_BAD_REQUEST)
                sub_services = service.subservice_set.all()
                sub_services.update(is_active=request.data['service_active'])
                data = {
                    'service_change': False, # True when execute_now or crontime update
                    'device_details_change': False,
                    'reauthenticate': False,
                    'code_change': False,
                    'device_status_change':False, # when device status change we need to send it true
                    'service_status_change':True, # when service change send true
                }
                data = data
                device.call_config_types = data
                device.save()
                data = self.get_serializer(service).data
                return Response({"message":"Service updated successfully.", "data": data}, status=status.HTTP_200_OK)
            else:
                return Response({"error":"Pass 'service_active' to update activity status."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status=status.HTTP_403_FORBIDDEN)
    

    def destroy(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass
    

class ClientDeviceSubServices(viewsets.ModelViewSet):
    serializer_class = ClientDeviceSubServicesSerializer
    permission_classes = IsAuthenticated, FusionClient

    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value.'}, status=status.HTTP_400_BAD_REQUEST)
                
        org = Organization.objects.get(user = request.user)
        try:
            sub_service = SubService.objects.get(id = pk, organization = org)
        except:
            return Response({"error":"This sub-service does not exist."}, status = status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(sub_service)
        return Response(serializer.data, status = status.HTTP_200_OK)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value.'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin") or request.user.has_perm('accounts.client_user'):

            org = Organization.objects.get(user = request.user)
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            try:
                sub_service = SubService.objects.get(id = pk, organization = org)
                service=Service.objects.get(id=sub_service.service.id)
                device=Device.objects.get(services=service)
                if not device.is_subscribed:
                    return Response({'error':'Device is not covered under your subscription.'}, status=400)
                if not device.is_active:
                    return Response({'error':'Device is deactivated.'}, status=400)
            except:
                return Response({"error":"This sub-service does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            if not sub_service.service.service_active:
                return Response({"error":"Service is deactivated."}, status = status.HTTP_403_FORBIDDEN)
            if not 'is_active' in request.data:
                devices = Device.objects.filter(services = sub_service.service, soft_delete = False, is_subscribed = True)

                if request.user.has_perm('accounts.client_user'):
                    if devices.exists():
                        device = devices.first()
                        locations = Location.objects.filter(user = request.user, is_active = True)
                        if not device.location in locations:
                            return Response({"error":"You are not present at device's location."}, status=status.HTTP_400_BAD_REQUEST)
                        
                if "executionTime" in request.data:
                    cron_data = request.data["executionTime"]
                    request.data['raw_execution_period'] = json.dumps(cron_data)

                    devicelog=DeviceLog(
                        device_id=device.id,
                        organization=device.org,
                        changed_by=request.user.username,
                        service_name=sub_service.name,
                        device_serial_no=device.serial_number,
                        title=f'Execution time has been changed',
                        sentence = f'Execution time has been changed by {request.user.get_full_name()}'
                    )
                    devicelog.save()

                    request.data["execution_period"] = cron_converter(cron_data)

            elif 'is_active' in request.data:
                if is_current_plan_paused(org):
                    return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                
                if not request.user.has_perm("accounts.client_admin"):
                    return Response({"error":"You can not perform this action."}, status=status.HTTP_400_BAD_REQUEST)
                if not sub_service.service.service_active:
                    return Response({"error":"You can not activate the sub-service when the service is deactivated."}, status = status.HTTP_403_FORBIDDEN)
                
            data = {
                'service_change': True,
                'device_details_change': False,
                'reauthenticate': False,
                'code_change': False,
                'device_status_change':False, # when device status change we need to send it true
                'service_status_change':False,
            }
            data = data
            device.call_config_types = data
            device.save()
            serializer = self.get_serializer(instance = sub_service, data = request.data, partial = True)
            
            if serializer.is_valid():
                
                serializer.save()
                
                return Response({"message":"Updated the sub service successfully.", "data":serializer.data}, status = status.HTTP_200_OK)

            else:
                errors = serializer.errors
                try:
                    for _, messages in errors.items():
                        for message in messages:
                            return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    @action(methods=["GET"], detail=True, url_path="reset-to-default")
    def reset_to_default(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin") or request.user.has_perm('accounts.client_user'):

            org = Organization.objects.get(user = request.user)
            
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

            try:
                sub_service = SubService.objects.get(id = pk, organization = org)
            except:
                return Response({"error":"This sub-service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            
            devices = Device.objects.filter(org = org, services = sub_service.service, soft_delete = False, is_subscribed = True)
            if not devices.exists():
                return Response({'error':'This device is not covered under your subscription.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if request.user.has_perm('accounts.client_user'):
                if devices.exists():
                    device = devices.first()
                    locations = Location.objects.filter(user = request.user, is_active = True)
                    if not device.location in locations:
                        return Response({"error":"You are not present at device's location."}, status=status.HTTP_400_BAD_REQUEST)

            if not sub_service.service.service_active:
                return Response({"error":"Service is deactivated."}, status = status.HTTP_403_FORBIDDEN)
            
            org_sub_services = OrgnisationSubService.objects.filter(name = sub_service.name, orginstion = org, is_active = True)
            if org_sub_services.exists():
                org_sub_service = org_sub_services.first()
                sub_service.execution_period = org_sub_service.executionTime
                sub_service.raw_execution_period = org_sub_service.raw_executionTime
                device = sub_service.service.device_set.first()
                data = {
                    'service_change': True, # True when execute_now or crontime update
                    'device_details_change': False,
                    'reauthenticate': False,
                    'code_change': False,
                    'device_status_change':False, # when device status change we need to send it true
                    'service_status_change':False, # when service change send true
                }
                data = data
                device.call_config_types = data
                device.save()
                
                sub_service.save()
                serializer = self.get_serializer(sub_service)
                return Response({"message":"Sub-service execution time is now reset to default.", "data":serializer.data}, status=status.HTTP_200_OK)
            
            else:
                return Response({"error":"No active sub-service found."}, status = status.HTTP_400_BAD_REQUEST)
            
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    @action(methods=["GET"], detail = True, url_path="execute-now")
    def execute_now(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if request.user.has_perm("accounts.client_admin") or request.user.has_perm('accounts.client_user'):

                try:
                    sub_service = SubService.objects.get(id = pk)
                except:
                    return Response({"error":"This sub-service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
                
                devices = Device.objects.filter(services = sub_service.service, soft_delete = False, is_subscribed = True)

                if request.user.has_perm('accounts.client_user'):
                    if devices.exists():
                        device = devices.first()
                        locations = Location.objects.filter(user = request.user, is_active = True)
                        if not device.location in locations:
                            return Response({"error":"You are not present at device's location."}, status=status.HTTP_400_BAD_REQUEST)
                
                currtime=datetime.now(utc)
                subservice=SubService.objects.get(id=pk)
                if subservice.is_active == False:
                    return Response ({"error":"This sub-service is not active."},status=status.HTTP_400_BAD_REQUEST)
                # here is the code for the new one
                service = Service.objects.get(id=subservice.service.id)
                device = Device.objects.get(services=service)
                data = {
                    'service_change': True,
                    'device_details_change': False,
                    'reauthenticate': False,
                    'code_change': False,
                    'device_status_change':False,
                    'service_status_change':False,
                }
                data = data
                if service.service_active == True:
                    if subservice.next_manual_execution:
                        if currtime > subservice.next_manual_execution:
                            subservice.next_manual_execution = datetime.now(utc) + timedelta(hours=2)
                            subservice.save()
                            device.call_config_types=data
                            device.save()
                            devicelog=DeviceLog(
                                device_id=device.id,
                                organization=device.org,
                                changed_by=request.user.username,
                                service_name=subservice.name,
                                device_serial_no=device.serial_number,
                                title=f'Manual execution',
                                sentence = f'Manual execution by {request.user.get_full_name()}'
                            )
                            devicelog.save()
                            return Response({"message":"This sub service has been executed."})
                        if not request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                            return Response({"error":f'{subservice.next_manual_execution}'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
                        else:
                            try:
                                return Response({'error':f'You can manually execute this service after {(subservice.next_manual_execution - datetime.now()).seconds // 60} minutes.'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
                            except:
                                return Response({'error':f'You can manually execute this service after {(subservice.next_manual_execution - datetime.now(utc)).seconds // 60} minutes.'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

                    subservice.execute_now=True
                    subservice.next_manual_execution=datetime.now(utc)+timedelta(hours=2)
                    device.call_config_types=data
                    device.save()
                    devicelog=DeviceLog(
                        device_id=device.id,
                        organization=device.org,
                        changed_by=request.user.username,
                        service_name=subservice.name,
                        device_serial_no=device.serial_number,
                        title=f'Manual execution',
                        sentence = f'Manual execution by {request.user.get_full_name()}'
                    )
                    devicelog.save()
                    subservice.save()
                    return Response({"message":"This sub-service has been executed."})
                return Response ({"error":"Your service is not active"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as E:
            return Response({"error":str(E)},status=status.HTTP_400_BAD_REQUEST)
        

        # if request.user.has_perm("accounts.client_user"):

        if request.user.has_perm("accounts.client_admin") or request.user.has_perm('accounts.client_user'):
            try:
                org = Organization.objects.get(name = request.user.org)
                try:
                    sub_service = SubService.objects.get(id = pk)
                except:
                    return Response({"error":"This sub-service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
                
                devices = Device.objects.filter(services = sub_service.service, soft_delete = False, is_subscribed = True)

                if request.user.has_perm('accounts.client_user'):
                    if devices.exists():
                        device = devices.first()
                        locations = Location.objects.filter(user = request.user, is_active = True)
                        if not device.location in locations:
                            return Response({"error":"You are not present at device's location."}, status=status.HTTP_400_BAD_REQUEST)
                        
                                                    
                if not sub_service.service.service_active:
                    return Response({"error":"Service is deactivated."}, status = status.HTTP_403_FORBIDDEN)
                

                if sub_service.next_manual_execution is None:
                    sub_service.execute_now = True
                    try:
                        sub_service.next_manual_execution = datetime.now(utc) + timedelta(hours = 2)
                    except:
                        sub_service.next_manual_execution = datetime.now(utc) + timedelta(hours = 2)
                    device = sub_service.service.device_set.first()
                    data = {
                        'service_change': True, # True when execute_now or crontime update
                        'device_details_change': False,
                        'reauthenticate': False,
                        'code_change': False,
                        'device_status_change':False, # when device status change we need to send it true
                        'service_status_change':False, # when service change send true
                    }
                    data = data
                    device.call_config_types = data
                    device.save()
                    sub_service.save()

                    client_log(request, org, action = f"Manually executed the service {sub_service.name}.")
                    return Response({"message":"Manually executed the service."}, status.HTTP_200_OK)
                
                elif sub_service.next_manual_execution <= datetime.now(utc):
                    sub_service.execute_now = True
                    sub_service.next_manual_execution = datetime.now(utc) + timedelta(hours = 2)
                    device = sub_service.service.device_set.first()
                    data = {
                        'service_change': True, # True when execute_now or crontime update
                        'device_details_change': False,
                        'reauthenticate': False,
                        'code_change': False,
                        'device_status_change':False, # when device status change we need to send it true
                        'service_status_change':False, # when service change send true
                    }
                    data = data
                    device.call_config_types = data
                    device.save()
                    sub_service.save()

                    client_log(request, org, action = f"Manually executed the service {sub_service.name}.")
                    return Response({"message":"Manually executed the service."}, status.HTTP_200_OK)
                
                else:
                    if not request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                        return Response({"error":f'{subservice.next_manual_execution}'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
                    else:
                        return Response({'error':f'You can manually execute this service after {(subservice.next_manual_execution - datetime.now()).seconds // 60} minutes.'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)                
            except Exception as e:
                return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    def destroy(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass



################################### Device domain whitelisting ####################################################################################
class ClientDeviceWhitelistedDomain(viewsets.ModelViewSet):
    serializer_class = ClientDeviceWhitelistedDomainSerializer
    permission_classes = IsAuthenticated, FusionClient
    
    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        org = Organization.objects.get(name = request.user.org)
        try:
            sub_service = SubService.objects.get(id = pk, organization = org)
        except:
            return Response({"error":f"Sub service does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        try:
            device_domains = DeviceSubServiceWhiteListDomain.objects.filter(associated_to = sub_service)
            device_whitelist_serializer = self.get_serializer(device_domains, many = True)

            org_sub_service = OrgnisationSubService.objects.get(orginstion = org, name = sub_service.name)
            org_domains = OrgWhitelistDomain.objects.filter(associated_to = org_sub_service)
            org_whitelist_serializer = OrgWhitelistDomainSerializer(org_domains, many = True)

            response = {
                "org_whitelist":org_whitelist_serializer.data,
                "whitelist_domain":device_whitelist_serializer.data, 
            }
            
            return Response(response, status = status.HTTP_200_OK)  
        except Exception as e:
            return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)


    def create(self, request):
        if request.user.has_perm("accounts.client_admin"):


            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
 
            try:
                sub_service = SubService.objects.get(id = request.data['associated_to'])
            except:
                return Response({"error":"This sub-service does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            
            try:
                org_sub_service = OrgnisationSubService.objects.get(orginstion = org, name = sub_service.name)
            except:
                return Response({"error":"No organization service exists with this name."}, status = status.HTTP_400_BAD_REQUEST)
            
            if not OrgWhitelistDomain.objects.filter(associated_to = org_sub_service, url = request.data["url"]).exists():
                if not DeviceSubServiceWhiteListDomain.objects.filter(associated_to = sub_service, url = request.data["url"]).exists():

                    validate = URLValidator()
                    try:
                        validate(request.data["url"])
                    except ValidationError as e:
                        return Response({"error":"Please enter a valid URL."}, status = status.HTTP_400_BAD_REQUEST)
                    try:
                        whitelist_domain = DeviceSubServiceWhiteListDomain(
                            domain_name = request.data['domain_name'],
                            url = request.data["url"],
                            associated_to = sub_service,
                            org = org
                        )
                        whitelist_domain.save()
                        service=Service.objects.get(id=sub_service.service.id)
                        devices=service.get_devices()
                        device=Device.objects.get(id=devices[0].id)
                        data = {
                            'service_change':True,
                            'device_details_change': False,
                            'reauthenticate': False,
                            'code_change': False,
                            'device_status_change':False,
                            'service_status_change':False,
                            'code_version_change':False
                        }
                        data = data
                        device.call_config_types=data
                        device.save()
                        return Response({"message":"Whitelisted domain successfully."}, status = status.HTTP_200_OK)
                    except Exception as e:
                        return Response({"error":"Failed whitelisting the domain."}, status = status.HTTP_400_BAD_REQUEST)
                return Response({"error": "The entered domain is already whitlisted for this service."}, status = status.HTTP_400_BAD_REQUEST)
            return Response({"error":"This domain is already whitelisted under organization sub service."}, status = status.HTTP_403_FORBIDDEN)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin"):

            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
 
            try:
                domain = DeviceSubServiceWhiteListDomain.objects.get(id = pk)
                domain.delete()
                return Response({"message":"Removed domain from whitelist successfully."}, status = status.HTTP_200_OK)
            except:
                return Response({"message":f"Domain with id {pk} is not whitelisted."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        if request.user.has_perm("accounts.client_admin"):

            org = Organization.objects.get(user = request.user)
                
            if can_avail_trial(org):
                return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
            
            if not has_active_subscription(org) and not has_active_trial(org):
                return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)


            try:
                sub_service = SubService.objects.get(id = request.data['associated_to'])
            except:
                return Response({"error":f"This sub-service does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            
            if 'url' in request.data:
                validate = URLValidator()
                try:
                    validate(request.data["url"])
                except ValidationError as e:
                    return Response({"error":"Please enter a valid URL."}, status = status.HTTP_400_BAD_REQUEST)

            if not DeviceSubServiceWhiteListDomain.objects.filter(associated_to = sub_service, url = request.data["url"]).exclude(id = pk).exists():
                try:
                    domain = DeviceSubServiceWhiteListDomain.objects.get(id = pk)
                    serializer = self.get_serializer(instance = domain, data = request.data, partial = True)
                    if serializer.is_valid():
                        serializer.save()
                        return Response({"message":"Updated whitelisted domain successfully."}, status = status.HTTP_200_OK)

                    else:
                        errors = serializer.errors
                        try:
                            for _, messages in errors.items():
                                for message in messages:
                                    return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

                except:
                    return Response({"error":f"Domain with id {pk} does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            return Response({"error": "The entered domain is already whitlisted for this service."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


################################### Organization subservice domain whitelisting ####################################################################################

class ClientOrgWhitelistedDomain(viewsets.ModelViewSet):
    serializer_class = OrgWhitelistDomainSerializer
    permission_classes = IsAuthenticated, FusionClient

    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
 
        try:
            org_sub_service = OrgnisationSubService.objects.get(id = pk)
        except:
            return Response({"error":"Organization sub-service does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        org_whitelist = org_sub_service.orgwhitelistdomain_set.all()
        serializer = self.get_serializer(org_whitelist, many = True)
        return Response(serializer.data, status = status.HTTP_200_OK)
    
    def create(self, request):
        if request.user.has_perm("accounts.client_admin"):
            org = Organization.objects.get(name = request.user.org)
            org_sub_service = OrgnisationSubService.objects.get(id = request.data['associated_to'])

            if 'url' in request.data:
                validate = URLValidator()
                try:
                    validate(request.data["url"])
                except ValidationError as e:
                    return Response({"error":"Please enter a valid URL."}, status = status.HTTP_400_BAD_REQUEST)
                
            serializer = self.get_serializer(data = request.data)
            if not OrgWhitelistDomain.objects.filter(url = request.data['url'], domain_name = request.data['domain_name'], associated_to = org_sub_service).exists():
                if serializer.is_valid():
                    try:
                        serializer.save(org = org)
                        return Response({"message":"Domain whitelisted successfully."}, status = status.HTTP_200_OK)
                    except Exception as e:
                        return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"error":"This domain is already whitelisted for the sub-service."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized"}, status = status.HTTP_403_FORBIDDEN)
    

    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                

        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            try:
                obj = OrgWhitelistDomain.objects.get(id = pk)
                obj.delete()
                return Response({"message":"Domain removed from whitelist successfully."}, status = status.HTTP_200_OK)
            except:
                return Response({"error":"Domain does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized"}, status = status.HTTP_403_FORBIDDEN)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                

        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)
 
        if request.user.has_perm("accounts.client_admin"):
            try:
                obj = OrgWhitelistDomain.objects.get(id = pk)
                if 'url' in request.data:
                    validate = URLValidator()
                    try:
                        validate(request.data["url"])
                    except ValidationError as e:
                        return Response({"error":"Please enter a valid URL."}, status = status.HTTP_400_BAD_REQUEST)
                serializer = self.get_serializer(instance = obj, data = request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({"message":"Whitelist domain updated successfully."}, status = status.HTTP_200_OK)

                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

            except:
                return Response({"error":"Domain does not exist."}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized"}, status = status.HTTP_403_FORBIDDEN)
            

    
    # def list(self, request):
    #     try:
    #         sub_service = SubService.objects.get(id = request.data['sub_service_id'])
    #     except:
    #         return Response({'error':"This subservice does not exist."}, status = status.HTTP_400_BAD_REQUEST)
    #     org = Organization.objects.get(name = request.user.org)
    #     try:
    #         org_sub_service = OrgnisationSubService.objects.get(org = org, name = sub_service.name)
    #         org_white_list = OrgWhitelistDomain.objects.filter(org = org, associated_to = org_sub_service)
    #         serializer = self.get_serializer(org_white_list, )
    #     except:
    #         return Response({"error":"No related organization subservice found."}, status = status.HTTP_400_BAD_REQUEST)


############################# Organization Info #######################################################################################
# I think This is being used in admin flow 
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

class OrganizationView(viewsets.ModelViewSet):
    permission_classes = FusionClient, IsAuthenticated
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_serializer_class(self):
        if self.request.method == "GET":
            self.serializer_class = OrganizationSerializer
        elif self.request.method == "PUT":
            self.serializer_class = OrganizationUpdateSerializer

        return self.serializer_class

    def list(self, request):
        org = Organization.objects.get(name = request.user.org)
        return Response(self.get_serializer(org).data)


    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            org = Organization.objects.get(id = pk, is_active = True)
        except:
            return Response({"error":"This organization does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            
        if request.user.is_owner == True:
            try:
                serializer = self.get_serializer(instance = org, data = request.data, partial = True)
                if serializer.is_valid():
                    if "name" in request.data:
                        org_name = request.data['name']
                        users = org.user.all()
                        for user in users:
                            user.org = org_name
                            user.save()
                    instance = serializer.save()
                    if "zipcode" in request.data:
                        instance.zip = request.data["zipcode"]
                        instance.save()
 
                    client_log(request, org, "Updated organization details.")
                    data = OrganizationSerializer(instance, context = {'request':request}).data
                    return Response({"message":"Organization details updated successfully.", "data":data}, status = status.HTTP_200_OK)
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)
        return Response({"error":"Only organization owner can update this information."}, status = status.HTTP_403_FORBIDDEN)


    def destroy(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass


######################### Owner Profile View ############################################################################################
# I don't know where this will be used

class UserProfileView(viewsets.ModelViewSet):
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    permission_classes = IsAuthenticated, FusionClient #MJ added fusion client

    def get_object(self):
        return User.objects.get(id = self.request.user.id)
    
    def get_serializer_class(self):
        self.serializer_class = CurrentUserProfileSerializer
        if self.request.method == "GET":
            self.serializer_class = CurrentUserProfileSerializer
            if self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                self.serializer_class = CurrentUserMobileProfileSerializer
        
        elif self.request.method == "PUT":
            self.serializer_class = CurrentUserProfileUpdateSerializer
            if self.request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                self.serializer_class = CurrentUserMobileProfileSerializer

        return self.serializer_class

    def list(self, request):
        return Response(self.get_serializer(self.get_object()).data, status = 200)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
                
        if request.user.has_perm("accounts.client_admin"):
            try:
                serializer = self.get_serializer(
                    instance = request.user, 
                    data = request.data, 
                    partial = True,
                )
                if serializer.is_valid():
                    # if 'picture' in request.data:
                        # request.user.picture.delete(False)
                    instance = serializer.save()
                    client_log(request, org, "Updated the profile.")
                    data = CurrentUserMobileProfileSerializer(instance, context = {'request':request}).data
                    return Response({"message":"Profile Updated Successfully.", "data":data}, status = status.HTTP_200_OK)
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status = status.HTTP_400_BAD_REQUEST) 

            except Exception as e:
                return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = User.objects.get(id = pk)
        except:
            return Response({'error':'User does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user == user:
            try:
                serializer = self.get_serializer(
                    instance = request.user, 
                    data = request.data, 
                    partial = True,
                )
                if serializer.is_valid():
                    instance = serializer.save()
                    client_log(request, org, "Updated the profile.")
                    data = CurrentUserMobileProfileSerializer(instance, context = {'request':request}).data
                    return Response({"message":"Profile Updated Successfully.", "data":data}, status = status.HTTP_200_OK)
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status=status.HTTP_403_FORBIDDEN)
    

    def destroy(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass

    def retrieve(self, request, *args, **kwargs):
        pass
    

############################### Logs #####################################################################################################

class ClientLogListView(generics.RetrieveAPIView):
    permission_classes = IsAuthenticated, FusionClient
    queryset = LogModel.objects.filter(actor_type = "CL")
    serializer_class = ClientLogSerializer
    pagination_class = None


    def get(self, request, pk, *args, **kwargs):
        result = self.get_queryset().filter(actor_id = pk)
        serializer = ClientLogSerializer(result, many = True)
        data = serializer.data
        return Response({"data":data}, status=status.HTTP_200_OK)

    

class DeviceLogListView(generics.RetrieveAPIView):
    permission_classes = IsAuthenticated, FusionClient
    queryset = LogModel.objects.filter(actor_type = "DV")
    serializer_class = DeviceLogSerializer

    def get(self, request, pk, *args, **kwargs):
        result = self.get_queryset().filter(actor_id = pk)
        serializer = self.get_serializer(result, many = True)
        return Response(serializer.data, status = status.HTTP_200_OK)
 

# class SubServiceLogListView(generics.RetrieveAPIView):
#     permission_classes = IsAuthenticated, FusionClient
#     queryset = SubServiceLogModel.objects.all()
#     serializer_class = SubServiceLogSerializer

#     def get(self, request, pk, *args, **kwargs):
#         result = self.get_queryset().filter(actor_id = pk)
#         serializer = self.get_serializer(result, many = True)
#         return Response(serializer.data)


######################################### Organization Services #################################################################################
# from rest_framework.pagination import PageNumberPagination

class ClientOrganizationServices(viewsets.ModelViewSet):
    serializer_class = ClientOrganizationServicesSerializer
    permission_classes = IsAuthenticated, FusionClient

    def get_queryset(self):
        organization = Organization.objects.get(name = self.request.user.org)
        self.queryset = OrgnisationService.objects.filter(orginstion = organization)

        if bool(self.request.query_params):
            qs = self.queryset
            query = self.request.query_params
              
            #search filter
            if 'search' in query:                
                qs = qs.filter(Q(name__istartswith = query['search']))
                
            return qs

        return self.queryset  
    
    
    def list(self, request):
        try:
            result = self.get_queryset().order_by("-id")
            org = Organization.objects.get(user = request.user)
            org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
            subscription_flag = org_plans.exists()

            if not request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                paginator = StandardResultsSetPagination()
                page = paginator.paginate_queryset(result, request)
                if page is not None:
                    serializer = ClientOrganizationServicesSerializer(page, many = True)
                    return paginator.get_paginated_response(serializer.data, subscription_flag = subscription_flag)
            serializer = ClientOrganizationServicesSerializer(result, many = True)
            return Response(serializer.data, status = status.HTTP_200_OK)
            
        except:
            return Response({"error": UnAuthorizedException}, status = status.HTTP_403_FORBIDDEN)
        

    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        # try:
        org = Organization.objects.get(name = request.user.org)
        try:
            service = OrgnisationService.objects.get(id = pk, orginstion = org)
        except:
            return Response({'error':'Organization Service does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        query = request.query_params
        subservices = service.orgnisationsubservice_set.all()
        if 'search' in query:
            subservices = subservices.filter(name__icontains = query['search'])
        serializer = ClientOrganizationSubServicesSerializer(subservices, many = True)
        data = {
            "data":serializer.data,
            "count":subservices.count(),
            "service_name" : service.name
        }
        return Response(data, status=status.HTTP_200_OK)
        # except Exception as e:
        #     return Response({"error":str(e)}, status = status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)

        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if is_current_plan_paused(org):
            return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            org = Organization.objects.get(name = request.user.org)
            try:
                org_service = OrgnisationService.objects.get(id = pk, orginstion = org)
                is_active = request.data['service_active']

                if not isinstance(is_active, bool):
                    return Response({'error':'service_active must be a valid boolean value.'}, status=status.HTTP_400_BAD_REQUEST)
                
                new_status = "Activated" if is_active else "Deactivated"
                org_service.service_active = is_active
                org_service.save()

                org_subservices = OrgnisationSubService.objects.filter(service = org_service)
                org_subservices.update(is_active = is_active)

                # deactivating all the services with same name as organization service
                devices = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False)

                for device in devices:
                    service = device.services.filter(name = org_service.name).first()
                    service.service_active = is_active
                    service.save()
                    subservices = SubService.objects.filter(service = service)
                    
                    for ss in subservices:
                        ss.is_active = is_active
                        ss.save()
                    
                    data = {
                        'service_change': False, # True when execute_now or crontime update
                        'device_details_change': False,
                        'reauthenticate': False,
                        'code_change': False,
                        'device_status_change':True, # when device status change we need to send it true
                        'service_status_change':True, # when service change send true
                    }
                    data = data
                    device.call_config_types = data
                    device.save()

                client_log(request, org, f"{new_status} the service {org_service.name}")
                org_service = OrgnisationService.objects.get(id = pk, orginstion = org)
                org_service_data = ClientOrganizationServicesSerializer(org_service).data
                return Response({"message":f"{new_status} the service successfully.", "data":[org_service_data]}, status = status.HTTP_200_OK)

            except Exception as e:
                return Response({"error":"Organization Service does not exist."}, status = status.HTTP_403_FORBIDDEN)
        return Response({"error":"You are unauthorized"}, status = status.HTTP_403_FORBIDDEN)
    
    
    def create(self, request, *args, **kwargs):
        pass

    def destroy(self, request, *args, **kwargs):
        pass



class ClientOrganizationSubService(viewsets.ModelViewSet):
    serializer_class = ClientOrganizationSubServicesSerializer
    permission_classes = IsAuthenticated, FusionClient
    
    def get_queryset(self):
        org = Organization.objects.get(name = self.request.user.org)
        self.queryset = OrgnisationSubService.objects.filter(orginstion = org)

        return self.queryset
    
    def retrieve(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
                
        org = Organization.objects.get(name = request.user.org)
        try:
            subservice = OrgnisationSubService.objects.get(id = pk, orginstion = org)
        except:
            return Response({"error":"Sub-service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(subservice)
        return Response(serializer.data, status = status.HTTP_200_OK)
    

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            org = Organization.objects.get(name = request.user.org)
            try:
                subservice = OrgnisationSubService.objects.get(id = pk, orginstion = org)
            except:
                return Response({"error":"Sub-service does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            
            if "executionTime" not in request.data:
                return Response({'error':'Please pass the executionTime.'}, status=status.HTTP_400_BAD_REQUEST)
            
            cron_data = request.data["executionTime"]
            request.data["raw_executionTime"] = json.dumps(cron_data)
            request.data['executionTime'] = cron_converter(cron_data)
            


            serializer = self.get_serializer(instance = subservice, data = request.data, partial = True)
            devicelog=DeviceLog(
                organization = org,
                changed_by=request.user.username,
                service_name=subservice.name,
                title=f'Execution time has been changed',
                sentence = f'Execution time has been changed by {request.user.get_full_name()}'
            )
            devicelog.save()
            if serializer.is_valid():
                serializer.save()
                sub_services = SubService.objects.filter(organization = org, name = subservice.name)
                for s in sub_services:
                    s.execution_period = request.data['executionTime']
                    s.raw_execution_period = request.data["raw_executionTime"]
                    s.save()

                devices = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False)
                data = {
                    'service_change': True,
                    'device_details_change': False,
                    'reauthenticate': False,
                    'code_change': False,
                    'device_status_change':False, # when device status change we need to send it true
                    'service_status_change':False,
                }
                for d in devices:
                    d.call_config_types = data
                    d.save()

                return Response({"message":"The default execution time is updated successfully.", "data":[serializer.data]}, status = status.HTTP_200_OK)               
            else:
                errors = serializer.errors
                try:
                    for _, messages in errors.items():
                        for message in messages:
                            return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)
    
    
    def list(self, request, *args, **kwargs):
        pass

    def create(self, request, *args, **kwargs):
        pass

    def destroy(self, request, *args, **kwargs):
        pass


############################# Dashboard Analytics #####################################################################################################


class DeviceAnalyticsYearlyReport(APIView):
    permission_classes = IsAuthenticated, FusionClient

    def get(self, request):
        try:
            year = int(request.query_params.get('year'))
        except:
            year = datetime.now().year
        
        org = Organization.objects.get(name = request.user.org)
        device_data = DeviceAnalytics.objects.filter(reported_date__year = year, organization = org)
        devices = dict()
        devices['months'] = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        devices["active"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        devices["inactive"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        if device_data.exists():
            for data in device_data:
                devices['active'][data.reported_date.month - 1] = data.active_devices
                devices['inactive'][data.reported_date.month - 1] = data.inactive_devices

        current = datetime.now()
        if year == current.year:
            org_devices = Device.objects.filter(org = org, soft_delete = False)
            devices['active'][current.month - 1] = org_devices.filter(is_active = True).count()
            devices['inactive'][current.month - 1] = org_devices.filter(is_active = False).count()
        devices['year'] = year
        return Response(devices, status = status.HTTP_200_OK)
    

class UserAnalyticsYearlyReport(APIView):
    permission_classes = IsAuthenticated, FusionClient

    def get(self, request):
        try:
            year = int(request.query_params.get('year'))
        except:
            year = datetime.now().year
        
        org = Organization.objects.get(name = request.user.org)
        user_data = UserAnalytics.objects.filter(reported_date__year = year, organization = org)
        users = dict()
        users['months'] = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        users["active"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        users["inactive"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        if user_data.exists():
            for data in user_data:
                users['active'][data.reported_date.month - 1] = data.active_users
                users['inactive'][data.reported_date.month - 1] = data.inactive_users
        
        current = datetime.now()
        if year == current.year:
            org_users = User.objects.filter(org = org.name)
            users['active'][current.month - 1] = org_users.filter(is_active = True).count()
            users['inactive'][current.month - 1] = org_users.filter(is_active = False).count()
        users['year'] = year
        return Response(users, status = status.HTTP_200_OK)
    

############################## Invite APIs###############################################################################

class SendInvite(viewsets.ModelViewSet):
    serializer_class = DevicesTokenSerializer
    permission_classes = IsAuthenticated, FusionClient
    
    def get_queryset(self):
        self.queryset = DevicesToken.objects.filter(organisation = self.request.user.org)

        if bool(self.request.query_params):
            qs = self.queryset
            query = self.request.query_params

            if 'status' in query:
                invite_status = query.getlist('status')
                qs = qs.filter(invitation__in = invite_status)

            if 'search' in query:
                qs = qs.filter(assing_to_user__icontains = query['search'])

            return qs
        
        return self.queryset


    def create(self, request):
        
        org = Organization.objects.get(user = request.user)

        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        is_captcha_valid = False

        try:
            if request.META.get('HTTP_X_IS_MOBILE', None) == 'True':
                is_captcha_valid = True
            else:
                captcha_response = request.data.get('captcha', None)
                if not captcha_response:
                    return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

                captcha = ReCaptchaField()
                try:
                    if not captcha.clean(captcha_response):
                        return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        is_captcha_valid = True
                except:
                    return Response({'error': 'Captcha is invalid.'}, status=status.HTTP_400_BAD_REQUEST)


        except Exception as e:
            return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)


        if is_captcha_valid:
            if not request.user.has_perm("accounts.client_admin"):
                return Response({"error":"You are unauthorized."}, status=status.HTTP_400_BAD_REQUEST)
            
            org = Organization.objects.get(user = request.user)
            owners = User.objects.filter(org = request.user.org, is_owner = True)
            plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
            if plans.exists():
                plan = plans.first()
                if plan.is_paused:
                    return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                plan.utilized_limit = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False).count()
                plan.save()
                pending_counts = self.get_queryset().filter(invitation__iexact = "pending").count()
                if plan.device_limit <= (plan.utilized_limit + pending_counts):
                    return Response({
                            'error':'It looks like maximum device limit has been reached, please consider upgrading your plan.'
                        }, status = status.HTTP_400_BAD_REQUEST)
                
            if owners.exists():
                owner = owners.first()


            token = uuid.uuid4()

            try:
                loc = Location.objects.get(id = request.data["location"])
            except:
                return Response({"error":"Location does not exist."}, status = status.HTTP_400_BAD_REQUEST)
            
            try:
                registered = self.get_queryset().filter(assing_to_user = request.data["username"], invitation__in = ["Pending", "Expired"])
                if registered.exists():
                    return Response({'error':'User has not registered any device using the previous invitation.'}, status = status.HTTP_422_UNPROCESSABLE_ENTITY)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                expired = self.get_queryset().filter(assing_to_user = request.data["username"], invitation = "Expired")

                if expired.exists():
                    invite = expired[0]
                    data = {
                        "token":invite.token,
                        "invitation" : "Pending",
                        "token_expire_time" : datetime.now() + timedelta(days = request.data["token_expire_time"]),
                        "assing_by_user":owner.username,
                        "otp":generateOTP(),
                        "created_date": datetime.now().date(),
                        "otp_expire_time":datetime.now() + timedelta(minutes = 15),
                        "country_code":request.data['country_code'],
                        "phone_code":request.data['phone_code']
                    }
                    serializer = DevicesTokenSerializer(instance = invite, data = data, partial = True)

                pendings = self.get_queryset().filter(organisation = request.user.org, assing_to_user = request.data["username"], invitation = "Pending", location = loc.location_name)
                
                if pendings.exists():
                    return Response({'error':'User is already invited.'}, status=status.HTTP_400_BAD_REQUEST)

                else:
                    data = {
                        "token":str(token),
                        "location":loc.location_name,
                        "assing_to_user":request.data["username"].lower().strip(),
                        "assing_by_user":owner.username,
                        "phone_no":str(request.data["phone_no"]),
                        "organisation":request.user.org,
                        "otp":generateOTP(),
                        "invitation":"Pending",
                        "created_date": datetime.now().date(),
                        "token_expire_time":datetime.now() + timedelta(days = request.data["token_expire_time"]),
                        "expiration_period": int(request.data["token_expire_time"]),
                        "otp_expire_time":datetime.now() + timedelta(minutes = 15),
                        "country_code":request.data['country_code'],
                        "phone_code":request.data['phone_code']
                    }
                    serializer = DevicesTokenSerializer(data = data)

                if serializer.is_valid():
                    instance = serializer.save()
                    recipient_list = [request.data["username"]]

                    message = get_template("accounts/device_invite.html").render({
                        'owner_user': owner.username,
                        'invited_user': instance.assing_to_user,
                        'token': instance.token
                    })

                    subject = 'Invitation for device registration.'
                    send_otp_email_task(recipients=recipient_list, subject=subject, message=message)
                    return Response({"messsage":"Invitation sent successfully."}, status = status.HTTP_200_OK)
                
                else:
                    errors = serializer.errors
                    try:
                        for _, messages in errors.items():
                            for message in messages:
                                return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                    except:
                        return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)
            
            except Exception as e:
                return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        else:
            return Response({'error':'Captcha is invalid'}, status = status.HTTP_400_BAD_REQUEST)
        
    
    def list(self, request):
        try:
            invites = self.get_queryset().order_by("-id")
            
            serializer = self.get_serializer(invites, many = True)

            org = Organization.objects.get(user = request.user)
            org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)

            subscription_flag = org_plans.exists()
            if subscription_flag:
                plan = org_plans.first()
                plan.utilized_limit = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False).count()
                plan.save()
            # return Response({"data":serializer.data}, status=status.HTTP_200_OK)

            paginator = StandardResultsSetPagination()
            page = paginator.paginate_queryset(invites, request) 
            if page is not None:
                serializer = self.get_serializer(page, many = True)
                return paginator.get_paginated_response(serializer.data, subscription_flag = subscription_flag)


        except Exception as e:
            return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
        
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            try:
                try:
                    invite = DevicesToken.objects.get(id = pk, organisation = request.user.org)
                except:
                    return Response({'error':'Invitation does not exist.'}, status = status.HTTP_400_BAD_REQUEST)

                plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
                if plans.exists():
                    plan = plans.first()
                    if plan.is_paused:
                        return Response({'error':'Your plan is paused due to renewal failure.'}, status=status.HTTP_400_BAD_REQUEST)
                    plan.utilized_limit = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False).count()
                    plan.save()

                    pending_counts = self.get_queryset().filter(invitation__iexact = "pending").count()
                    if plan.device_limit <= (plan.utilized_limit + pending_counts):
                        return Response({
                                'error':'It looks like maximum device limit has been reached, please consider upgrading your plan.'
                            }, status = status.HTTP_400_BAD_REQUEST)

                owners = User.objects.filter(org = request.user.org, is_owner = True)
                if owners.exists():
                    owner = owners.first()
                if invite.invitation.lower() in ['expired', 'device register']:
                    request.data["token_expire_time"] = datetime.now() + timedelta(days = invite.expiration_period)
                    request.data["invitation"] = "Pending"
                    request.data["created_date"] = datetime.now().date()
                    request.data.update({"phone_code":invite.phone_code})
                    request.data.update({"country_code":invite.country_code})
                    request.data.update({"phone_no":invite.phone_no})
                    serializer = self.get_serializer(instance = invite, data = request.data, partial = True)
                    if serializer.is_valid():
                        instance = serializer.save()
                        recipient_list = [instance.assing_to_user]

                        message = get_template("accounts/device_invite.html").render({
                            'owner_user': owner.username,
                            'invited_user': instance.assing_to_user,
                            'token': instance.token
                        })
                        subject = 'Renewed invitation for device registration.'
                        send_otp_email_task(recipients=recipient_list, subject=subject, message=message)
                        data = self.get_serializer(invite).data
                        return Response({"messsage":"Re-invited successfully.", "data":data}, status = status.HTTP_200_OK)
                    else:
                        errors = serializer.errors
                        try:
                            for _, messages in errors.items():
                                for message in messages:
                                    return Response({"error":message}, status=status.HTTP_400_BAD_REQUEST)
                        except:
                            return Response({'error':errors}, status=status.HTTP_400_BAD_REQUEST)

                else:
                    return Response({"error":"You can not re-invite if the existing invite has not been expired."}, status=status.HTTP_400_BAD_REQUEST)
                return Response({"data":serializer.data}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error":str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error":"You are unauthorized"}, status=status.HTTP_403_FORBIDDEN) 
    

    def destroy(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        if not has_active_subscription(org) and not has_active_trial(org):
            return Response({'error':'Your subscription has expired, please consider buying a new one.'}, status = status.HTTP_400_BAD_REQUEST)

        if request.user.has_perm("accounts.client_admin"):
            invites = DevicesToken.objects.filter(id = pk, organisation = request.user.org)
            if invites.exists():
                invites[0].delete()
                return Response({"message":"Deleted the invitation successfully."}, status = status.HTTP_200_OK)
            else:
                return Response({"error":"Invitation does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error":"You are unauthorized."}, status = status.HTTP_403_FORBIDDEN)


    def retrieve(self, request, *args, **kwargs):
        pass


####################################################################################################################################################3

class DeviceOnline(viewsets.ViewSet):
    permission_classes = IsAuthenticated,FusionClient
    pagination_class = StandardResultsSetPagination
    
    def list(self,request,pk=None):
        device_id = request.query_params.get('device_id', None)
        mac_address = request.query_params.get('mac_address', None)

        if device_id and mac_address:
            queryset = DeviceOnlineStatus.objects.filter(device_id=device_id, mac_address=mac_address).order_by('-time')
            if queryset.exists():
                serilizer = DeviceOnlineStatusSerializer(queryset, many = True)
                return Response({"data":serilizer.data}, status=status.HTTP_200_OK)
        
        return Response({"data":[]}, status=status.HTTP_200_OK)

    
class DeviceLogView(viewsets.ViewSet):
    permission_classes = IsAuthenticated, FusionClient
    pagination_class = StandardResultsSetPagination

    def list(self,request,pk=None):
        try:
            device_id = request.query_params.get('device_id', None)
            service_name = request.query_params.get('subservice_name', None)
            current_user = request.query_params.get('user', None)
            year = request.query_params.get('year', None)
            day = request.query_params.get('day', None)
            queryset = None
            if device_id:
                org = Organization.objects.get(user = request.user)
                queryset = DeviceLog.objects.filter(device_id = device_id, organization = org.name).order_by('-time')                           
            else:
                return Response({'error':"Please provide a serial number."}, status = status.HTTP_400_BAD_REQUEST)
            
#            if current_user != "" or current_user is not None:
 #               queryset = queryset.filter(current_user = current_user)
            
            if day:
                today = datetime.today()
                today_with_time = datetime(
                    year=today.year,
                    month=today.month,
                    day=today.day,
                )
                if day == 'today':
                    queryset = queryset.filter(Q(time__gt = today_with_time))
                
                elif day == 'yesterday':
                    yesterday = today.date() - timedelta(days = 1)

                    yesterday_with_time = datetime(
                        year = yesterday.year, 
                        month = yesterday.month,
                        day = yesterday.day,
                    )
                    queryset = queryset.filter(Q(time__gt = yesterday_with_time) & Q(time__lt = today_with_time))

                elif day == "last-week":
                    week_before = today.date() - timedelta(days = 7)

                    week_before_time = datetime(
                        year = week_before.year,
                        month = week_before.month,
                        day = week_before.day,
                    )
                    queryset = queryset.filter(Q(time__gt = week_before_time) & Q(time__lt = today))
                
                else:
                    try:
                        date = datetime.strptime(day, '%y-%m-%d')
                    except:
                        return Response({'error':'Please enter valid date.'}, status = status.HTTP_400_BAD_REQUEST)
                    day_after = date + timedelta(days = 1)
                    queryset = queryset.filter(Q(time__gt = date) & Q(time__lt = day_after))

            if current_user != "" and current_user != None:
                queryset = queryset.filter(current_user__iexact = current_user)

            if service_name:
                
                queryset = queryset.filter(service_name__iexact = service_name.lower().strip())
                
                if year:
                    queryset = queryset.filter(time__year = year)
                    serilizer = DeviceLogSerializer(queryset,many=True)
                    data = serilizer.data
                    file_delete_count = [0] * 12
                    for item in data:
                        month = int(item["time"][5:7]) - 1

                        if item["file_deleted"]== None:
                            file_delete_count[month] += 0
                        if item["file_deleted"] != "":     
                            file_delete_count[month] += int(item["file_deleted"])

                    if service_name == "Web Cache Protection":
                        for i in range(len(file_delete_count)):
                            file_delete_count[i] = bytest_to_kb(file_delete_count[i])
                            
                    return Response({"data":file_delete_count, "type":service_file_type_map[service_name]}, status=status.HTTP_200_OK)
                 
                serilizer = DeviceLogSerializer(queryset,many=True)
                return Response({"data":serilizer.data, "type":service_file_type_map[service_name]}, status=status.HTTP_200_OK)         
            serilizer = DeviceLogSerializer(queryset, many = True)
            return Response({"data":serilizer.data}, status = status.HTTP_200_OK)
        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)
        

    @action(methods = ['GET'], detail=False, url_path = 'chart-data')
    def chart_data(self, request):
        try:
            device_id = request.query_params.get('device_id', None)
            service_name = request.query_params.get('subservice_name', None)
            year = request.query_params.get('year', None)


            if device_id:
                org = Organization.objects.get(user = request.user)
                queryset = DeviceLog.objects.filter(device_id = str(device_id), organization = org.name)                

            else:
                return Response({'error':"Please provide the device id."}, status = status.HTTP_400_BAD_REQUEST)

            if service_name:
                
                queryset = queryset.filter(service_name = service_name)
                
                if year:
                    file_counts = []

                    queryset = queryset.filter(time__year = year)
                    serilizer = DeviceLogSerializer(queryset, many=True)
                    data = serilizer.data
                    file_delete_count = [0] * 12
                    for item in data:
                        month = int(item["time"][5:7]) - 1
                        if item["file_deleted"]==None:
                            file_delete_count[month] += 0
                        if item["file_deleted"] != "":    
                            file_delete_count[month] += int(item["file_deleted"])
                    
                    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                    for i in range(0, 12):
                        file_counts.append({
                            'month': months[i],
                            'counts': bytest_to_kb(file_delete_count[i]) if service_name == "Web Cache Protection" else file_delete_count[i]
                        })
                    return Response({"data": file_counts, "type":service_file_type_map[service_name]}, status=status.HTTP_200_OK)
                else:
                    return Response({'error':'Please provide year.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error':'Please provide subservice_name.'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)


    @action(methods=['GET'], detail=False, url_path = 'device-users')
    def device_users(self, request):
        try:
            device_id = request.query_params.get('device_id', None)
            users = list()
            if device_id:
                org = Organization.objects.get(user = request.user)
                # queryset = DeviceLog.objects.filter(device_id = device_id, organization = org.name)
                
                # for log in queryset:
                #     users.append(log.current_user)
                # users = list(set(users))
                device_qs = Device.objects.filter(id = int(device_id), org = org)
                if not device_qs.exists():
                    return Response({'error':'Device not found.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    device = device_qs.first()
                
                users = []
                online_users = []
                online_queryset = DeviceOnlineStatus.objects.filter(device_id=device_id).order_by('-time')
                for user in online_queryset:
                    if user.online_user !=  "":
                        users.append(user.online_user)
                users = list(set(users))

                for user in users:
                    online_queryset = DeviceOnlineStatus.objects.filter(device_id=device_id, online_user = user).order_by('-time')
                    if online_queryset.exists():
                        try:
                            is_online = False if not device.is_online else True if online_queryset[0].time >= timezone.now() else False
                        except:
                            is_online = False if not device.is_online else True if online_queryset[0].time >= datetime.now() else False
                        if not device.is_active:
                            is_online = False                        
                        online_users.append({
                            'user':user,
                            'is_online': is_online,
                            'last_login': online_queryset[0].time
                        })

                online_users = sorted(online_users, key = lambda x:x['is_online'], reverse = True)

                # if online_queryset.exists():
                #     online_user = online_queryset.first()
                #     online_user_name = online_user.online_user

                        
                return Response({'users':online_users}, status=status.HTTP_200_OK)

            else:
                return Response({'error':"Please provide the device id."}, status = status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)

    
#############################################################################################################################################################

class ContactUs(APIView):

    def post(self, request):

        try:
            if not 'message' in request.data:
                return Response({'error':"Please provide message."}, status = status.HTTP_400_BAD_REQUEST)
            message = request.data['message']
            send_mail(
                from_email = settings.OTP_EMAIL,
                subject = "Enquiry",
                message = "from: " + request.user.username + '\nname: ' + request.user.get_full_name()+ "\nCompany name: " + request.user.org + "\n\nmessage: " + message,
                connection = otp_mail_connection,
                recipient_list = ['customer-support@fusiondatasecure.com']
                # recipient_list = ['jayeshmaiyani37@gmail.com']
            )
            return Response({"message":"Thank you for your time, we will contact you shortly."}, status = status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)



######################################################################################################################################################
class OrgSubServicesLogView(viewsets.ViewSet):
    permission_classes = IsAuthenticated, FusionClient
    pagination_class = StandardResultsSetPagination


    def list(self,request,pk=None):
        try:
            service_name = request.query_params.get('subservice_name', None)
            current_user = request.query_params.get('current_user', None)
            year = request.query_params.get('year', None)
            day = request.query_params.get('day', None)

            org = Organization.objects.get(user = request.user)
            if service_name is None:
                return Response({'error':'Please provide the name of sub-service.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                queryset = DeviceLog.objects.filter(organization = org.name, service_name__iexact = service_name.lower().strip()).order_by('-time')
            
            
            if day:
                today = datetime.today()
                today_with_time = datetime(
                    year=today.year, 
                    month=today.month,
                    day=today.day,
                )
                if day == 'today':
                    queryset = queryset.filter(Q(time__gt = today_with_time))
                
                elif day == 'yesterday':
                    yesterday = today.date() - timedelta(days = 1)

                    yesterday_with_time = datetime(
                        year = yesterday.year, 
                        month = yesterday.month,
                        day = yesterday.day,
                    )
                    queryset = queryset.filter(Q(time__gt = yesterday_with_time) & Q(time__lt = today_with_time))

                elif day == "last-week":
                    week_before = today.date() - timedelta(days = 7)

                    week_before_time = datetime(
                        year = week_before.year, 
                        month = week_before.month,
                        day = week_before.day,
                    )
                    queryset = queryset.filter(Q(time__gt = week_before_time) & Q(time__lt = today))

                else:
                    try:
                        date = datetime.strptime(day, '%y-%m-%d')
                    except:
                        return Response({'error':'Please enter valid date.'}, status = status.HTTP_400_BAD_REQUEST)
                    day_after = date + timedelta(days = 1)
                    queryset = queryset.filter(Q(time__gt = date) & Q(time__lt = day_after))

                
            if year:
                queryset = queryset.filter(time__year = year)
                serilizer = DeviceLogSerializer(queryset, many=True)
                data = serilizer.data
                file_delete_count = [0] * 12
                for item in data:
                    month = int(item["time"][5:7]) - 1

                    if item["file_deleted"]==None:
                        file_delete_count[month] += 0
                    if item["file_deleted"] != "":     
                        file_delete_count[month] += int(item["file_deleted"])
                if service_name == "Web Cache Protection":
                    for i in range(12):
                        file_delete_count[i] = bytest_to_kb(file_delete_count[i])
                return Response({"data":file_delete_count, "type":service_file_type_map[service_name]}, status=status.HTTP_200_OK)
                
            
            if current_user:
                queryset=queryset.filter(current_user = current_user)
                serilizer=DeviceLogSerializer(queryset, many = True)
                return Response({"data":serilizer.data}, status = status.HTTP_200_OK)
            
            
            serilizer = DeviceLogSerializer(queryset, many = True)
            return Response({"data":serilizer.data}, status = status.HTTP_200_OK)
        except Exception as e:
            return Response({'error':str(e)}, status = status.HTTP_400_BAD_REQUEST)


# one-signal

import json
import requests

app_id = settings.ONESIGNAL_APP_ID
auth_key = settings.ONESIGNAL_AUTH_KEY

headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Authorization': f'Basic {auth_key}',
}

import json
import requests

app_id = settings.ONESIGNAL_APP_ID
auth_key = settings.ONESIGNAL_AUTH_KEY

headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Authorization': f'Basic {auth_key}',
}

def SendNotification(message, user_id, tag_name, heading = None, data = None):
    

    payload = {
        'app_id': app_id,
        'contents': {'en': f'{message}'},
        'headings': {'en': f'{heading}'},
        'data':data,
        'included_segments': ['All'],
        "filters": [
            {"field": "tag", "key": tag_name, "relation": "=", "value": user_id}
        ],
    }

    response = requests.post('https://onesignal.com/api/v1/notifications', headers=headers, data=json.dumps(payload))

    if response.ok:
       pass
    else:
        pass



#################################### Country/City/State ###########################################################################################################################

class CountryDataAPIView(APIView):


    def get(self, request):
        
        data = None
        abs_path = os.path.abspath('accounts/utils/countries.json')
        with open(abs_path, 'r') as file:
            data = json.load(file)

        
        if bool(self.request.query_params):
            query = self.request.query_params

            #role filter
            if "country" in query:
                country = query['country']

                abs_path = os.path.abspath('accounts/utils/states.json')
                with open(abs_path, 'r') as file:
                    data = json.load(file)
                    data = data.get(country, [])
                return Response({"data":data}, status = 200)


            elif "state" in query:
                state = query['state']

                abs_path = os.path.abspath('accounts/utils/cities.json')
                with open(abs_path, 'r') as file:
                    data = json.load(file)
                    data = data.get(state, [])

                return Response({"data":data}, status = 200)
            
        return Response({"data":data}, status = 200)

    # @action(methods = ['POST'], detail = False, url_path = 'contact-us')



################################# Notifications ##################################################################################

    
class NotificationAPIView(viewsets.ModelViewSet):
    
    queryset = Notification.objects.all()

    def list(self, request, *args, **kwargs):
        org = Organization.objects.get(user = request.user)
        qs = self.queryset.filter(organization = org).order_by('-timestamp')
        qs = qs.filter(Q(status = 'pending') | Q(status = None))
        for n in qs:
            if n.device:
                if n.device.soft_delete == True:
                    n.delete()
        ## retrieving notifications for 7 days only
        other_notifications = qs.filter(status = None)

        today = datetime.today()
        week_before = today.date() - timedelta(days = 7)

        week_before_time = datetime(
            year = week_before.year,
            month = week_before.month,
            day = week_before.day,
        )
        other_notifications = other_notifications.filter(Q(timestamp__gt = week_before_time))

        if request.user.is_owner:
            uninstall_requests = qs.filter(status="pending")
            uninstall_serializer = NotificationSerializer(uninstall_requests, many = True)
            serializer = NotificationSerializer(other_notifications, many = True)
            data = serializer.data
            uninstall_requests_data = list(uninstall_serializer.data)
            uninstall_requests_data.extend(list(data))
            return Response({'data':uninstall_requests_data, 'uninstall_requests':[]})
            

        elif request.user.has_perm('accounts.client_admin'):
            serializer = NotificationSerializer(other_notifications, many = True)

            return Response({'data':serializer.data})
        

        elif request.user.has_perm('accounts.client_user') or request.user.has_perm('accounts.client_reader'):
            queryset = Notification.objects.filter(organization = org, affected_user = request.user)
            serializer = NotificationSerializer(queryset, many = True)
            return Response({'data':serializer.data})

        else:
            return Response({'data':[]})
        
    
    def update(self, request, pk = id):
        if not pk.isnumeric():
            return Response({'error':'id must be a numeric value'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not request.user.is_owner:
            return Response({'error':'You are unauthorized.'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.get(user = request.user)
            
        if can_avail_trial(org):
            return Response({'error':'Please consider subscribing to one of our plans or trial.'}, status = status.HTTP_400_BAD_REQUEST)
        
        try:
            uninstall_request = Notification.objects.get(id = pk)
            if uninstall_request.type != 1:
                return Response({'error':"Access unauthorized."}, status=status.HTTP_400_BAD_REQUEST)
            if uninstall_request.type == 1 and uninstall_request.status.lower() != "pending":
                return Response({'error':"Access unauthorized."}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({'error':"Notification does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if request.user.is_owner:
                uninstall_status=request.data["status"]
                device = uninstall_request.device
                org = Organization.objects.get(user = request.user)
                
                if uninstall_status.lower() == 'accept':
                    device.soft_delete = True
                    device.is_active = False
                    device.is_subscribed = False
                    device.is_online = False
                    device.save()
                    uninstall_request.status=uninstall_status
                    uninstall_request.save()

                    DeviceChangesLog.objects.create(
                        changed_by = request.user.username,
                        title = f"Uninstall request accepted by {request.user.get_full_name()}",
                        device_serial_no = device.serial_number,
                        organization = org,
                        device_id = str(device.id)
                    )

                    device_notifications = Notification.objects.filter(device = device).exclude(id = uninstall_request.id)
                    for dn in device_notifications:
                        dn.delete()

                    services = device.services.all()
                    for service in services:
                        subservices=SubService.objects.filter(service=service)
                        subservices.delete()
                    service.delete()
                    device.services.remove(*device.services.all())

                    org_plan_qs = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
                    if org_plan_qs.exists():
                        org_plan = org_plan_qs.first()
                        org_plan.utilized_limit = Device.objects.filter(org = org, is_subscribed = True, soft_delete = False).count()
                        org_plan.save()

                    return Response({"message":"Status updated successfully"}, status=status.HTTP_200_OK)

                elif uninstall_status.lower() == 'reject':
                    uninstall_request.status=uninstall_status
                    uninstall_request.save()
                    DeviceChangesLog.objects.create(
                        changed_by = request.user.username,
                        title = f"Uninstall request rejected by {request.user.get_full_name()}",
                        device_serial_no = device.serial_number,
                        organization = org,
                        device_id = str(device.id)
                    )
                    return Response({"message":"Status updated successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({'error':'Invalid request.'}, status = status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error':'You are unauthorized.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error":str(e)},status=status.HTTP_400_BAD_REQUEST)

################################# Device Logs ################################################################################################################


class DeviceSpecificLog(APIView):
    def get(self, request, pk=None):
        try:
            device_id = request.query_params.get('device_id', None)
            devicelog = DeviceChangesLog.objects.filter(device_id = device_id, organization = request.user.org).order_by('-time')
            serializer = DeviceSpecificLogSerializer(devicelog, many = True)

            org = Organization.objects.get(user = request.user)
            device_qs = Device.objects.filter(id = int(device_id), org = org)
            if not device_qs.exists():
                return Response({'error':'Device not found.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                device = device_qs.first()
            
            users = []
            online_users = []
            online_queryset = DeviceOnlineStatus.objects.filter(device_id=device_id).order_by('-time')
            for user in online_queryset:
                if user.online_user !=  "":
                    users.append(user.online_user)

            users = list(set(users))

            for user in users:
                online_queryset = DeviceOnlineStatus.objects.filter(device_id=device_id, online_user = user).order_by('-time')
                if online_queryset.exists():
                    online_user = online_queryset.first()
                    try:
                        is_online = False if not device.is_online else True if online_user.time >= timezone.now() else False
                    except:
                        is_online = False if not device.is_online else True if online_user.time >= datetime.now() else False
                    if not device.is_active:
                        is_online = False
                    online_users.append({
                        'user':user,
                        'is_online': is_online,
                        'last_login': online_user.time
                    })
            online_users = sorted(online_users, key = lambda x:x['is_online'], reverse = True)
                        
            return Response({"data":serializer.data, 'users':online_users})
        except Exception as e:
            return Response({"error":str(e)},status = status.HTTP_400_BAD_REQUEST)


##############################################################################################################################################################