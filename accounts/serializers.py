from datetime import datetime
import json
import favicon
from django.utils import timezone
import functools, re
from django.forms import model_to_dict
from pytz import utc

from django.http import QueryDict
from django.db.models import Q
from rest_framework import serializers

from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.state import token_backend

from cron_descriptor import get_description
from .helpers import convert_size

from subscription.models import OrganizationPlan

from subscription.serializers import OrganizationPlanSerializer


from .models import *
from .exceptions import BadRequest, InsufficientDataException, UserNotMapedWithOrg
from .utils import generate_key
from accounts import exceptions

from captcha.fields import ReCaptchaField

from .socket_app import get_socketio_app


sio = get_socketio_app()
################################################### ReCAPTCHA #################################################################################################

class CaptchaSerializer(serializers.Serializer):
    # add the reCAPTCHA field to your serializer
    captcha = ReCaptchaField()


####################################################################################################################################################################
service_graph_map = {
    "Web Tracking Protecting": True,
    "Web Session Protection": True,
    "Web Cache Protection": True,
    "DNS Cache Protection": False,
    "Windows Registry Protection": True,
    "Free Storage Protection": False,
    "Trash Data Protection": True
}
##############################################################################################################################################################
# Capitalize Strings
class CapitalizeCharField(serializers.CharField):
    def to_internal_value(self, data):
        return super().to_internal_value(data.title())
    
    def to_representation(self, value):
        return super().to_representation(value.title())

#############################################################################################################################################################
class UserSerializer(serializers.ModelSerializer):

    picture = serializers.ImageField(required=False)
    username = serializers.EmailField()
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    class Meta:
        model = User

        fields = [
            "id", 
            "picture",
            "username", 
            'email',
            "first_name", 
            "profileupdateon", 
            "addresh", 
            "designation", 
            "created_on", 
            "gender", 
            "contact_number",
            'country_code',
            'phone_code',
            "last_name", 
            "created_by", 
            "is_active", 
            "date_joined", 
            "last_login",
            "city",
            "is_online",
            "state",
            "zipcode",
            "country",
            "org",
        ]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        country_code = attrs.get('country_code')
        phone_code = attrs.get('phone_code')
        country = attrs.get('country')
        if phone_code[0] != "+":
            raise serializers.ValidationError("Invalid phone code format.")
        
        if country_code is not None and phone_code is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for country in data:
                    if country["country_code"] == country_code and country["phone_code"] == phone_code:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country code did not match.")
            
        else:
            raise serializers.ValidationError("Please provide both country code and phone code.")
        
        country = attrs.get('country')
        if country is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for c in data:
                    if c["name"] == country:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country is invalid.")
            
            state = attrs.get('state')
            if state is not None and state != country:
                abs_path = os.path.abspath('accounts/utils/states.json')
                with open(abs_path, 'r') as file:
                    data = json.load(file)
                    states = data.get(country, None)
                    if state not in states:
                        raise serializers.ValidationError("State is invalid.")
                    
                    city = attrs.get('city')
                    if city is not None and city != state:
                        abs_path = os.path.abspath('accounts/utils/cities.json')
                        with open(abs_path, 'r') as file:
                            data = json.load(file)
                            cities = data.get(state, None)
                            if city not in cities:
                                raise serializers.ValidationError("City is invalid.")

        return attrs
    

    def validate_zipcode(self, value):
        if not value.isnumeric():
            raise serializers.ValidationError("Zipcode must be numeric.")
        length = len(value)
        if length < 5 or length > 10:
            raise serializers.ValidationError("Zipcode must be of 5 to 10 digits.")
        
        return value
        

    def validate_gender(self, value):
        if value.lower() not in ['male', 'female', 'prefer not to say']:
            raise serializers.ValidationError("Valid values of gender are 'Male', 'Female', and 'Prefer not to say'.")
        
        return value


    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only alphabetic characters.")
        
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only alphabetic characters.")
        
        return value
    
    def validate_addresh(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Address must be at least 10 characters long.")
        
        match = re.match('^[#.0-9a-zA-Z\s,-]+$', value)
        if match is None:
            raise serializers.ValidationError("Address can only be an alphanumeric value.")
        
        return value
        
    
    def validate_contact_number(self, value):
        if len(value) < 10 or not value.isdigit() or len(value) > 12:
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
        
        return value

    def to_representation(self, instance):
        rep = super(UserSerializer,self).to_representation(instance)
        rep['org'] = instance.org
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep


##############################################################################################################################################


class BulkUserSerializer(serializers.ModelSerializer):

    picture = serializers.ImageField(required=False)
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()
    username = serializers.EmailField()

    class Meta:
        model = User

        fields = [
            "id", 
            "picture",
            "username", 
            'email',
            "first_name", 
            "addresh", 
            "designation", 
            "gender",
            "contact_number",
            'country_code',
            'phone_code',
            "last_name", 
            "created_by", 
            "is_active", 
            "zipcode",
            "org",
        ]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        country_code = attrs.get('country_code')
        phone_code = attrs.get('phone_code')
        if phone_code[0] != "+":
            raise serializers.ValidationError("Invalid phone code format.")
        
        if country_code is not None and phone_code is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for country in data:
                    if country["country_code"] == country_code.upper() and country["phone_code"] == phone_code:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country code did not match.")
            
        else:
            raise serializers.ValidationError("Please provide both country code and phone code.")
        
        return attrs
    

    def validate_zipcode(self, value):
        if not value.isalnum():
            raise serializers.ValidationError("Zipcode must be alphanumeric.")
        length = len(value)
        if length < 5 or length > 10:
            raise serializers.ValidationError("Zipcode must be of 5 to 10 digits.")
        
        return value
        

    def validate_gender(self, value):
        if value.lower() not in ['male', 'female', 'prefer not to say']:
            raise serializers.ValidationError("Valid values of gender are 'Male', 'Female', and 'Prefer not to say'.")
        
        return value


    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only alphabetic characters.")
        
        return value


    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only alphabetic characters.")
        
        return value
    

    def validate_addresh(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Address must be at least 10 characters long.")
        
        match = re.match('^[#.0-9a-zA-Z\s,-]+$', value)
        if match is None:
            raise serializers.ValidationError("Address can only be an alphanumeric value.")
        
        return value
        
    
    def validate_contact_number(self, value):
        if len(value) < 10 or not value.isdigit() or len(value) > 12:
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
        
        return value


    def to_representation(self, instance):
        rep = super(UserSerializer,self).to_representation(instance)
        rep['org'] = instance.org
        return rep


##############################################################################################################################################

# This serializer is only to be used for providing full list of users
class UserListSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    class Meta:
        model = User
        fields = ('id', 'full_name', 'first_name', 'last_name', 'picture', 'is_active')



################################################## User Profile ##############################################################################
class CurrentUserProfileSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required=False)
    role = serializers.SerializerMethodField()
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()
    # created_by = serializers.CharField(source = 'created_by.get_full_name')
    class Meta:
        model = User
        fields = [
            "id", 
            'username',
            'first_name',
            "last_name",
            "full_name",
            'contact_number',
            'country_code',
            'phone_code',
            "gender",
            "created_on",
            "designation", 
            "last_login", 
            "picture",
            'org',
            'is_owner',
            'role',
            "is_online",
        ]

    def get_role(self, obj):
        if obj.is_owner:
            return "Administrator Owner"
        elif obj.has_perm('accounts.client_admin'):
            return 'Client Administrator'
        elif obj.has_perm('accounts.client_user'):
            return 'Client User'
        else:
            return 'Client Reader'


    def to_representation(self, instance):
        rep = super(CurrentUserProfileSerializer, self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep


class CurrentUserMobileProfileSerializer(serializers.ModelSerializer):
    locations = serializers.SerializerMethodField()
    picture = serializers.ImageField(required=False)
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    created_on = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()
    # created_by = serializers.CharField(source = 'created_by.get_full_name')
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'first_name',
            "last_name",
            "full_name",
            'contact_number',
            'country_code',
            'phone_code',
            "gender",
            "created_on", 
            "picture",
            "is_online",
            "locations"
        ]
        read_only_fields = [
            'id',
            'username',
            "created_on",
            "is_online",
        ]

    
    def validate(self, attrs):
        attrs = super().validate(attrs)
        country_code = attrs.get('country_code')
        phone_code = attrs.get('phone_code')
        if phone_code[0] != "+":
            raise serializers.ValidationError("Invalid phone code format.")
        
        if country_code is not None and phone_code is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for country in data:
                    if country["country_code"] == country_code and country["phone_code"] == phone_code:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country code did not match.")
            
        else:
            raise serializers.ValidationError("Please provide both country code and phone code.")
        
        return attrs


    def validate_gender(self, value):
        if value.lower() not in ['male', 'female', 'prefer not to say']:
            raise serializers.ValidationError("Valid values of gender are 'Male', 'Female', and 'Prefer not to say'.")
        
        return value
    

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only alphabetic characters.")
        
        return value
    

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only alphabetic characters.")
        
        return value

    def validate_contact_number(self, value):
        if len(value) < 10 or not value.isdigit():
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
        
        return value
    
    def validate_picture(self, value):
        request = self.context['request']
        if "picture" in request.data:
            s3 = S3Storage()
            if request.user.picture:
                s3.delete(request.user.picture.name)
        return value
        # try:
        # width, height = get_image_dimensions(value)
        # ext = value.name.split(".")[-1].upper()
        # max_width = 400
        # max_height = 400
        # img = Image.open(value)
        # if width > max_width or height > max_height:
        #     img.thumbnail((max_width, max_height), Image.ANTIALIAS)

        # buffer = BytesIO()

        # img.save(buffer, format = ext, optimize = True, quality = 70)

        # compressed_image = InMemoryUploadedFile(
        #     buffer,
        #     None,
        #     value.name,
        #     value.content_type,
        #     buffer.tell(),
        #     None
        # )

        # except:
        #     return value  

    def get_locations(self, obj):
        org = Organization.objects.get(name = obj.org)
        locs = Location.objects.filter(organization = org, user__in = [obj])
        locations = dict()
        locations["id"] = []
        locations["names"] = []
        for loc in locs:
            locations["id"].append(loc.id)
            locations["names"].append(loc.location_name)

        return locations

    def to_representation(self, instance):
        rep = super(CurrentUserMobileProfileSerializer, self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep



class CurrentUserProfileUpdateSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required = False, use_url = True)
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'full_name',
            'contact_number',
            'country_code',
            'phone_code',
            "gender", 
            "picture",
        ]
    
    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only alphabetic characters.")
        
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only alphabetic characters.")
        
        return value

    def validate_contact_number(self, value):
        if len(value) < 10 or not value.isdigit():
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
        
        return value
    
    def validate_picture(self, value):
        request = self.context['request']
        if "picture" in request.data:
            s3 = S3Storage()
            if request.user.picture:
                s3.delete(request.user.picture.name)
        return value
    
#################################### Organization profile ##############################################################################################

class MasterRegistrationOrganizationSerializer(serializers.ModelSerializer):
    plan_limit = serializers.SerializerMethodField()
    remaining_limit = serializers.SerializerMethodField()
    active_locations = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'plan_limit', 'remaining_limit', 'active_locations']

    def get_plan_limit(self, instance):
        org_plan = OrganizationPlan.objects.filter(organization = instance, is_plan_active = True).order_by('-id')
        if org_plan.exists():
            return org_plan[0].device_limit
        return 0
    
    def get_remaining_limit(self, instance):
        org_plan = OrganizationPlan.objects.filter(organization = instance, is_plan_active = True).order_by('-id')
        if org_plan.exists():
            return org_plan[0].device_limit - org_plan[0].utilized_limit
        return 0
    
    def get_active_locations(self, instance):
        locations = Location.objects.filter(organization = instance, is_active = True)
        serializer = DashboardUserLocationSerializer(locations, many = True)
        return serializer.data


class OrganizationSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required=False)

    company_email = serializers.CharField(read_only = True)
    organisation_type = CapitalizeCharField()
    class Meta:
        model = Organization
        fields = [
            "id", 'name', "picture", "organisation_type", 
            "size_of_company", "licence", "company_phone", 
            "city", "state", "zip", "country",
            "company_address", "company_email", "created_date", 
            'country_code', 'phone_code'
        ]
        read_only_fields = ["company_email", 'name', 'id', "licence", "created_date"]


    def to_representation(self, obj):
        rep = super(OrganizationSerializer, self).to_representation(obj)
        user = User.objects.get(org = obj.name, is_owner = True)
        rep['owner'] = user.get_full_name() 
        if not user.phone_code is None:
            rep['owner_phone'] = user.phone_code + " " + user.contact_number
        else:
            rep['owner_phone'] = user.contact_number
        rep['owner_email'] = user.username
        return rep
    
    
class OrganizationUpdateSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required=False)
    organisation_type = CapitalizeCharField()

    class Meta:
        model = Organization
        fields = [
            'name', "picture", "organisation_type", 
            "size_of_company", "company_phone", 
            "city", "state", "zip", "country",
            "company_address", 'country_code', 'phone_code'
        ]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        country_code = attrs.get('country_code', None)
        phone_code = attrs.get('phone_code', None)
        if phone_code is not None:
            if phone_code[0] != "+" and phone_code:
                raise serializers.ValidationError("Invalid phone code format.")
        
        if country_code is not None and phone_code is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for country in data:
                    if country["country_code"] == country_code and country["phone_code"] == phone_code:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country code did not match.")
            

        return attrs
    
    def validate_zip(self, value):
        if value is not None:
            if not value.isnumeric():
                raise serializers.ValidationError("Zipcode must be numeric.")
            length = len(value)
            if length < 5 or length > 10:
                raise serializers.ValidationError("Zipcode must be of 5 to 10 digits.")
        
        return value
    

    def validate_name(self, value):
        if value is not None:
            match = re.match('^[#.0-9a-zA-Z\s,-]+$', value)
            if match is None:
                raise serializers.ValidationError("Name can only be an alphanumeric value.")
        
        return value

    def validate_organisation_type(self, value):
        if value is not None:
            match = re.match("^[a-zA-Z ]*$", value)
            if match is None:
                raise serializers.ValidationError("Organization type must contain only alphabetic characters.")        
            
        return value
    
    def validate_company_address(self, value):
        if value is not None:
            if len(value) < 10:
                raise serializers.ValidationError("Address must be at least 10 characters long.")
            
            match = re.match('^[#.0-9a-zA-Z\s,-]+$', value)
            if match is None:
                raise serializers.ValidationError("Address can only be an alphanumeric value.")
        
        return value
    
    
    def validate_company_phone(self, value):
        if value is not None:
            if len(value) < 10 or not value.isdigit() or len(value) > 12:
                raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
            
            return value
    
    def validate_picture(self, value):
        request = self.context['request']
        if "picture" in request.data:
            s3 = S3Storage()
            org = Organization.objects.get(user = request.user)
            if org.picture:
                s3.delete(org.picture.name)
        return value       


##########################################################################################################################   

class DashboardUserLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['location_name', "id"]


class UserDashboardSerializer(serializers.ModelSerializer):
    # locs = serializers.ListField(child = DashboardUserLocationSerializer(allow_null = True))
    locations = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    picture = serializers.ImageField(required=False)
    role = serializers.SerializerMethodField()
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()
    class Meta:
        model = User
        fields = ["name", "id", "locations", "is_online", "is_active", "picture", "first_name", "last_name", 'role']
        read_only_fields = ["id", 'is_online']

    def get_name(self, obj):
        return obj.get_full_name()
    
    def get_role(self, obj):
        if obj.is_owner:
            return "Administrator Owner"
        elif obj.has_perm('accounts.client_admin'):
            return 'Client Administrator'
        elif obj.has_perm('accounts.client_user'):
            return 'Client User'
        else:
            return 'Client Reader'

    def get_locations(self, obj):
        org = Organization.objects.get(name = obj.org)
        locs = Location.objects.filter(organization = org, user__in = [obj])
        serializer = DashboardUserLocationSerializer(locs, many = True)
        return serializer.data
    
    def to_representation(self, instance):
        rep = super(UserDashboardSerializer,self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep 


    

class LocationSerializer(serializers.ModelSerializer):

    #MJ addded this to create a new field for showing total numbers of user working at this location
    # use this wisely as I am using on filtered queryset based on organization.
    # otherwise it can return aggregated counts for all the locations disregarding of the organization
    user_counts = serializers.IntegerField(
        source = 'user.count',
        read_only = True
    )

    #MJ to only show date as per the figma format
    created_date = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )

    device_counts = serializers.SerializerMethodField()#MJ to get device counts at current location

    # creator_name = serializers.CharField(source = "created_by.get_full_name")

    #MJ method to count device at current location
    def get_device_counts(self, obj):
        org = self.context.get("org")
        return Device.objects.device_by_org_location(org, obj).count()
    
    def validate_name(self, value):
        if value is not None:
            match = re.match('^[#.0-9a-zA-Z\s,-]+$', value)
            if match is None:
                raise serializers.ValidationError("Location name can only be an alphanumeric value.")
        
        return value.title()

    class Meta:
        model = Location
        fields = ['id', 
                  'location_name', 
                  'is_active', 
                  'created_date', 
                  'user_counts', 
                  'device_counts',
                ]
        read_only_fields = ['id', 'created_date', 'user_counts', 'device_counts',]



class LocationDetailSerializer(serializers.ModelSerializer):

    #MJ addded this to create a new field for showing total numbers of user working at this location
    # use this wisely as I am using on filtered queryset based on organization.
    # otherwise it can return aggregated counts for all the locations disregarding of the organization
    user_counts = serializers.IntegerField(
        source = 'user.count',
        read_only = True
    )

    #MJ to only show date as per the figma format
    created_date = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )

    device_counts = serializers.SerializerMethodField()#MJ to get device counts at current location

    # creator_name = serializers.CharField(source = "created_by.get_full_name")

    #MJ method to count device at current location
    def get_device_counts(self, obj):
        org = self.context.get("org")
        return Device.objects.device_by_org_location(org, obj).count()


    class Meta:
        model = Location
        fields = ['id', 
                  'location_name', 
                  'is_active', 
                  'created_date', 
                  'user_counts', 
                  'device_counts',
                ]
        read_only_fields = ['id', 'created_date']
        
    def to_representation(self, instance):
        rep = super(LocationDetailSerializer, self).to_representation(instance)
        try:
            users = instance.user.all()
            rep['users'] = UserDashboardSerializer(users, many = True).data
        except:
            rep['users'] = []
        try:
            rep['devices'] = ClientDeviceSerializer(Device.objects.filter(location = instance, soft_delete = False), many = True).data
        except:
            rep['devices'] = []
        return rep
    

class LocationMobileDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = Location
        fields = ['id']
        
    def to_representation(self, instance):
        rep = super(LocationMobileDetailSerializer, self).to_representation(instance)
        try:
            users = instance.user.all()
            rep['users'] = UserDashboardSerializer(users, many = True, context = {"request":self.context['request']}).data
        except:
            rep['users'] = []
        try:
            rep['devices'] = ClientDeviceSerializer(Device.objects.filter(location = instance, soft_delete = False), many = True).data
        except:
            rep['devices'] = []
        return rep


class LocationUserSerializer(serializers.ModelSerializer):

    name = serializers.CharField(source="get_full_name")
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    class Meta:
        model = User
        fields = ["name", "id", 'is_online', 'first_name', 'last_name']
        read_only_fields = ['id', 'is_online', 'name']

    def to_representation(self, instance):
        rep = super(LocationUserSerializer,self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep 


class LocationDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["id", "device_name"]
        read_only_fields = ['id', 'device_name']
    


class DeviceSerializer(serializers.ModelSerializer):
    def validate_empty_values(self, data):
        if isinstance(data, QueryDict):
            data = data.dict()
        fields = ['mac_address', 'serial_number', 'device_name', 'device_type',"code_version","os_version"]
        da = list(data.keys())
        if len(da) == 0:
            raise BadRequest()
        da.sort()
        fields.sort()
        if not (functools.reduce(lambda x, y: x and y, map(lambda p, q: p == q, da, fields), True)
                and len(da) == len(fields)):
            raise exceptions.InsufficientDataException()
        mac_address = data.get('mac_address')
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()):
            raise exceptions.BadRequest(message="Invalid MAC address")
        device_type = data.get('device_type')
        if isinstance(device_type, str):
            if device_type.isnumeric():
                device_type = int(device_type)
        if device_type not in [1,2]:
            raise exceptions.BadRequest(message="Invalid device type")
        data.update({'device_type': device_type})
        code_version = data.get('code_version')
        desktop_code_version=Desktop_code_version.objects.all().order_by("-id").first()
        if code_version != desktop_code_version.version:
            raise exceptions.BadRequest(message="Please update the code version")
        data.update({"code_version":code_version})
        return super(DeviceSerializer, self).validate_empty_values(data)
    def create(self, validated_data):
        # validated_data['qr_code_token'] = generate_key()
        try:
            device = Device.objects.get(
                Q(mac_address=validated_data.get('mac_address')) &
                Q(serial_number=validated_data.get('serial_number')))
            diff = (datetime.now(utc) - device.qr_code_generated_on).total_seconds() / 60.0
            if int(diff) > 10 or device.qr_code_token_used == True:
                device.qr_code_token = generate_key()
                device.updated_on = datetime.now()
                device.qr_code_generated_on = datetime.now()
                device.qr_code_token_used = False
                device.location = device.location
                device.code_version=validated_data.get('code_version')
                device.os_version=validated_data.get('os_version')
            validated_data = model_to_dict(device)
            validated_data['location'] = device.location
            validated_data['org'] = device.org
            validated_data['code_version'] = device.code_version
            validated_data['authenticated_by'] = device.authenticated_by
            validated_data['services'] = device.services.all()
            return super(DeviceSerializer, self).update(device, validated_data)
        except Device.DoesNotExist as e:
            validated_data['qr_code_token'] = generate_key()
            return super(DeviceSerializer, self).create(validated_data)
    class Meta:
        model = Device
        read_only_fields = ('qr_code_token',)
        depth = 1
        fields = '__all__'
        # fields = ('qr_code_token', 'serial_number', 'mac_address')
        # extra_kwargs = {
        #     'serial_number': {'write_only': True},
        #     'mac_address': {'write_only': True},
        # }


class LocationWebSerializer(serializers.ModelSerializer):

    #MJ addded this to create a new field for showing total numbers of user working at this location
    # use this wisely as I am using on filtered queryset based on organization.
    # otherwise it can return aggregated counts for all the locations disregarding of the organization
    user_counts = serializers.IntegerField(
        source = 'user.count',
        read_only = True
    )

    #MJ to only show date as per the figma format
    created_date = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )

    device_counts = serializers.SerializerMethodField()#MJ to get device counts at current location

    # creator_name = serializers.CharField(source = "created_by.get_full_name")

    #MJ method to count device at current location
    def get_device_counts(self, obj):
        org = self.context.get("org")
        return Device.objects.device_by_org_location(org, obj).count()

    class Meta:
        model = Location
        fields = ['id', 
                  'location_name', 
                  'is_active', 
                  'created_date', 
                  'user_counts', 
                  'device_counts',
                ]
        read_only_fields = ['id']
        
    def to_representation(self, instance):
        rep = super(LocationWebSerializer, self).to_representation(instance)
        try:
            users = instance.user.all()
            rep['users'] = LocationUserSerializer(users, many = True).data
        except:
            rep['users'] = []
        try:
            rep['devices'] = LocationDeviceSerializer(Device.objects.filter(location = instance, soft_delete = False), many = True).data
        except:
            rep['devices'] = []
        return rep


# cleint srelizers:-
class ClientUserMobileSerializer(serializers.ModelSerializer):
    
    picture = serializers.ImageField(required = False)
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    location_data = serializers.SerializerMethodField()
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    def get_location_data(self, obj):
        data = dict()
        locs = Location.objects.filter(user = obj)
        data['counts'] = locs.count()
        data["locations"] = list()
        if locs.exists():
            for loc in locs:
                data["locations"].append([loc.id, loc.location_name])

        return data
    
        
    class Meta:
        model = User
        fields = [
            'id',
            "full_name", 
            'username',
            'picture',
            "is_online",
            'is_active',
            'location_data',
            'first_name',
            'last_name'
        ]
        read_only_fields = ['id', 'full_name', "is_online"]

    def to_representation(self, instance):
        rep = super(ClientUserMobileSerializer, self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep 



#MJ use this serializer for client Users ListView
class ClientUserSerializer(ClientUserMobileSerializer):
    full_name = serializers.CharField(source = "get_full_name", read_only=True)
    picture = serializers.ImageField(required=False)
    created_on = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )


    role = serializers.SerializerMethodField()
    device_counts = serializers.SerializerMethodField()
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    def get_role(self, obj):
        if obj.is_owner:
            return "Administrator Owner"
        elif obj.has_perm('accounts.client_admin'):
            return 'Client Administrator'
        elif obj.has_perm('accounts.client_user'):
            return 'Client User'
        else:
            return 'Client Reader'
    
    def get_device_counts(self, obj):
        return Device.objects.filter(authenticated_by = obj, soft_delete = False).count()
    
        
    class Meta:
        model = User
        fields = [
            'id',
            "first_name",
            "picture",
            "last_name",
            "full_name", 
            'username',
            'is_active',
            'created_on', 
            'location_data', 
            'device_counts', 
            'role', 
            'picture',
            'last_login',
            'is_online'
        ]
        read_only_fields = ['id', 'full_name', "is_online", "last_login"]

    def to_representation(self, instance):
        rep = super(ClientUserSerializer, self).to_representation(instance)
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()
        return rep 

    


    
#MJ this serializer is just for the Client User Profile data API
# mind the 's' after User and before Serializer
class ClientUserDetailSerializer(serializers.ModelSerializer):
    
    role = serializers.SerializerMethodField()
    device_info = serializers.SerializerMethodField()
    full_name = serializers.CharField(source = "get_full_name")
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    def get_role(self, obj):
        if obj.is_owner:
            return "Administrator Owner"
        elif obj.has_perm('accounts.client_admin'):
            return 'Client Administrator'
        elif obj.has_perm('accounts.client_user'):
            return 'Client User'
        else:
            return 'Client Reader'
        

       
    def get_device_info(self, obj):
        # return DeviceDashboardSerializer(Device.objects.filter(authenticated_by = obj, soft_delete = False), many = True).data
        return ClientDeviceSerializer(Device.objects.filter(authenticated_by = obj, soft_delete = False), many = True).data
    
        
    class Meta:
        model = User
        fields = [
            'id', 
            "full_name",
            "first_name",
            "last_name",
            "email",
            'username',
            'picture',
            'contact_number',
            'country_code',
            'phone_code',
            'gender', 
            'created_on', 
            'city', 
            'state',
            'zipcode', 
            'country', 
            'addresh', 
            'org',
            'designation', 
            'role', 
            'last_login', 
            'is_active', 
            'device_info',
            "is_online",
        ]
        read_only_fields = ["id", "email", "username", 'created_on', 'org', 'is_online']


    def to_representation(self, instance):
        rep = super(ClientUserDetailSerializer, self).to_representation(instance)   
        locations = instance.location_set.all()
        rep['location_counts'] = locations.count()
        if not instance.is_active:
            rep['is_online'] = False
            instance.is_online = False
            instance.save()

        if rep["picture"]:
            rep['picture'] = rep['picture']
        if locations.exists():
            rep['locations'] = DashboardUserLocationSerializer(locations, many = True).data
            return rep
        rep['locations'] = []

        return rep



#MJ use it for updating client user profile only
class ClientUserUpdateSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required=False)
    first_name = CapitalizeCharField()
    last_name = CapitalizeCharField()

    class Meta:
        model = User
        fields = [
            "first_name",
            "picture",
            "last_name",
            'country_code',
            'phone_code',
            "contact_number",
            "designation",
            "gender",
            "addresh",
            "city",
            "state",
            "zipcode",
            "country",
        ]

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only alphabetic characters.")
        
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only alphabetic characters.")
        
        return value
    
    def validate_addresh(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Address must be at least 10 characters long.")
        
        return value
    
    def validate_contact_number(self, value):
        if len(value) < 10 or not value.isdigit():
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")
        
        return value


#MJ can be used on dasboard device details + user profile device detail
class DeviceDashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["id", "device_name", "mac_address", "device_type", "is_active", 'last_online_time', 'is_online']

    def to_representation(self, instance):
        rep = super(DeviceDashboardSerializer, self).to_representation(instance)   
        if not instance.is_active:
            rep['is_online'] = False

        return rep

    

device_types = {
    "1" : "Windows",
    "2" : "Mac",
    "3" : "Android",
    "4" : "iPhone"
}

class ClientDeviceSerializer(serializers.ModelSerializer):

    auth_person = serializers.CharField(source = "authenticated_by.get_full_name")
    organization = serializers.CharField(source = "org.name")
    type = serializers.SerializerMethodField()
    created_on = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )
    re_authenticated_on = serializers.DateTimeField(
        read_only = True,
        format = "%b %d, %Y"
    )

    class Meta:
        model = Device
        fields = [
            "id", 
            "device_name", 
            'mac_address', 
            "serial_number", 
            "device_type", 
            "authenticated_by",
            "auth_person",
            "is_active", 
            "created_on",
            "re_authenticated_on",
            "location",
            "organization",
            "last_seen",
            "type",
            'last_online_time',
            'is_online'
        ]

    
    def to_representation(self, instance):
        rep = super(ClientDeviceSerializer,self).to_representation(instance)    
        rep['location_name'] = instance.location.location_name
        if instance.last_seen!=None:
            try:
                if instance.last_seen <= timezone.now():
                    instance.is_online = False
                    instance.save()
                    rep['is_online'] = False
                else:
                    rep['is_online'] = instance.is_online
            except:
                if instance.last_seen <= datetime.now():
                    instance.is_online = False
                    instance.save()
                    rep['is_online'] = False
                else:
                    rep['is_online'] = instance.is_online
            if not instance.is_active:
                rep['is_online'] = False
        return rep

    def get_type(self, instance):
        return device_types[instance.device_type]


#MJ Device Serializer   
class DeviceSerializer(serializers.ModelSerializer):

    def validate_empty_values(self, data):
        if isinstance(data, QueryDict):
            data = data.dict()
        fields = ['mac_address', 'serial_number', 'device_name', 'device_type']
        da = list(data.keys())
        if len(da) == 0:
            raise BadRequest()
        da.sort()
        fields.sort()
        if not (functools.reduce(lambda x, y: x and y, map(lambda p, q: p == q, da, fields), True)
                and len(da) == len(fields)):
            raise InsufficientDataException()
        mac_address = data.get('mac_address')
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()):
            raise BadRequest(message="Invalid MAC address.")

        device_type = data.get('device_type')
        if isinstance(device_type, str):
            if device_type.isnumeric():
                device_type = int(device_type)

        if device_type not in [1,2]:
            raise BadRequest(message = "Invalid device type.")
        data.update({'device_type': device_type})
        return super(DeviceSerializer, self).validate_empty_values(data)


    def create(self, validated_data):
        try:
            device = Device.objects.get(
                Q(mac_address=validated_data.get('mac_address')) &
                Q(serial_number=validated_data.get('serial_number')))

            diff = (datetime.now(utc) - device.qr_code_generated_on).total_seconds() / 60.0
            if int(diff) > 10 or device.qr_code_token_used == True:
                device.qr_code_token = generate_key()
                device.updated_on = datetime.now()
                device.qr_code_generated_on = datetime.now()
                device.qr_code_token_used = False
                # device.location = device.location
            validated_data = model_to_dict(device)
            validated_data['location'] = device.location
            validated_data['org'] = device.org
            validated_data['authenticated_by'] = device.authenticated_by
            validated_data['services'] = device.services.all()
            return super(DeviceSerializer, self).update(device, validated_data)
        except Device.DoesNotExist as e:
            validated_data['qr_code_token'] = generate_key()
            return super(DeviceSerializer, self).create(validated_data)


    class Meta:
        model = Device
        read_only_fields = ('qr_code_token',)
        depth = 1
        fields = '__all__'





############################# Device Service and Subservices ############################################################################################################
class ClientDeviceSubServicesSerializer(serializers.ModelSerializer):

    class Meta:
        model = SubService

        fields = [
            'id', 'name', 'is_active', 'execution_period', 
            'last_execution', 'next_execution', "execute_now", 
            "next_manual_execution", "raw_execution_period"
        ]
        ordering = ["-id"]

    def to_representation(self, instance):
        rep = super(ClientDeviceSubServicesSerializer, self).to_representation(instance)
        if instance.execution_period:
            try:
                data = instance.execution_period
                value = get_description(data)
                if len(value) == 11:
                    value = value + ", every day"
                value = value.replace('only on', 'every')
                value = value.replace('only in', 'every')
                if (value[-1:-10:-1])[-1:-10:-1] == 'the month':
                    value = value.replace('the month', 'every month')
                value = value.replace('the month, ', '')
                value = value.replace('on day 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, and 31', 'every day')
                value = value.replace('January, February, March, April, May, June, July, August, September, October, November, and December', 'month')
                value = value.replace("Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, and Saturday", 'day')
                value = value.replace("of every month", "")
                value = value.replace("every day, every month", "every day")


                rep['execution_period'] = value
            except:
                data = instance.execution_period
                # value = get_description(data)
                rep['execution_period'] = data

        if instance.name == "Web Session Protection":
            rep['needs_whitelisting'] = True
        else:
            rep['needs_whitelisting'] = False
        try:
            rep['needs_graph'] = service_graph_map[instance.name]
        except:
            rep['needs_graph'] = False

        device_qs = Device.objects.filter(services = instance.service)
        rep['device_id'] = None

        if instance.raw_execution_period is not None:
            try:
                rep["raw_execution_period"] = json.loads(instance.raw_execution_period)
            except:
                rep["raw_execution_period"] = instance.raw_execution_period

        if device_qs.exists():
            rep['device_id'] = device_qs.first().id
        return rep


class ClientDeviceServicesSerializer(serializers.ModelSerializer):
    """
    A serializer to get the data of device related services with their subservices.
    """
    subservices_data = serializers.SerializerMethodField()

    class Meta:
        model = Service
        fields = ['id', 'name', 'service_active', 'subservices_data']

    def get_subservices_data(self, instance):
        subservices = instance.subservice_set.all().order_by('-id')
        return ClientDeviceSubServicesSerializer(subservices, many = True).data


class OrgWhitelistDomainSerializer(serializers.ModelSerializer):
    """
    Use this serializer to list and update an existing orgwhitelisted domain.
    """
    favicon = serializers.SerializerMethodField()

    class Meta:
        model = OrgWhitelistDomain
        fields = [
            "id", "domain_name", "url", "associated_to", "favicon"
        ]
    
    def get_favicon(self, instance):
        try:
            icons = favicon.get(instance.url)
            return icons[0].url
        except:
            return ""


class ClientDeviceWhitelistedDomainSerializer(serializers.ModelSerializer):
    """
    Use this serializer to list and update an existing device whitelist domains.
    """

    favicon = serializers.SerializerMethodField()

    class Meta:
        model = DeviceSubServiceWhiteListDomain
        fields = [
            "id", "domain_name", "url", "associated_to", "favicon"
        ]

    def get_favicon(self, instance):
        try:
            icons = favicon.get(instance.url)
            return icons[0].url
        except:
            return ""



########################################################################################################################################

class SubServiceSerializer(serializers.ModelSerializer):
    sub_service_name = serializers.SerializerMethodField()
    sub_service_authorization_code = serializers.SerializerMethodField()
    sub_service_active = serializers.SerializerMethodField()

    def get_sub_service_name(self,instance):
        return instance.service_name

    def get_sub_service_authorization_code(self, instance):
        return instance.authorization_code

    def get_sub_service_active(self, instance):
        return instance.is_active

    class Meta:
        model = SubService
        fields = ['id', 'name', 'sub_service_name', 'sub_service_authorization_code',
                  'sub_service_active', 'execution_period','execute_now', 
                  "next_manual_execution"]
        read_only_fields = ('updated_time', 'updated_time')
        

class ServiceSerializer(serializers.ModelSerializer):

    service_count = serializers.SerializerMethodField()
    subservices = serializers.SerializerMethodField()
    service_name = serializers.SerializerMethodField()

    def get_service_name(self, instance):
        return instance.name

    def get_service_count(self, instance):
        return SubService.objects.filter(service=instance).count()

    def get_subservices(self, instance):
        return SubServiceSerializer(SubService.objects.filter(service=instance), many=True).data

    class Meta:
        model = Service
        fields = ['id','service_name', 'service_count', 'service_active', 'subservices', ]
        read_only_fields = ('updated_time', 'updated_time')


class DeviceServiceSerializer(serializers.ModelSerializer):
    services = ServiceSerializer(many=True)
    class Meta:
        model = Device
        fields = ['services']


# device in location:-
class LocationDevicesSerializer(serializers.ModelSerializer):
    class Meta:
        model=Device
        fields = [
            "id", "mac_address", "serial_number","location","org",
            "device_name", "device_type", "is_active", "authenticated_by", 
            "last_seen","created_on", "re_authenticated_on", 'last_online_time', 
            'is_online'
        ]

    def to_representation(self, instance):
        rep = super(LocationDevicesSerializer,self).to_representation(instance)
        rep['authenticated_by'] = instance.authenticated_by.username
        rep['location'] = instance.location.location_name
        rep['org'] = instance.org.name
        return rep


class TokenSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

        if Organization.objects.orgs_by_user(self.user).count() == 0:
            raise UserNotMapedWithOrg()
        
        refresh = self.get_token(self.user)
        org = Organization.objects.get(user = self.user)

        if self.user.has_perm('accounts.client_admin'):
            data['role'] =  'Administrator'
            if self.user.is_owner:
                data['role'] += " Owner"
        elif self.user.has_perm('accounts.client_user'):
            data['role'] = 'User'
        else:
            data['role'] = 'Reader'

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['type'] = str("client")
        data['user_id'] = self.user.id
        data['org_id'] = org.id
        data['org_name'] = org.name
        data['org_type'] = org.organisation_type.capitalize()
        data['username'] = self.user.username
        
        org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        if org_plans.exists():
            data['subscription_flag'] = True
            org_plan = org_plans.first()
            data['per_device_price'] = round(org_plan.price / org_plan.device_limit)
            data['plan_id'] = org_plan.subscription_plan.id
        else:
            data['subscription_flag'] = False
            data['per_device_price'] = None
            data['plan_id'] = 0
        
        if self.user.has_perm("accounts.master_client"):
            data['is_master_client'] = True
        else:
            data['is_master_client'] = False

        return data


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """
    Inherit from `TokenRefreshSerializer` and touch the database
    before re-issuing a new access token and ensure that the user
    exists and is active.
    """

    error_msg = 'No active account found with the given credentials'

    def validate(self, attrs):
        token_payload = token_backend.decode(attrs['refresh'])
        try:
            user = get_user_model().objects.get(pk=token_payload['user_id'])
            if not user.is_active:
                raise serializers.ValidationError(
                    'No active account found.'
            )
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError(
                'Account is deleted.'
            )

        return super().validate(attrs)


# class SubScriptionSerializer(serializers.ModelSerializer):

#     class Meta:
#         model = OrgSubscriptions
#         fields="__all__"

#     def to_representation(self, instance):
#         rep = super(SubScriptionSerializer, self).to_representation(instance)
#         rep['orginstion'] = instance.orginstion.name
#         return rep


class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ResetPasswordSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)
    class Meta:
        model = User
        fields = '__all__'
    def save(self):
        username = self.validated_data['username']
        password = self.validated_data['password']
    #filtering out whethere username is existing or not, if your username is existing then if condition will allow your username
        if User.objects.filter(username=username).exists():
            #if your username is existing get the query of your specific username
            user = User.objects.get(username=username)
            #then set the new password for your username
            user.set_password(password)
            user.save()
            return user
        else:
            raise serializers.ValidationError({'error': 'Please enter valid crendentials.'})
        
#################################### Services ##################################################################################################

class MasterSubServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = MasterSubSevice
        fields = "__all__"

class MasterServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model=MasterService
        fields=[
            'id',
            'name',
            'price',
        ]


from cron_converter import Cron

        
######################################################################################################################################
# class SubServiceLogSerializer(serializers.ModelSerializer):

#     date = serializers.DateTimeField(
#         source = 'timestamp',
#         read_only = True,
#         format = "%b %d, %Y"
#     )

#     time = serializers.DateTimeField(
#         source = 'timestamp',
#         read_only = True,
#         format = "%I:%M %p"
#     )

#     name = serializers.CharField(source = "user.get_full_name", default = None)
    
#     class Meta:
#         model = SubServiceLogModel
#         fields = [
#             "service" 
#             "action", 
#             "user",
#             "name",
#             "time",
#             "outcome",
#             "date",
#             # "is_info_log",
#             "org"
#         ]



class ClientLogSerializer(serializers.ModelSerializer):

    date = serializers.DateTimeField(
        source = 'timestamp',
        read_only = True,
        format = "%b %d, %Y"
    )

    time = serializers.DateTimeField(
        source = 'timestamp',
        read_only = True,
        format = "%I:%M %p"
    )

    name = serializers.CharField(source = "user.get_full_name", default = None)
    
    class Meta:
        model = LogModel
        fields = [
            "action", 
            "time",
            "date",
            "user",
            "name",
            "org",
            'timestamp'
        ]

########################################### Services #########################################################################################

class ClientOrganizationServicesSerializer(serializers.ModelSerializer):

    subservices_count = serializers.SerializerMethodField()
    class Meta:
        model = OrgnisationService
        fields = [
            "id",
            "name",
            "create_on",
            "created_time",
            "service_active",
            "subservices_count"
        ]

    def get_subservices_count(self, obj):
        subservices = obj.orgnisationsubservice_set.all()
        return subservices.count()
    

class ClientOrganizationSubServicesSerializer(serializers.ModelSerializer):
    name = serializers.CharField(read_only = True)
    service_name = serializers.CharField(source = "service.name", read_only = True)
    service_id = serializers.IntegerField(source = "service.id", read_only = True)
    class Meta:
        model = OrgnisationSubService
        fields = [
            "id",
            "name",
            "executionTime",
            "service_id",
            "service_name",
            'created_date',
            'raw_executionTime'
        ]

    def to_representation(self, instance):
        rep = super(ClientOrganizationSubServicesSerializer, self).to_representation(instance)
        if instance.executionTime:
            try:
                data = instance.executionTime
                value = get_description(data)
                if len(value) == 11:
                    value = value + ", every day"
                value = value.replace('only on', 'every')
                value = value.replace('only in', 'every')
                if (value[-1:-10:-1])[-1:-10:-1] == 'the month':
                    value = value.replace('the month', 'every month')
                value = value.replace('the month, ', '')
                value = value.replace('on day 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, and 31', 'every day')
                value = value.replace('January, February, March, April, May, June, July, August, September, October, November, and December', 'month')
                value = value.replace("Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, and Saturday", 'day')
                value = value.replace("of every month", "")
                value = value.replace("every day, every month", "every day")


                rep['executionTime'] = value
            except:
                rep['executionTime'] = instance.executionTime
        if instance.name == "Web Session Protection":
            rep['needs_whitelisting'] = True
        else:
            rep['needs_whitelisting'] = False

        if instance.raw_executionTime is not None:
            try:
                rep["raw_executionTime"] = json.loads(instance.raw_executionTime)
            except:
                rep["raw_executionTime"] = instance.raw_executionTime

        try:
            rep['needs_graph'] = service_graph_map[instance.name]
        except:
            rep['needs_graph'] = False
        return rep 
    

########################## Invite Serializer#########################################################################################

class DevicesTokenSerializer(serializers.ModelSerializer):
   
    assing_to_user = serializers.EmailField()

    class Meta:
        model = DevicesToken
        fields = [
            'id',
            'token',
            'token_expire_time',
            'location',
            'assing_to_user',
            'assing_by_user',
            'organisation',
            'otp',
            'otp_expire_time',
            'otp_expire_count',
            'phone_no',
            'invitation',
            'created_date',
            'country_code',
            'phone_code',
            'expiration_period'
        ]
        extra_kwargs = {'token': {'write_only': True}, 'expiration_period': {'write_only': True}}


    def validate(self, attrs):
        attrs = super().validate(attrs)
        country_code = attrs.get('country_code')
        phone_code = attrs.get('phone_code')
        if phone_code is not None and phone_code[0] != "+":
            raise serializers.ValidationError("Invalid phone code format.")
        
        if country_code is not None and phone_code is not None:
            flag = False
            abs_path = os.path.abspath('accounts/utils/countries.json')
            with open(abs_path, 'r') as file:
                data = json.load(file)
                for country in data:
                    if country["country_code"] == country_code and country["phone_code"] == phone_code:
                        flag = True
                        break
            if not flag:
                raise serializers.ValidationError("Country code did not match.")
            
        else:
            raise serializers.ValidationError("Please provide both country code and phone code.")
        
        phone_no = attrs.get("phone_no")
        if len(phone_no) < 10 or not phone_no.isdigit() or len(phone_no) > 12:
            raise serializers.ValidationError("Contact number must be a valid 10 to 12 digit number.")

        return attrs

    def to_representation(self, instance):
        rep = super(DevicesTokenSerializer, self).to_representation(instance)
        if instance.invitation.lower() == "pending":
            try:
                if instance.token_expire_time <= timezone.now():
                    instance.invitation = "Expired"
                    instance.token = str(uuid.uuid4())
                    instance.save()
                    rep['invitation'] = "Expired"
                else:
                    rep['invitation'] = instance.invitation
            except:
                if instance.token_expire_time <= datetime.now():
                    instance.invitation = "Expired"
                    instance.token = str(uuid.uuid4())
                    instance.save()
                    rep['invitation'] = "Expired"
                else:
                    rep['invitation'] = instance.invitation
        else:
            rep['invitation'] = instance.invitation
        return rep


class UserStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'is_online',
        ]

    def to_representation(self, instance):
        rep = super(UserStatusSerializer, self).to_representation(instance)
        if instance.is_online is None:
            rep['is_online'] = False

        return rep


class UserSocketSerializer(serializers.ModelSerializer):
    permission = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = [
            'id',
            'is_online',
            'permission'
        ]

    def to_representation(self, instance):
        rep = super(UserSocketSerializer, self).to_representation(instance)
        if instance.is_online is None:
            rep['is_online'] = False
        return rep


    def get_permission(self, obj):
        if obj.is_owner:
            return "client_owner"
        elif obj.has_perm('accounts.client_admin'):
            return 'client_admin'
        elif obj.has_perm('accounts.client_user'):
            return 'client_user'
        elif obj.has_perm('accounts.client_reader'):
            return 'client_reader'
        else:
            return ""
        


###########################################################################################################################################


# async def send_socketio_event(data, room):
#     await sio.emit('device_status', data=data, room=room)


class DeviceOnlineStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model=DeviceOnlineStatus
        fields="__all__"

    def to_representation(self, instance):
        rep = super(DeviceOnlineStatusSerializer, self).to_representation(instance)
        try:
            if instance.time <= timezone.now():
                instance.is_online = False
                instance.save()
                rep['is_online'] = False
            else:
                rep['is_online'] = instance.is_online
        except:
            if instance.time <= datetime.now():
                instance.is_online = False
                instance.save()
                rep['is_online'] = False
            else:
                rep['is_online'] = instance.is_online
        return rep


# device log
class DeviceLogSerializer(serializers.ModelSerializer):
    class Meta:
        model=DeviceLog
        fields = "__all__"
#        exclude = ['file_deleted']

    def to_representation(self, instance):
        rep = super(DeviceLogSerializer, self).to_representation(instance)
        users = User.objects.filter(username = instance.changed_by, is_staff = False)
        rep['files_deleted'] = None
        if users.exists():
            user = users.first()
            rep['user_details'] = [user.get_full_name(), user.id]
            rep['changed_by'] = user.get_full_name()
            
        else:
            rep['user_detalis'] = None
            rep['changed_by'] = "" if instance.changed_by == "" else "FDS"
            if instance.file_deleted != "":
                if instance.service_name == "Web Cache Protection":
                    rep['files_deleted'] = convert_size(int(instance.file_deleted)) + " cleared"
                elif instance.service_name == "Web Session Protection":
                    rep['files_deleted'] = instance.file_deleted + " " + "cookies cleared"
                elif instance.service_name in ["Free Storage Protection", "DNS Cache Protection"]:
                    rep['files_deleted'] = None
                else:
                    rep['files_deleted'] = instance.file_deleted + " " + "files cleared"
        if instance.sentence is None or instance.sentence.strip() == "":
            rep['sentence'] = instance.title
        return rep


class DeviceSpecificLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceChangesLog
        fields = "__all__"

    def to_representation(self, instance):
        rep = super(DeviceSpecificLogSerializer, self).to_representation(instance)
        users = User.objects.filter(username = instance.changed_by)
        if users.exists():
            user = users.first()
            rep['user_details'] = [user.get_full_name(), user.id]
            rep['changed_by'] = user.get_full_name()
        else:
            rep['user_detalis'] = None
        rep['sentence'] = rep['title'].split('by')[0].strip()
        return rep
    

class NotificationSerializer(serializers.ModelSerializer):


    class Meta:
        model = Notification
        fields = ['id', 'heading', 'message', 
                  'location', 'device', 'timestamp', 
                  'actor_user', 'affected_user',
                  'type', 'plan', 'status'
                ]
        
    def to_representation(self, instance):
        rep = super(NotificationSerializer, self).to_representation(instance)
        rep['device_details'] = None
        rep['user_details'] = None
        rep['location_details'] = None
        rep['plan_details'] = None
        if instance.type == 4 or instance.type == 1:
            try:
                rep['device_details'] = ClientDeviceSerializer(instance.device).data
            except:
                rep['device_details'] = None   
        if instance.type == 2:
            rep['user_details'] = UserDashboardSerializer(instance.affected_user).data
            rep['location_details'] = LocationSerializer(instance.location).data
        if instance.type == 3:
            rep['location_details'] = LocationSerializer(instance.location).data
        if instance.type == 5:
            rep['plan_details'] = OrganizationPlanSerializer(instance.plan).data
        return rep
