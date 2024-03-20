# Create your models here.
import uuid, boto3, logging, datetime, os, json
from datetime import datetime

from django.dispatch import receiver
from django.core.validators import FileExtensionValidator
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.core.files.storage import Storage
from django.db.models.signals import post_save
from django.contrib.postgres.fields import ArrayField


from accounts.cryptoutils import gen_keys, encrypt, decrypt,decrypt_decode, decode_base64,decode_base64_decode
from accounts.exceptions import PayloadDecryptError, SubServiceNotFound, SubServiceCodeNotFound
from accounts.managers import DeviceManager, LocationManager, OrganizationManager
from accounts.utils import encode_base64

from subscription.models import OrganizationPlan


logger = logging.getLogger(__name__)

default_call_api = {
    'service_change': False,
    'device_details_change': False,
    'reauthenticate': False,
    'code_change': False,
    'device_status_change':False,
    'service_status_change':False,
}
confif_data=json.dumps(default_call_api)

DEVICE_CHOICES = (('1', 'windows'), ('2', 'mac'))


SubcriptionChoise=(
   ("Combo" ,"Combo"),
   ("Specific" ,"Specific"),
   ("Default" ,"Default")
)

PriceChoise=(
   ("Combo" ,"5$"),
   ("Specific" ,"0$"),
   ("Default" ,"0$")
)
###################  ORGNISATIONS MODELS #############################


def generate_unique_filename(instance, filename):
    # Customize the generation of the S3 object key as per your needs
    # Get the file extension
    ext = filename.split('.')[-1]

    # Generate a random filename with a combination of unique ID and timestamp
    unique_filename = '{}.{}'.format(uuid.uuid4().hex, ext)

    # Return the unique filename
    return f'media/image/profile/{unique_filename}'

# Configure the storage backend for ImageField
class S3Storage(Storage):
    def __init__(self):
        self.s3 = boto3.client(
            's3', 
            region_name = settings.AWS_S3_REGION_NAME,
            aws_access_key_id = settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY
        )
        self.bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        self.region_name = settings.AWS_S3_REGION_NAME

    def save(self, name, content, max_length = None):
        self.s3.upload_fileobj(content, self.bucket_name, name)

        return name

    def url(self, name):
        return f'https://{self.bucket_name}.s3.amazonaws.com/{name}'

    def generate_filename(self, filename):
        # Customize the generation of the filename as per your needs
        # You can use a UUID, timestamp, or any other desired logic
        return filename
    
    def delete(self, filename):
        self.s3.delete_object(Bucket=self.bucket_name, Key=filename)
        return True


class User(AbstractUser):
    created_by = models.ForeignKey('User', null=True, on_delete=models.CASCADE, related_name='user_created_by')
    created_on=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    picture=models.ImageField(upload_to = generate_unique_filename, blank=True, null=True)
    addresh=models.CharField(max_length=100,null=True,blank=True)
    city=models.CharField(max_length=50,null=True,blank=True)
    state=models.CharField(max_length=50,null=True,blank=True)
    zipcode=models.CharField(max_length=8,null=True,blank=True)
    country=models.CharField(max_length=50,null=True,blank=True)
    contact_number=models.CharField(max_length=15,null=True,blank=True)
    gender=models.CharField(max_length=25,null=True,blank=True)
    designation=models.CharField(max_length=50,null=True,blank=True)
    profileupdateon=models.DateTimeField(null=True, blank=True)
    org=models.CharField(max_length=100,null=True,blank=True)
    otp = models.BigIntegerField(blank=True, null=True)
    failedLoginCount = models.IntegerField(blank=True, null=True,default=0)
    otpgenerationTime = models.DateTimeField(blank=True, null=True)
    forgotlink=models.UUIDField(null=True,blank=True)
    forgotlinktime=models.DateTimeField(null=True, blank=True)
    is_owner=models.BooleanField(default=False,null=True,blank=True)
    is_online = models.BooleanField(default=False)
    country_code = models.CharField(max_length = 5, null = True)
    phone_code = models.CharField(max_length = 8, null = True)
    socket_id = ArrayField(base_field = models.CharField(max_length = 100, null = True, blank = True), default = list)
    last_online_time = models.DateTimeField(null = True, blank = True)

    class Meta:
        permissions = (
            ("master_client", "Master Client"),
            ('client_admin', 'Client Administrator'),
            ('client_user', 'Client User'),
            ('client_reader', 'Client Reader'),
            ("staff_admin","Staff Admin"),
            ("staff_user","Staff User"),
            ("staff_reader", "Staff Reader")
        )


class Location(models.Model):
    location_name = models.CharField(blank=True, max_length=100)
    is_active = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    last_modified = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    created_by = models.ForeignKey(User, null=True, on_delete = models.CASCADE, related_name='loc_created_user')
    user = models.ManyToManyField(User, blank=True)
    organization = models.ForeignKey('Organization',on_delete = models.CASCADE,blank=True,null=True)
    objects = LocationManager()

    def __str__(self):
        return self.location_name

    class Meta:
        verbose_name = 'Location'
        verbose_name_plural = 'Locations'

############################################### ORGNISATIONS MODELS ################################################
def generate_unique_filename_org(instance, filename):
    # Get the file extension
    ext = filename.split('.')[-1]

    # Generate a random filename with a combination of unique ID and timestamp
    unique_filename = '{}.{}'.format(uuid.uuid4().hex, ext)

    # Return the unique filename
    return 'media/image/organization/{}'.format(unique_filename)

class Organization(models.Model):
    name = models.CharField(blank=True, max_length=100)
    company_address = models.CharField(blank=True, max_length=100)
    city=models.CharField(blank=True, max_length=50)
    picture = models.ImageField(upload_to = generate_unique_filename_org, blank = True, null = True)
    state=models.CharField(blank=True, max_length=50)
    zip=models.CharField(blank=True, max_length=8)
    country=models.CharField(blank=True, max_length=50)
    company_phone=models.CharField(blank=True, max_length=15)
    company_email=models.CharField(blank=True,null=True, max_length=100)
    organisation_type=models.CharField(blank=True, max_length=100)
    owner=models.CharField(blank=True, max_length=100)
    size_of_company=models.IntegerField(blank=True)
    is_active = models.BooleanField(default=False)
    created_date = models.DateTimeField(
        auto_now_add=True, null=True, blank=True)
    last_modified_datetime = models.DateTimeField(
        auto_now_add=True, null=True, blank=True)
    created_by = models.ForeignKey(
        User, null=True, on_delete=models.CASCADE, related_name='org_created_user')
    licence = models.IntegerField(default = 0)
    user = models.ManyToManyField(User)
    objects = OrganizationManager()
    country_code = models.CharField(max_length = 5, null = True)
    phone_code = models.CharField(max_length = 8, null = True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'


############################################ Organization Services & Subservices ######################################################################
class OrgnisationService(models.Model):
    name = models.CharField(max_length=100)
    create_on = models.DateField()
    expire_on = models.DateField()
    Subscribed = models.BooleanField(default=False)
    price = models.CharField(max_length=50,default=10)
    service_active = models.BooleanField(default=True,null=True,blank=True)
    created_time = models.DateTimeField(auto_now_add=True,null=True,blank=True)
    updated_time = models.DateTimeField(auto_now=True,null=True,blank=True)
    orginstion = models.ForeignKey("Organization", on_delete=models.CASCADE,null=True,blank=True)


class OrgnisationSubService(models.Model):
    name = models.CharField(max_length=100)
    orginstion = models.ForeignKey(Organization, on_delete=models.CASCADE, null = True)
    service = models.ForeignKey(OrgnisationService, on_delete=models.CASCADE, null = True)
    executionTime = models.CharField(max_length=500, null = True, blank = True)
    raw_executionTime = models.CharField(max_length=1000, null=True)
    created_date = models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_active=models.BooleanField(default = True, null=True, blank=True)

    class Meta:
        ordering = ['-id']


class OrgWhitelistDomain(models.Model):
    domain_name = models.CharField(max_length = 100, null = True, blank = True)
    url = models.CharField(max_length = 100, null = True, blank = True)
    associated_to = models.ForeignKey(OrgnisationSubService, null = True, blank = True, on_delete = models.CASCADE)
    org = models.ForeignKey(Organization, on_delete = models.CASCADE, null = True, blank=True)
    
    def __str__(self):
        return self.url


############################################### Device Services & Subservices ###########################################################
class Service(models.Model):
    name = models.CharField(max_length=200)
    service_active = models.BooleanField(default=True)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)
    # here is change the code
    orgnization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, null=True, blank=True)
    combo = models.CharField(choices=SubcriptionChoise,
                             default='Default', max_length=50)
    price = models.CharField(
        choices=PriceChoise, default='Default', max_length=50)
    Expire_on = models.DateField(null=True, blank=True)

    def get_devices(self):
        return self.device_set.all()


class SubService(models.Model):
    name = models.CharField(max_length=200)
    service_name = models.CharField(max_length=200)
    service = models.ForeignKey(
        Service, on_delete=models.CASCADE, null=True, blank=True)
    is_code_updated = models.BooleanField(default=False)
    authorization_code = models.UUIDField(default=uuid.uuid4)
    execution_period = models.CharField(max_length=500, null=True)
    raw_execution_period = models.CharField(max_length=1000, null=True)
    last_execution = models.DateTimeField(
        null = True
    )  
    next_execution = models.DateTimeField(null=True)
    is_executed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_scheduled = models.BooleanField(default=False)
    is_running = models.BooleanField(default=False)
    execute_now = models.BooleanField(default=False)
    next_manual_execution = models.DateTimeField(null = True)
    log = models.TextField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)
    Expire_on = models.DateField(null=True, blank=True)
    activate_on = models.DateTimeField(auto_now_add=True)
    subscribe = models.BooleanField(default=False, null=True, blank=True)
    subserviceprice = models.CharField(max_length=50)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,null=True,blank=True)

    class Meta:
        unique_together = (('service', 'service_name'))
        ordering = ['-id']

    def __str__(self):
        return self.name

#################### Device Subservice Whitelisting #####################################################################################################################

class DeviceSubServiceWhiteListDomain(models.Model):
    domain_name = models.CharField(max_length = 100, null = True, blank = True)
    url = models.CharField(max_length = 100, null = True, blank = True)
    associated_to = models.ForeignKey(SubService, null = True, blank = True, on_delete=models.CASCADE)
    org = models.ForeignKey(Organization, on_delete = models.CASCADE, null = True)

    def __str__(self):
        return self.url
    
#################### Subservice Code #####################################################################################################################

def get_upload_path(instance, filename):
    device_type = 'windows' if instance.device_type == '1' else 'mac'
    return os.path.join("assets", "code", instance.service_name, device_type, filename)


class SubServiceCode(models.Model):
    service_name = models.CharField(max_length=200)
    device_type = models.CharField(
        max_length=200, null=False, choices=DEVICE_CHOICES)
    code = models.FileField(upload_to=get_upload_path, validators=[
                            FileExtensionValidator(allowed_extensions=['txt'])])
    code_version = models.FloatField(default=1.0)
    previous_hash = models.TextField()
    code_hash = models.TextField()

# ------------------------------------------------------> DEVICE MODLES <-------------------------------------------------------------

class DeviceAuthLog(models.Model):
    mac_address = models.CharField(max_length = 200, null = False)
    serial_number = models.CharField(max_length = 200, null = False)
    device_name = models.CharField(max_length = 200, null = False)
    device_type = models.CharField(max_length = 200, null = False)
    device = models.CharField(max_length = 200, null = True)
    ip_address = models.CharField(max_length = 200, null = True)
    created = models.ForeignKey(User, null = True, on_delete = models.CASCADE)


class Device(models.Model):
    mac_address = models.CharField(max_length = 200, null = False)
    serial_number = models.CharField(max_length = 200, null = False)
    device_uuid=models.CharField(max_length=200, null=False)
    device_name = models.CharField(max_length = 200, null = False)
    device_type = models.CharField(max_length = 50, null = False)
    public_key_server = models.TextField(null = True)
    public_key_device = models.TextField(null = True)
    private_key_server = models.TextField(null = True)
    code_version = models.CharField(max_length = 200, null=False)
    os_version = models.CharField(max_length = 200, null=False)    
    qr_code_token = models.TextField(null = True)
    qr_code_generated_on = models.DateTimeField(default = datetime.now)
    authorization_token = models.UUIDField(default = uuid.uuid4)
    authentication_token = models.UUIDField(default = uuid.uuid4)
    created_on = models.DateTimeField(null = True)
    updated_on = models.DateTimeField(default = datetime.now)
    last_seen = models.DateTimeField(default = None, null = True)
    is_active = models.BooleanField(default = False, null = True)
    is_subscribed = models.BooleanField(default = False, null = True)
    is_authenticated = models.BooleanField(default = False, null = True)
    is_re_authenticated = models.BooleanField(default = False, null = True)
    re_authenticated_on = models.DateTimeField(default = None, null = True)
    location = models.ForeignKey("Location", on_delete = models.CASCADE, blank = True, null = True)
    authenticated_by = models.ForeignKey(User, on_delete = models.CASCADE, null = True)
    credentials_shared = models.BooleanField(default = False)  
    qr_code_token_used = models.BooleanField(default = False)
    services = models.ManyToManyField('Service')
    call_config = models.BooleanField(default = False)
    call_config_types = models.CharField(max_length=200, default = confif_data)
    is_online = models.BooleanField(default = False, null = True)
    last_online_time = models.DateTimeField(auto_now_add=True,null=True,blank=True)    
    soft_delete = models.BooleanField(default = False, null = True)
    org = models.ForeignKey("Organization",on_delete = models.CASCADE,null = True,blank = True)

    objects = DeviceManager()

    def authenticate(self):
        try:
            # if qr code token has already been used to activate a device
            assert not self.qr_code_token_used
            if self.is_authenticated:
                if self.credentials_shared:
                    self.is_re_authenticated = True
                    self.re_authenticated_on = datetime.now()
            else:
                self.is_authenticated = True
                if not self.created_on:
                    self.created_on = datetime.now()
            self.is_active = True
            self.credentials_shared = False
            self.qr_code_token_used = True
            public_key, private_key = gen_keys()
            self.public_key_server = public_key.decode('utf-8')
            self.private_key_server = private_key.decode('utf-8')
            self.public_key_device = None
            self.authentication_token = None
            self.authorization_token = uuid.uuid4()
            self.authentication_token = uuid.uuid4()
            self.updated_on = datetime.now()
            self.save()
            remove_services_for_device(self)
            # add_services_for_device(self)
            return True
        except AssertionError:
            return False

    def reauth(self):
        self.is_authenticated = False
        self.is_active = False
        self.updated_on = datetime.now()
        self.save()

    def get_call_config(self):
        call_config = any(self.call_config_types.values())
        self.call_config = call_config
        self.save()
        data = {'success': True, 'call_config': call_config}
        # {'call_config_types': self.call_config_types}
        return data

    def get_service_code(self, subservice_authorization_code):
        try:
            subservice = SubService.objects.get(
                authorization_code=subservice_authorization_code)
        except:
            raise SubServiceNotFound()
        try:
            servicecode = SubServiceCode.objects.get(
                service_name=subservice.service_name)
            return encode_base64(servicecode.code.read())
        except:
            raise SubServiceCodeNotFound()

    def encode(self, str_data):
        public_key_server = decode_base64(self.public_key_server)
        return encrypt(str.encode(str_data), public_key_server)

    def encode_for_device(self, str_data, public_key=None):
        if public_key:

            public_key_device = decode_base64(public_key)

        else:
            public_key_device = decode_base64(self.public_key_device)
        return encrypt(str.encode(str_data), public_key_device)

    def decode_for_device(self, str_data, private_key_device):
        # here is re-wright
        return decrypt_decode(str.encode(str_data), decode_base64_decode(private_key_device))

    # def decode_for_device_decode(self, str_data, private_key_device):
    #     print("this is for decode only")
    #     return decrypt_decode(str.encode(str_data), decode_base64_decode(private_key_device))

    def decode(self, str_data):
        private_key_server = decode_base64(self.private_key_server)
        try:
            return decrypt(str.encode(str_data), private_key_server)
        except Exception as e:
            raise PayloadDecryptError()

    def add_agent_public_key(self, public_key):
        self.public_key_device = public_key
        self.save()

    def save_service_log(self, payload):
        sub_service_authorization_code = payload.get(
            "sub_service_authorization_code")
        # sub_service_name = payload.get("sub_service_name")
        # datetime = payload.get("datetime")
        current_time = datetime.now()
        files_deleted = payload.get("files_deleted")  # we need to delete
        executed = payload.get("executed")
        subservice = SubService.objects.get(
            authorization_code=sub_service_authorization_code)
        if subservice:
            subservice.is_executed = executed
            # subservice.files_deleted = files_deleted
            subservice.last_execution = current_time
            subservice.log = payload.get('log', '')
            subservice.save()
        else:
            return SubServiceNotFound()

    class Meta:
        verbose_name = 'Device'
        verbose_name_plural = 'Devices'

#################################### Importatnt for the device services #################################################################################################


@receiver(post_save, sender=SubServiceCode, dispatch_uid="update_service_code")
def calculate_md5(sender, instance, **kwargs):
    if instance.code_version > 1.0:
        subservice = SubService.objects.filter(service_name=instance.service_name)
        subservice.update(is_code_updated=True)
        devices = Device.objects.filter(services__in=subservice.values_list('service', flat=True), soft_delete = False)
        for d in devices:
            call_config_types = d.call_config_types
            call_config_types.update({'code_change': True})
            d.call_config_types = call_config_types
            d.save()


# called when device gets registered............................
def add_services_for_device(instance):
    try:  
        if instance.location:
            locName = instance.location
            
            orgdata = Organization.objects.get(name=locName.organization)
            org_plans = OrganizationPlan.objects.filter(organization = orgdata, is_plan_active = True)
            if org_plans.exists():
                orgservice = OrgnisationService.objects.filter(orginstion = orgdata).order_by('-id').first()
                if instance.services.all().count() == 0:
                    service = Service(name=orgservice.name,orgnization=orgdata, Expire_on = orgservice.expire_on)
                    service.save()
                    Msubservice = OrgnisationSubService.objects.filter(service = orgservice)
                    for ss in Msubservice:
                        if instance.device_type == "2" and ss.name.lower() == "windows registry protection":
                            continue
                        subservice = SubService(
                            name = ss.name,
                            service_name = ss.name.lower().replace(' ', '_'),
                            execution_period = ss.executionTime,
                            raw_execution_period = ss.raw_executionTime,
                            service = service,
                            organization = orgdata,
                            Expire_on = orgservice.expire_on
                        )
                        subservice.save()
                    instance.services.add(service)
                instance.save()
    except Exception as e:
        pass

def remove_services_for_device(device):
    for service in device.services.all():
        subservices=SubService.objects.filter(service=service)
        subservices.delete()
        service.delete()
        
    device.services.remove(*device.services.all())



@receiver(post_save, sender=Device, dispatch_uid="update_device")
def update_stock(sender, instance, **kwargs):
    ip = getattr(instance, '_ip', None)
    user_agent = getattr(instance, '_user_agent', None)
    if instance.location:
# here is tha main code of subscription:-
#         masterServ = MasterService.objects.all()
#         orgdata = Location.objects.get(location_name=instance.location)
#         org = Organization.objects.get(name=orgdata.organization)
#         for services in masterServ:
#             try:
#                 Orgservices=OrgnisationService.objects.get(name=services,orginstion=org)
#             except:
#                 orgservices=OrgnisationService(name=services,orginstion=org,price=services.price)
#                 orgservices.save()
#                 orgsubservices=MasterSubSevice.objects.filter(service=services)
#                 for subservices in orgsubservices:
#                     try:
#                         OrgSubService = OrgnisationSubService.objects.get(
#                             name=subservices.sub_service_name, orginstion=org)
#                     except:
#                         orgSubservice = OrgnisationSubService(
#                             name=subservices.sub_service_name,service=orgservices ,orginstion=org, executionTime=subservices.default_execution_time)
#                         orgSubservice.save()
# # her is the end
#         Mservice=MasterService.objects.all()
#         orgdata=Location.objects.get(location_name=instance.location)
#         oganisation = Organization.objects.get(name=orgdata.organization)
        if instance.services.count() == 0:
            add_services_for_device(instance)
        # if instance.services.count()> 0 and instance.services.count()<=Mservice.count() :
        #     service=instance.services.all()
        #     Mservice=MasterService.objects.all()
        #     for data in Mservice:
        #         try:
        #             Servicedata=instance.services.get(name=data.name)
        #         except:
        #             service=Service(name=data.name,orgnization=orgdata.organization)
        #             service.save()
        #             Msubservice=MasterSubSevice.objects.filter(service=data)
        #             for data in Msubservice:
        #                 try:
        #                     issubclass=SubService.objects.get(name=data.sub_service_name)
        #                     pass;
        #                 except:
        #                     orgsubservice = OrgSubscriptions.objects.get(
        #                         name=data.sub_service_name, orginstion=oganisation)
        #                     subservice=SubService(name=data.sub_service_name,
        #                                 service_name=data.sub_service_name.lower().replace(' ', '_'),
        #                                 #    execution_period=subservice.get('execution_period'),
        #                                           execution_period=orgsubservice.executionTime, subscribe=orgsubservice.Subscribed,
        #                                 service=service)
        #                     subservice.save()
        #             instance.services.add(service)
        #             instance.save()
    if instance.authenticated_by:
        d = DeviceAuthLog(
            mac_address=instance.mac_address,
            device_name=instance.device_name,
            device_type=instance.device_type,
            serial_number=instance.serial_number,
            device=user_agent.device.family if user_agent and user_agent.device else None,
            ip_address=ip,
            created=instance.authenticated_by
        )
        d.save()

# method for updating
# @receiver(post_save, sender = Device, dispatch_uid="update_device")
# def update_stock(sender, instance, **kwargs):
#     ip = getattr(instance, '_ip', None)
#     user_agent = getattr(instance, '_user_agent', None)
#     if instance.location:
# here is tha main code of subscription:-

        # loc = Location.objects.get(id = instance.id)
        # org = Organization.objects.get(name = loc.organization)
        # org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
        # if org_plans.exists():
        #     org_plan = org_plans.first()
        #     try:
        #         if instance.services.count() == 0:
        #             orgservices = OrgnisationService.objects.filter(orginstion = org)
        #             for orgservice in orgservices:
        #                 service = Service(name = orgservice.name, orgnization = org)
        #                 service.save()
        #                 org_sub_services = OrgnisationSubService.objects.filter(service = orgservice)
        #                 for org_sub_service in org_sub_services:
        #                     subservice = SubService(
        #                         name = org_sub_service.name,
        #                         service_name = org_sub_service.name.lower().replace(' ', '_'),
        #                         execution_period = org_sub_service.executionTime,
        #                         service = service, 
        #                         organization = org
        #                     )
        #                     subservice.save()
        #                 instance.services.add(service)
        #                 instance.save()
        #             org_plan.utilized_limit += 1
        #             org_plan.save()
        #     except Exception as e:
        #         pass
        
        # else:
        #     print("=========================> No organization plan was found active.")

    # if instance.authenticated_by:
    #     d = DeviceAuthLog(
    #         mac_address=instance.mac_address,
    #         device_name=instance.device_name,
    #         device_type=instance.device_type,
    #         serial_number=instance.serial_number,
    #         device=user_agent.device.family if user_agent and user_agent.device else None,
    #         ip_address=ip,
    #         created=instance.authenticated_by
    #     )
    #     d.save()


##################################### Access Tokens BlackListing ############################################################################################
class AccessTokensBlackList(models.Model):
    user = models.ForeignKey(User, on_delete = models.SET_NULL, null = True, blank = False)
    jti = models.CharField(unique = True, max_length=255)
    token = models.TextField()
    expires_at = models.DateTimeField()
    class Meta:
        db_table = "AccessTokensBlacklist"

    def __str__(self):
        return self.token


############################################# Logs #####################################################################################
class LogModel(models.Model):
    ACTOR_TYPES = [('CL', 'CLIENT'), ('ST', "STAFF")]

    actor_type = models.CharField(max_length = 2, choices = ACTOR_TYPES, default = "CL")
    actor_id = models.IntegerField(null = False)
    action = models.CharField(null = False, max_length = 200)
    user = models.ForeignKey(User, on_delete = models.CASCADE, default = None, null = True, blank = True)
    timestamp = models.DateTimeField(auto_now_add = True)
    org = models.ForeignKey(Organization, on_delete = models.CASCADE, default = None, null = True, blank = True)

    class Meta:
        db_table = "Logs"
        verbose_name = 'Log'
        verbose_name_plural = 'Logs'
        ordering = ["-timestamp"]


# device sub-service logs
class DeviceLog(models.Model):
    changed_by=models.CharField(max_length=100,blank=True,null=True)
    title=models.CharField(max_length = 200,blank=False,null=False)
    sentence = models.CharField(max_length = 200, null = True, blank = False)
    error=models.BooleanField(default=False)
    device_id = models.CharField(max_length=200,blank=False,null=False)
    device_serial_no = models.CharField(max_length=200,blank=False,null=False)
    service_name = models.CharField(max_length=100,blank=False,null=False)
    file_deleted = models.CharField(max_length=50,blank=False,null=False)
    time = models.DateTimeField(auto_now_add = True, null=True,blank=True)
    current_user=models.CharField(max_length=100,blank=False,null=False)
    organization=models.CharField(max_length=100,blank=False,null=False)


# specific device log
class DeviceChangesLog(models.Model):
    changed_by=models.CharField(max_length=100,blank=True,null=True)
    title=models.CharField(max_length=200,blank=False,null=False)
    device_serial_no=models.CharField(max_length=200,blank=False,null=False)
    time=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    organization=models.CharField(max_length=100,blank=False,null=False)
    device_id = models.CharField(max_length=200,blank=False,null=False)
    

# device online status
class DeviceOnlineStatus(models.Model):
    mac_address=models.CharField(max_length=200,blank=False,null=False)
    serial_no=models.CharField(max_length=200,blank=False,null=False)
    time=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    device_id=models.CharField(max_length=100,blank=False,null=False)
    online_user=models.CharField(max_length=100,blank=False,null=False)
    is_online=models.BooleanField(default=False)


################################### Master Models (Service and Subservice) ############################

class MasterService(models.Model):
    name = models.CharField(max_length=200)
    standalone = models.BooleanField(default=True)
    price = models.CharField(
        max_length=50, default="Null", null=True, blank=True)
    service_active = models.BooleanField(default=True)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)
    created_by=models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.name


class MasterSubSevice(models.Model):
    sub_service_name = models.CharField(max_length=100, null=False, blank=False)
    # here is the model linked to the service master model
    service = models.ForeignKey(
        MasterService, on_delete=models.CASCADE, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    # here is the main things that subservice have
    default_execution_time = models.CharField(
        max_length=500, null=True, blank=True,default="* * * * *")
    created_by = models.CharField(
        max_length=100, null=True, blank=True)
    raw_default_execution_time = models.CharField(max_length=1000, null=True)

    def __str__(self):
        return self.sub_service_name


####################### User and Device Analytics ###################################################################

class DeviceAnalytics(models.Model):
    active_devices = models.IntegerField(default = 0)
    inactive_devices = models.IntegerField(default = 0)
    reported_date = models.DateTimeField()
    organization = models.ForeignKey("Organization", on_delete = models.CASCADE, default = None, null = True)

    class Meta:
        db_table = "DeviceAnalytics"



class UserAnalytics(models.Model):
    active_users = models.IntegerField(default = 0)
    inactive_users = models.IntegerField(default = 0)
    reported_date = models.DateTimeField()
    organization = models.ForeignKey("Organization", on_delete = models.CASCADE, default = None, null = True)
    
    class Meta:
        db_table = "UserAnalytics"


# ############################### Invitation #############################################################################
class DevicesToken(models.Model):
    token = models.CharField(max_length=200,blank=False,null=False)
    token_expire_time=models.DateTimeField()
    location=models.CharField(max_length=200,blank=False,null=False)
    assing_to_user=models.CharField(max_length=200,blank=False,null=False)
    assing_by_user=models.CharField(max_length=200,blank=False,null=False)
    organisation=models.CharField(max_length=200,blank=False,null=False)
    otp=models.CharField(max_length=20,blank=False,null=False)
    otp_expire_time=models.DateTimeField()
    otp_expire_count=models.IntegerField(default=0)
    phone_no=models.CharField(max_length=20,blank=False,null=False)
    invitation=models.CharField(max_length=20,blank=False,null=False)
    created_date = models.DateField(null = True)
    country_code = models.CharField(max_length = 5, null = True)
    phone_code = models.CharField(max_length = 8, null = True)
    expiration_period = models.IntegerField(null = True)

##################################### Desktop Code Version #####################################################################################

class Desktop_code_version(models.Model):

    OS_CHOICES = [("1", "WINDOWS"), ("2", "MAC")]

    version=models.CharField(max_length=200)
    realise_date=models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length = 100)
    created_by_email = models.EmailField()
    application_os = models.CharField(choices = OS_CHOICES, max_length = 20)
    is_live = models.BooleanField(default = False)

    def __str__(self):
        return  f"{self.version} {'Live' if self.is_live else 'Unstable'}"
    

##################################### Notification ############################################################################################

class Notification(models.Model):
    class Types(models.IntegerChoices):
        DEVICE_UNINSTALL = 1
        ASSIGN_LOCATION = 2
        CREATE_LOCATION = 3
        DEVICE = 4
        SUBSCRIPTION = 5

    organization = models.ForeignKey('Organization', on_delete = models.CASCADE, null = True, default = None)
    type = models.IntegerField(Types.choices)
    heading = models.CharField(max_length = 500, null = False, blank = True)
    message = models.CharField(max_length = 500, null = True, blank = True)
    location = models.ForeignKey("Location", null = True, on_delete = models.CASCADE)
    device = models.ForeignKey("Device", null = True, on_delete = models.CASCADE)
    timestamp = models.DateTimeField(auto_now = True)
    actor_user = models.ForeignKey("User", on_delete = models.CASCADE, related_name = "notification_actor", null = True)
    affected_user = models.ForeignKey('User', on_delete = models.CASCADE, related_name = "notification_affected", null = True)
    plan = models.ForeignKey('subscription.OrganizationPlan', on_delete = models.CASCADE, null = True)
    role = models.CharField(max_length=15, null = True)
    status = models.CharField(max_length = 8, null = True)

############################## Auto Update Model ################################################################################################
class AutoUpdate(models.Model):
    token=models.CharField(max_length=200,blank=False,null=False)
    serial_number=models.CharField(max_length=200,blank=False,null=False)
    mac_address=models.CharField(max_length=200,blank=False,null=False)
    device_uuid=models.CharField(max_length=200,blank=False,null=False)
    link=models.CharField(max_length=200,blank=False,null=False)


######################################### OLD SUBSCRIPTION MODELS ########################################################################################################

# here is the subscription timing

# def yearly():
#     dataTime=datetime.now().date()
#     return (dataTime + timedelta(days=365))


# def monthly():
#     dataTime=datetime.now().date()
#     return (dataTime + timedelta(days=30))


# Subcription=(
#    (yearly() ,"yearly"),
#    (monthly() ,"monthly")
# )


# class MasterCurrency(models.Model):
#     country = models.CharField(max_length=50)
#     currency_name = models.CharField(max_length=50)
#     currency_acronym = models.CharField(max_length=50)


# class MasterSubscriptions(models.Model):
#     name = models.CharField(max_length=50)
#     active_days_of_service = models.IntegerField()
#     number_of_device_allowed = models.IntegerField(null=True, blank=True)
#     discount_amount = models.IntegerField()
#     currency_name = models.ForeignKey(
#         MasterCurrency, on_delete=models.CASCADE, blank=False, null=False)
#     created_on = models.DateTimeField(auto_now_add=True)
#     created_by = models.CharField(max_length=50)


# class MasterDevicePrice(models.Model):
#     price_of_one_device = models.IntegerField()
#     currency = models.ForeignKey(MasterCurrency, on_delete=models.CASCADE, null = True)


# class MasterSubscriptionService(models.Model):
#     service = models.ForeignKey(MasterService, on_delete=models.CASCADE, null = True)
#     subscriptions = models.ForeignKey(
#         MasterSubscriptions, on_delete=models.CASCADE, null = True)


# class MasterSubscriptionSubservice(models.Model):
#     subservice = models.ForeignKey(MasterSubSevice, on_delete=models.CASCADE, null = True)
#     is_Active = models.BooleanField()
#     subscriptions = models.ForeignKey(
#         MasterSubscriptions, on_delete=models.CASCADE, null = True)
#     service = models.ForeignKey(
#         MasterSubscriptionService, on_delete=models.CASCADE, null = True)


# class MasterDiscountCoupon(models.Model):
#     coupon_code = models.CharField(max_length=50)
#     start_on = models.DateTimeField(auto_now_add=True)
#     end_on = models.DateTimeField(default=datetime.now)
#     is_fixed_disscount = models.BooleanField()
#     fiexed_discount_amount = models.IntegerField()
#     is_percent_discount = models.BooleanField()
#     percent_discount = models.IntegerField()
#     max_disscount_upto = models.IntegerField()
#     is_open = models.BooleanField()
#     is_assinged_to_organisation = models.BooleanField()
#     assinged_organistion = models.CharField(max_length=50)
#     is_disscount_on_sub_services = models.BooleanField()
#     assinged_subservice = models.ForeignKey(
#         MasterSubSevice, on_delete=models.CASCADE, null = True)
#     is_disscoiunt_on_subscriptions = models.BooleanField()
#     assinged_subscriptions = models.ForeignKey(
#         MasterSubscriptions, on_delete=models.CASCADE, null = True)

######################################### OLD SUBSCRIPTION MODELS ########################################################################################################
