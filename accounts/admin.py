from ajax_select import make_ajax_form
from ajax_select.admin import AjaxSelectAdmin
from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.db import models
from django.db.models import Q
from django.db.models.signals import post_save
from django.dispatch import receiver

# Register your models here.
from accounts.forms import UserForm
from accounts.middlewares import get_current_user
from accounts.utils import to_md5
from .models import*
# reduce()

# admin.site.register(User)

# admin.site.register(OrgSubscriptions)

admin.site.register(AccessTokensBlackList)
admin.site.register(DevicesToken)
admin.site.register(MasterService)
admin.site.register(MasterSubSevice)
admin.site.register(OrgWhitelistDomain)
admin.site.register(DeviceSubServiceWhiteListDomain)

admin.site.register(DeviceOnlineStatus)
admin.site.register(Organization)


class OrganizationAdmin(AjaxSelectAdmin):
    form = make_ajax_form(Organization, {
        'user': 'users',
    })

    def render_change_form(self, request, context, *args, **kwargs):
        context['adminform'].form.fields['created_by'].queryset = User.objects.filter(is_superuser=False)
        return super(OrganizationAdmin, self).render_change_form(request, context, *args, **kwargs)


@admin.register(Location)
class LocationAdmin(AjaxSelectAdmin):
    form = make_ajax_form(Location, {
        'user': 'users',
    })
    list_display = ('location_name','organization')
    # list_display = ('location_name', 'get_organization')
    search_fields = 'location_name',

    def render_change_form(self, request, context, *args, **kwargs):
        context['adminform'].form.fields['created_by'].queryset = User.objects.filter(is_superuser=False)
        return super(LocationAdmin, self).render_change_form(request, context, *args, **kwargs)

    # def get_organization(self, obj):
    #     return "\n".join([p.name for p in obj.organization.all()])


class DeviceAdmin(admin.ModelAdmin):
    list_display = ['id', 'org', 'device_name', 'device_type', 'location', 'is_active', 'is_subscribed', 'soft_delete']

admin.site.register(Device, DeviceAdmin)

class MasterServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']

class OrganizationServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'orginstion', 'name', 'Subscribed', 'service_active', 'expire_on', 'price']

admin.site.register(OrgnisationService, OrganizationServiceAdmin)

class OrganizationSubServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'orginstion', 'name', 'service', 'executionTime', 'is_active']

admin.site.register(OrgnisationSubService, OrganizationSubServiceAdmin)

class DesktopVersionAdmin(admin.ModelAdmin):
    list_display = ['id', "version", 'realise_date', 'created_by', 'created_by_email', 'application_os', 'is_live']
admin.site.register(Desktop_code_version, DesktopVersionAdmin)


class DeviceLogAdmin(admin.ModelAdmin):
    list_display = ['id', "changed_by", 'device_id', 'device_serial_no', 'service_name', 'file_deleted', 'time', 'current_user', 'organization']

admin.site.register(DeviceLog, DeviceLogAdmin)

class SubServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'organization', 'name', 'subscribe', 'service', 'is_active', 'Expire_on', 'execution_period']

admin.site.register(SubService, SubServiceAdmin)

class ServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'orgnization', 'name', 'price', 'service_active', 'Expire_on']

admin.site.register(Service, ServiceAdmin)



class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'organization', 'type', 'timestamp', 'device', 'actor_user', 'affected_user', 'status', 'heading']
admin.site.register(Notification, NotificationAdmin)



class DeviceAnalyticsAdmin(admin.ModelAdmin):
    list_display = ['id', 'organization', 'active_devices', 'inactive_devices', 'reported_date']

admin.site.register(DeviceAnalytics, DeviceAnalyticsAdmin)


class UserAnalyticsAdmin(admin.ModelAdmin):
    list_display = ['id', 'organization', 'active_users', 'inactive_users', 'reported_date']

admin.site.register(UserAnalytics, UserAnalyticsAdmin)


@admin.register(LogModel)
class LogModelAdmin(admin.ModelAdmin):
    list_display = ['id', 'actor_type', 'actor_id', 'action', 'user', 'timestamp', 'org']
    


@admin.register(User)
class UserAdmin(BaseUserAdmin):

    def get_queryset(self, request):
        if request.user.is_superuser:
            return User.objects.all()
        return User.objects.filter(requested_by=request.user)

    def get_form(self, request, obj=None, **kwargs):
        form = super(UserAdmin, self).get_form(request, obj, **kwargs)
        # adding a User via the Admin doesn't include the permissions at first
        if 'user_permissions' in form.base_fields:
            permissions = form.base_fields['user_permissions']
            permissions.queryset = permissions.queryset.filter(
                Q(codename__icontains='client')|Q(codename__icontains='staff'))
        return form

    add_form = UserForm
    list_display = ('username', 'first_name', 'last_name',
                    'is_staff',"org","picture","is_owner", 'otp')
    # list_editable = ('is_staff',)
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','first_name', 'last_name', 'username',
                       'password1', 'password2',
                       'is_staff', 'user_permissions',"org","picture","is_owner",
                       )}
         ),
    )
    

UserAdmin.fieldsets += ('Organisations',
                        {'fields': ('org',)},
                        ),
UserAdmin.fieldsets += ('picture',
                        {'fields': ('picture',)},
                        ),
UserAdmin.fieldsets += ('is_owner',
                        {'fields': ('is_owner',)},
                        ),



@receiver(post_save, sender=User)
def update_username(sender, instance, created, **kwargs):
    user = get_current_user()
    if created:
        if not instance.username:
            instance.username = instance.email
        instance.requested_by = user
        instance.save()


# admin.site.register(Organization)
# admin.site.register(Location)
# admin.site.register(SubServiceCodes)

class SubServiceCodeForm(forms.ModelForm):
    CHOICES = (
        ('web_cache_cleaning', 'Web Cache Cleaning'),
        ('web_history_cleaning', 'Web History Cleaning'),
        ('web_cookie_cleaning', 'Web Cookie Cleaning'),
        ('dns_flushing', 'DNS Flushing'),
        ('windows_registry_cleaning', 'Windows Registry Cleaning'),
        ('recycle_bin_cleaning', 'Recycle Bin Cleaning'),
        ('memory_cleaning', 'Memory Cleaning')
    )

    service_name = forms.ChoiceField(choices=CHOICES)


    class Meta:
        model = SubServiceCode
        fields = ('service_name', 'device_type', 'code')


@admin.register(SubServiceCode)
class SubServiceCodeAdmin(admin.ModelAdmin):
    form = SubServiceCodeForm
    list_display = ('service_name', 'code_hash', 'previous_hash', 'code_version')

    def save_model(self, request, obj, form, change):
        content = form.cleaned_data['code'].open('rb')
        new_hash = to_md5(content)
        if not change:
            obj.code_hash = new_hash
            super(SubServiceCodeAdmin, self).save_model(request, obj, form, change)
        if change:
            if obj.code_hash != new_hash:
                obj.previous_hash = obj.code_hash
                obj.code_hash = to_md5(content)
                obj.code_version += 0.1
                super(SubServiceCodeAdmin, self).save_model(request, obj, form, change)
