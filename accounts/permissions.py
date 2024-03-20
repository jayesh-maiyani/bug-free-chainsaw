from django.contrib.auth.models import Permission
from django.db.models import Q
from rest_framework import permissions, exceptions, status

def get_user_permissions(user):
    if user.is_superuser:
        return Permission.objects.all()
    return user.user_permissions.all() | Permission.objects.filter(group__user=user)


class UserAccessPermission(permissions.BasePermission):
    message = 'Adding customers not allowed.'

    def permission_denied(self, request, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.
        """
        if request.authenticators and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        raise exceptions.PermissionDenied(detail=message)

    def has_permission(self, request, view):

        if request.method == 'POST':
            permissions = [permission.codename for permission in get_user_permissions(request.user)]
            if 'add_user' not in permissions:
                self.permission_denied(
                    request, {"message": 'This user is not allowed here'}
                )
        return True


class FusionClient(permissions.BasePermission):

    def has_permission(self, request, view):

        if request.user.is_superuser:
            return True

        if request.method == 'POST':
            return request.user.user_permissions.filter(
                Q(codename='client_user') |
                Q(codename='client_admin')
            ).exists()
        if request.user.user_permissions.filter(Q(codename='client_admin')).exists():
            setattr(request.user, 'role', 'client_admin')
            # request.user.role = 'client_admin'
        elif request.user.user_permissions.filter(Q(codename='client_user')).exists():
            setattr(request.user, 'role', 'client_user')
            # request.user.role = 'client_user'
    
        else:
            setattr(request.user, 'role', 'client_reader')
            # request.user.role = 'client_reader'

        return True


class FusionStaff(permissions.BasePermission):

    def has_permission(self, request, view):

        if request.user.is_superuser:
            return True

        if request.method == 'POST':
            return request.user.user_permissions.filter(
                Q(codename='staff_admin')
            ).exists()
        if request.user.user_permissions.filter(Q(codename='staff_admin')).exists():
            setattr(request.user, 'role', 'client_admin')
            # request.user.role = 'client_admin'

        else:
            setattr(request.user, 'role', 'staff_reader')
            # request.user.role = 'client_reader'

        return True


class MasterRegisterer(permissions.BasePermission):
    message = "Access Unauthorized."
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def has_permission(self, request, view):
        if request.user.has_perm("accounts.master_client"):
            return True
