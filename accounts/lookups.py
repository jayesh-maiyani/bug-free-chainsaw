from ajax_select import LookupChannel, register
from django.db.models import Q

from accounts.models import User, Organization


@register('users')
class UserLookup(LookupChannel):
    model = User

    def get_query(self, q, request):
        return self.model.objects.filter(
            Q(email__icontains=q) &
            Q(is_superuser=0)
        )

    def format_item_display(self, item):
        return u"<span class='tag'>%s</span>" % item.email


@register('organizations')
class OrganizationLookup(LookupChannel):
    model = Organization

    def get_query(self, q, request):
        return self.model.objects.all()
        # return self.model.objects.filter(
        #     Q(email__icontains=q) &
        #     Q(is_superuser=0)
        # )

    def format_item_display(self, item):
        return u"<span class='tag'>%s</span>" % item.name


@register('permissions')
class Permissions(LookupChannel):

    def get_query(self, q, request):
        return self.model.objects.filter(
            Q(codename__icontains=q)
        )

    def format_item_display(self, item):
        return u"<span class='tag'>%s</span>" % item.name
