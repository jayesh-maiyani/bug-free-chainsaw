from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm, ReadOnlyPasswordHashField
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from searchableselect.widgets import SearchableSelect

from accounts.models import User, Organization


# from searchableselect.widgets import SearchableSelect

# from accounts.models import User, Client, Subdomain, FacebookConfig, Industry


class UserForm(UserCreationForm):
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput,
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput,
        strip=False,
        help_text=_("Enter the same password as before, for verification."),
    )

    class Meta:
        model = User
        fields = '__all__'
        # fields = ['username', 'email', 'password1',
        #           'password2', 'is_staff', "org"]
        # widgets = {
        #     'organization': forms.CheckboxSelectMultiple()
        # }

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_(
            "Raw passwords are not stored, so there is no way to see this "
            "user's password, but you can change the password using "
            "<a href=\"{}\">this form</a>."
        ),
    )

    class Meta:
        model = User
        # fields = ('user_permissions',"organizations")
        fields = "__all__"


class OrganizationForm(forms.ModelForm):
    class Meta:
        widgets = {
            'user': SearchableSelect(model='accounts.User', search_field='email', many=True, limit=10),
        }

    def __init__(self, *args, **kwargs):
        super(OrganizationForm, self).__init__(*args, **kwargs)
        self.fields['user'].queryset = User.objects.filter(Q(is_superuser=0) & Q(status=1))


class LocationForm(forms.ModelForm):
    class Meta:
        widgets = {
            'organization': SearchableSelect(model='accounts.Organisation', search_field='name', many=True, limit=10),
        }

    def __init__(self, *args, **kwargs):
        super(LocationForm, self).__init__(*args, **kwargs)
        self.fields['organization'].queryset = Organization.objects.filter(Q(is_superuser=0))
