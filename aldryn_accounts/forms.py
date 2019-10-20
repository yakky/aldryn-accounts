# -*- coding: utf-8 -*-
import urllib

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _

from .models import EmailAddress, EmailConfirmation, UserSettings
from .utils import get_most_qualified_user_for_email
import password_reset.forms


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label=_("Email"), max_length=255)


class PasswordRecoveryForm(password_reset.forms.PasswordRecoveryForm):
    def __init__(self, *args, **kwargs):
        super(PasswordRecoveryForm, self).__init__(*args, **kwargs)
        self.fields['username_or_email'].label = _('email')

    def get_user_by_both(self, username):
        """
        we care about case with the username, but not for the email (emails are saved in all lowercase).
        :param username:
        """
        try:
            user = User.objects.get(username=username)
            return user
        except User.DoesNotExist:
            user = get_most_qualified_user_for_email(username)
            if user:
                return user
        raise forms.ValidationError(_("Sorry, this user doesn't exist."))


class PasswordResetForm(forms.Form):
    password = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput,
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super(PasswordResetForm, self).__init__(*args, **kwargs)

    def save(self):
        self.user.set_password(self.cleaned_data['password'])
        User.objects.filter(pk=self.user.pk).update(
            password=self.user.password,
        )


class ChangePasswordForm(forms.Form):
    password_current = forms.CharField(
        label=_("Current Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_new = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(render_value=False)
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_password_current(self):
        if not self.user.check_password(self.cleaned_data.get("password_current")):
            raise forms.ValidationError(_("Please type your current password."))
        return self.cleaned_data["password_current"]

    def save(self, user):
        user.set_password(self.cleaned_data["password_new"])
        user.save()


class CreatePasswordForm(ChangePasswordForm):
    def __init__(self, *args, **kwargs):
        super(CreatePasswordForm, self).__init__(*args, **kwargs)
        del self.fields['password_current']


class EmailForm(forms.Form):
    email = forms.EmailField(label=_("Email"), required=True, max_length=200)


class SignupForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(), required=True, max_length=200)
    code = forms.CharField(
        max_length=64,
        required=False,
        widget=forms.HiddenInput()
    )

    def clean_email(self):
        value = self.cleaned_data["email"]
        verified_qs = EmailAddress.objects.filter(email__iexact=value)
        if verified_qs.exists():
            raise forms.ValidationError(_("A user is already registered with this email address."))
        unverified_qs = EmailConfirmation.objects.filter(email__iexact=value)
        if unverified_qs.exists():
            resend_url = reverse('accounts_signup_email_resend_confirmation')
            resend_url += '?' + urllib.urlencode({'email': value})
            body = render_to_string('aldryn_accounts/inc/email_already_in_the_verification_phase.html',
                                    {'resend_url': resend_url})
            raise forms.ValidationError(body)
        return value


class SignupEmailResendConfirmationForm(forms.Form):
    email = forms.EmailField(required=True, widget=forms.HiddenInput(), max_length=200)

    def clean_email(self):
        email = self.cleaned_data["email"]
        verified_qs = EmailAddress.objects.filter(email__iexact=email)
        if verified_qs.exists():
            raise forms.ValidationError(_("A user is already registered with this email address."))
        return email


class UserSettingsForm(forms.ModelForm):
    first_name = forms.CharField(label=_("First name"), required=True)
    last_name = forms.CharField(label=_("Last name"), required=True)

    class Meta:
        model = UserSettings
        fields = ('birth_date', 'preferred_language', 'timezone',
                  'location_name', 'location_latitude', 'location_longitude', 'profile_image')
        widgets = {
            'location_latitude': forms.HiddenInput(),
            'location_longitude': forms.HiddenInput(),
        }

    def __init__(self, *args, **kwargs):
        super(UserSettingsForm, self).__init__(*args, **kwargs)
        user = self.instance.user
        self.fields['first_name'].initial = user.first_name
        self.fields['last_name'].initial = user.last_name

    def save(self):
        first_name = self.cleaned_data['first_name']
        last_name = self.cleaned_data['last_name']
        user = self.instance.user
        user.first_name = first_name
        user.last_name = last_name
        user.save()
        return super(UserSettingsForm, self).save()
