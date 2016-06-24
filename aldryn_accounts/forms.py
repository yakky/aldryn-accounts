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
from .conf import settings
import password_reset.forms


def get_user_email(user, form_email):
    """
    Search for confirmed emails with respect to form_email.
    Returns string, email address
    """
    # check if there is confirmed emails for this user
    confirmed_emails = EmailAddress.objects.get_for_user(
        user).order_by('is_primary')
    if not confirmed_emails:
        # if there is no confirmed emails - don't return anything
        return None
    email_instance = confirmed_emails[0]
    # check if entered email is confirmed
    matching_email = confirmed_emails.filter(email=form_email)
    if matching_email:
        email_instance = matching_email.get()
    # if entered email is not among the confirmed - user first
    # confirmed email
    return email_instance.email


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label=_("E-Mail"), max_length=255)


class PasswordRecoveryForm(password_reset.forms.PasswordRecoveryForm):
    def __init__(self, *args, **kwargs):
        super(PasswordRecoveryForm, self).__init__(*args, **kwargs)
        self.fields['username_or_email'].label = _('E-Mail')

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
        if not user:
            if settings.ALDRYN_ACCOUNTS_RESTORE_PASSWORD_RAISE_VALIDATION_ERROR:
                raise forms.ValidationError(
                    _("Sorry, this user doesn't exist."))
            return None
        return user

    def clean(self):
        cleaned_data = super(PasswordRecoveryForm, self).clean()
        user = cleaned_data.get('user')
        if not user:
            return cleaned_data
        form_email = cleaned_data.get('username_or_email', '')
        email = get_user_email(user, form_email)
        # check if wee need to raise validation error.
        validation_error = (
            not email and
            settings.ALDRYN_ACCOUNTS_RESTORE_PASSWORD_RAISE_VALIDATION_ERROR)
        if validation_error:
            raise forms.ValidationError(
                    _("Sorry, this user doesn't have any verified E-Mail."))
        cleaned_data['email'] = email
        return cleaned_data


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
    email = forms.EmailField(label=_("E-Mail"), required=True)


class ProfileEmailForm(EmailForm):

    def clean_email(self):
        email = self.cleaned_data.get('email')
        verified_qs = EmailAddress.objects.filter(email__iexact=email)
        if verified_qs.exists():
            raise forms.ValidationError(_("This E-Mail address is already in use."))
        return email


class SignupForm(forms.Form):
    email = forms.EmailField(label=_("E-Mail"), widget=forms.TextInput(), required=True)
    code = forms.CharField(
        max_length=64,
        required=False,
        widget=forms.HiddenInput()
    )

    def clean_email(self):
        value = self.cleaned_data["email"]
        verified_qs = EmailAddress.objects.filter(email__iexact=value)
        if verified_qs.exists():
            raise forms.ValidationError(_("A user is already registered with this E-Mail address."))
        unverified_qs = EmailConfirmation.objects.filter(email__iexact=value)
        if unverified_qs.exists():
            resend_url = reverse('accounts_signup_email_resend_confirmation')
            resend_url += '?' + urllib.urlencode({'email': value})
            body = render_to_string('aldryn_accounts/inc/email_already_in_the_verification_phase.html',
                                    {'resend_url': resend_url})
            raise forms.ValidationError(body)
        return value


class SignupEmailResendConfirmationForm(forms.Form):
    email = forms.EmailField(label=_("E-Mail"), required=True, widget=forms.HiddenInput())

    def clean_email(self):
        email = self.cleaned_data["email"]
        verified_qs = EmailAddress.objects.filter(email__iexact=email)
        if verified_qs.exists():
            raise forms.ValidationError(_("A user is already registered with this E-Mail address."))
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
