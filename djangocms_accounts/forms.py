# -*- coding: utf-8 -*-
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django import forms
from djangocms_accounts.models import EmailAddress, UserSettings
import password_reset.forms


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label=_("Email"), max_length=255)


class PasswordRecoveryForm(password_reset.forms.PasswordRecoveryForm):
    def __init__(self, *args, **kwargs):
        super(PasswordRecoveryForm, self).__init__(*args, **kwargs)
        self.fields['username_or_email'].label = _('email')

    def get_user_by_both(self, username):
        """
        we care about case with the username, but not for the email (emails are save all lowercase).
        we check the email in the EmailAddress model (those are validated).
        """
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        try:
            email = EmailAddress.objects.get(email=username.strip().lower())
            user = email.user
        except EmailAddress.DoesNotExist:
            raise forms.ValidationError(_("Sorry, this user doesn't exist."))
        return user


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
    email = forms.EmailField(label=_("Email"), required=True)


class SignupForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(), required=True)
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_confirm = forms.CharField(
        label=_("Password (again)"),
        widget=forms.PasswordInput(render_value=False)
    )
    code = forms.CharField(
        max_length=64,
        required=False,
        widget=forms.HiddenInput()
    )

    def clean_email(self):
        value = self.cleaned_data["email"]
        qs = EmailAddress.objects.filter(email__iexact=value)
        if not qs.exists():
            return value
        raise forms.ValidationError(_("A user is registered with this email address."))

    def clean(self):
        if "password" in self.cleaned_data and "password_confirm" in self.cleaned_data:
            if self.cleaned_data["password"] != self.cleaned_data["password_confirm"]:
                raise forms.ValidationError(_("You must type the same password each time."))
        return self.cleaned_data


class UserSettingsForm(forms.ModelForm):
    class Meta:
        model = UserSettings
        fields = ('timezone',)