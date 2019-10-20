# -*- coding: utf-8 -*-
from aldryn_accounts.models import EmailAddress
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned
from django.utils.translation import ugettext, ugettext_lazy as _



class UserCreationForm(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given email and
    password.
    """
    error_messages = {
        'duplicate_email': _("A user is already registered with this email address."),
    }
    email = forms.EmailField(max_length=200)
    password = forms.CharField(label=_("Password"),
        widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ('email',)

    def clean_email(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        email = self.cleaned_data["email"]
        try:
            User._default_manager.get(email=email)
            verified_qs = EmailAddress.objects.filter(email__iexact=email)
            if verified_qs.exists():
                raise forms.ValidationError(self.error_messages['duplicate_email'])
        except User.DoesNotExist:
            return email
        except MultipleObjectsReturned:
            raise forms.ValidationError(self.error_messages['duplicate_email'])
        return email


    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
