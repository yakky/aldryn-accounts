# -*- coding: utf-8 -*-
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from aldryn_accounts.models import EmailAddress, EmailConfirmation


class EmailBackend(ModelBackend):
    def authenticate(self, username=None, password=None):
        """
        tries verified email addresses, the email field on user objects and unconfirmed email addresses.
        username is not checked, since the default model backend already does that.
        """
        username = username.strip()
        # try verified email addresses
        for email in EmailAddress.objects.filter(email=username):
            # (EmailAddress.email is unique, but using the forloop vs a .get removes the need for a try/except.
            if email.user.check_password(password):
                return email.user
        # try the email field on the user
        for user in User.objects.filter(email=username):
            if user.check_password(password):
                return user
        # try unconfirmed email addresses
        for email_confirmation in EmailConfirmation.objects.filter(email=username):
            if email_confirmation.user.check_password(password):
                return email_confirmation.user
        return None


class PermissionBackend(object):
    def authenticate(self):
        return None
    
    def has_perm(self, user_obj, perm, obj=None):
        # TODO: cache
        if perm == 'aldryn_accounts.has_verified_email':
            if not user_obj or user_obj.is_anonymous():
                return False
            return EmailAddress.objects.has_verified_email(user_obj)
        return False
