# -*- coding: utf-8 -*-
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from djangocms_accounts.models import EmailAddress, EmailConfirmation
from djangocms_accounts.utils import get_most_qualified_user_for_email_and_password


class EmailBackend(ModelBackend):
    def authenticate(self, username=None, password=None):
        """
        tries verified email addresses, the email field on user objects and unconfirmed email addresses.
        username is not checked, since the default model backend already does that.
        """
        username = username.strip()
        return get_most_qualified_user_for_email_and_password(username, password)


class PermissionBackend(object):
    def authenticate(self):
        return None
    
    def has_perm(self, user_obj, perm, obj=None):
        # TODO: cache
        if perm == 'djangocms_accounts.has_verified_email':
            if not user_obj or user_obj.is_anonymous():
                return False
            return EmailAddress.objects.has_verified_email(user_obj)
        return False
