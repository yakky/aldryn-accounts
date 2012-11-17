# -*- coding: utf-8 -*-
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned
from djangocms_accounts.models import EmailAddress


class EmailBackend(ModelBackend):
    def authenticate(self, username=None, password=None):
        try:
            # TODO: can we enforce email to be unique instead?
            email = EmailAddress.objects.get(email=username)
            if email.user.check_password(password):
                return email.user
            return None
        except (EmailAddress.DoesNotExist, User.DoesNotExist, MultipleObjectsReturned):
            return None