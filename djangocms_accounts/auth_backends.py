# -*- coding: utf-8 -*-
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned


class EmailBackend(ModelBackend):
    def authenticate(self, username=None, password=None):
        try:
            # TODO: can we enforce email to be unique instead?
            users = User.objects.filter(email=username)
            for user in users:
                if user.check_password(password):
                    return user
            return None
        except (User.DoesNotExist, MultipleObjectsReturned):
            return None