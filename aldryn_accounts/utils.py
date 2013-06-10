# -*- coding: utf-8 -*-
import hashlib
import os
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.utils.crypto import random

import pygeoip


def user_display(user, fallback_to_username=False, fallback_to_pk=False):
    if user.is_anonymous():
        return 'Anonymous user'
    if user.email:
        return user.email
    elif user.first_name or user.last_name:
        return (u"%s %s" % (user.first_name, user.last_name)).strip()
    elif fallback_to_username and user.username:
        return user.username
    elif fallback_to_pk and user.pk:
        return user.pk
    return None


def random_token(extra=None, hash_func=hashlib.sha256):
    if extra is None:
        extra = []
    bits = extra + [str(random.getrandbits(512))]
    return hash_func("".join(bits)).hexdigest()


def profile_image_upload_to(instance, filename):
    name, extension = os.path.splitext(filename)
    profile_data_prefix = getattr(settings, 'ALDRYN_ACCOUNTS_PROFILE_IMAGE_UPLOAD_TO', 'profile-data')
    return profile_data_prefix + '/%s.%s' % (uuid.uuid4(), extension)


# TODO: make cache method configurable
gi4 = pygeoip.GeoIP(os.path.join(settings.GEOIP_PATH, getattr(settings, 'GEOIP_CITY', 'GeoLiteCity.dat')))


def geoip(ip):
    # TODO: validate ip
    data = gi4.record_by_addr(ip)
    if not data:  # empty dict
        return data
    if data.get('city') and data.get('country'):
        data['pretty_name'] = u"%s, %s" % (data.get('city'), data.get('country_name'))
    elif data.get('country'):
        data['pretty_name'] = u"%s" % data.get('country_name')
    return data


def get_most_qualified_user_for_email_and_password(email, password):
    from aldryn_accounts.models import EmailAddress, EmailConfirmation
    # try verified email addresses
    for email in EmailAddress.objects.filter(email=email):
        # (EmailAddress.email is unique, but using the forloop vs a .get removes the need for a try/except.
        if email.user.check_password(password):
            return email.user
        # try the email field on the user
    for user in User.objects.filter(email=email):
        if user.check_password(password):
            return user
        # try unconfirmed email addresses
    for email_confirmation in EmailConfirmation.objects.filter(email=email):
        if email_confirmation.user.check_password(password):
            return email_confirmation.user
    return None


def get_most_qualified_user_for_email(email):
    from aldryn_accounts.models import EmailAddress, EmailConfirmation
    # try verified email addresses
    for email in EmailAddress.objects.filter(email=email):
        # (EmailAddress.email is unique, but using the forloop vs a .get removes the need for a try/except.
        return email.user
    for user in User.objects.filter(email=email):
        return user
    for email_confirmation in EmailConfirmation.objects.filter(email=email):
        return email_confirmation.user
    return None
