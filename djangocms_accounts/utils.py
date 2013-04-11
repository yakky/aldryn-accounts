# -*- coding: utf-8 -*-
import hashlib
from django.utils.crypto import random
from django.conf import settings
import pygeoip
import os


def user_display(user):
    if user.is_anonymous():
        return 'Anonymous user'
    if user.email:
        return user.email
    elif user.first_name or user.last_name:
        return (u"%s %s" % (user.first_name, user.last_name)).strip()
    elif user.username:
        return user.username
    elif user.pk:
        return user.pk
    else:
        return '<unknown user>'


def random_token(extra=None, hash_func=hashlib.sha256):
    if extra is None:
        extra = []
    bits = extra + [str(random.getrandbits(512))]
    return hash_func("".join(bits)).hexdigest()


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
