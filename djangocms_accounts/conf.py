# -*- coding: utf-8 -*-
from django.conf import settings
NOTIFY_PASSWORD_CHANGE = getattr(settings, 'ACCOUNTS_NOTIFY_PASSWORD_CHANGE', True)
PASSWORD_CHANGE_REDIRECT_URL = getattr(settings, 'ACCOUNTS_PASSWORD_CHANGE_REDIRECT_URL', '/')