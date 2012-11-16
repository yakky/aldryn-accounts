# -*- coding: utf-8 -*-
from django.conf import settings
from appconf import AppConf

class AccountsAppConf(AppConf):
    OPEN_SIGNUP = True
    NOTIFY_PASSWORD_CHANGE = True
    PASSWORD_CHANGE_REDIRECT_URL = '/'
    EMAIL_CONFIRMATION_REQUIRED = False
    EMAIL_CONFIRMATION_EMAIL = True
    EMAIL_CONFIRMATION_EXPIRE_DAYS = 3
    EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = "account_login"
    EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = None
    TRUSTED_EMAIL_SOCIAL_BACKENDS = ['github', 'google']

    class Meta:
        prefix = 'accounts'
