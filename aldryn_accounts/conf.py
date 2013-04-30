# -*- coding: utf-8 -*-
from django.conf import settings
from appconf import AppConf


class AccountsAppConf(AppConf):
    OPEN_SIGNUP = True  # whether any user may signup. If set to False only users with an invite code may sign up.
    SIGNUP_REDIRECT_URL = 'accounts_profile'
    NOTIFY_PASSWORD_CHANGE = True  # whether a confirmation email should be sent out whenever the password is changed
    PASSWORD_CHANGE_REDIRECT_URL = 'accounts_profile'
    EMAIL_CONFIRMATION_REQUIRED = True  # whether emails need to be confirmed in order to get an active account. False IS NOT SUPPORTED YET!
    EMAIL_CONFIRMATION_EMAIL = True  # whether to send out a confirmation email when a user signs up
    EMAIL_CONFIRMATION_EXPIRE_DAYS = 3  # how long a confirmation email code is valid
    SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL = ['google']  # which backends can be trusted to provide validated email addresses
    SUPPORT_EMAIL = settings.DEFAULT_FROM_EMAIL

    SOCIAL_BACKEND_ORDERING = []

    ENABLE_SOCIAL_AUTH=False  # controls visibility of social auth related things in the UI

    LOGIN_REDIRECT_URL = '/'
