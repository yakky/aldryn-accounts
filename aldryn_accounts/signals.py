# -*- coding: utf-8 -*-
from django.conf import settings
from django.utils import translation
from django.contrib.auth import user_logged_in, user_logged_out
import django.dispatch
import pytz


user_signed_up = django.dispatch.Signal(providing_args=["user", "form"])
user_sign_up_attempt = django.dispatch.Signal(providing_args=["username",  "email", "result"])
signup_code_sent = django.dispatch.Signal(providing_args=["signup_code"])
signup_code_used = django.dispatch.Signal(providing_args=["signup_code_result"])
email_confirmed = django.dispatch.Signal(providing_args=["email_address"])
email_confirmation_sent = django.dispatch.Signal(providing_args=["confirmation"])
password_changed = django.dispatch.Signal(providing_args=["user"])


def set_user_timezone_on_login(sender, user, request, **kwargs):
    from django.utils import timezone
    from django.db.models import ObjectDoesNotExist

    try:
        tz = user.settings.timezone
        if tz:
            request.session['django_timezone'] = tz
            timezone.activate(tz)
    except ObjectDoesNotExist:
        pass

user_logged_in.connect(set_user_timezone_on_login, dispatch_uid='aldryn_accounts:set_user_timezone_on_login')

# TODO: figure this out. actually we'd need to redirect to a url with the language prefix.
# def set_user_preferred_language_on_login(sender, user, request, **kwargs):
#     from django.db.models import ObjectDoesNotExist
#
#     try:
#         language = user.settings.preferred_language
#         if language and language in dict(settings.LANGUAGES).keys():
#             translation.activate(language)
#     except ObjectDoesNotExist:
#         pass
#
# user_logged_in.connect(set_user_preferred_language_on_login, dispatch_uid='aldryn_accounts:set_user_preferred_language_on_login')
