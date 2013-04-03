# -*- coding: utf-8 -*-
from pytz import UnknownTimeZoneError
import social_auth.middleware
from django.utils import timezone
from .conf import settings


class SocialAuthExceptionMiddleware(social_auth.middleware.SocialAuthExceptionMiddleware):
    def raise_exception(self, request, exception):
        return False


class TimezoneMiddleware(object):
    def process_request(self, request):
        tz = request.session.get('django_timezone')
        if tz:
            try:
                timezone.activate(tz)
            except UnknownTimeZoneError:
                tz = settings.TIME_ZONE
                request.session['django_timezone'] = tz
                timezone.activate(tz)