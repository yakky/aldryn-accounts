# -*- coding: utf-8 -*-
from django.conf import settings

try:
    from django.conf.urls import include, url
except ImportError:
    from django.conf.urls.defaults import include, url

urlpatterns = []

ALDRYN_ACCOUNTS_ENABLE_PYTHON_SOCIAL_AUTH = getattr(settings, 'ALDRYN_ACCOUNTS_ENABLE_PYTHON_SOCIAL_AUTH', False)
if ALDRYN_ACCOUNTS_ENABLE_PYTHON_SOCIAL_AUTH:
    urlpatterns += [
        url('_psa/', include('social_django.urls', namespace='social'))
    ]
