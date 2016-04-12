# -*- coding: utf-8 -*-
try:
    from collections import OrderedDict
except ImportError:
    from django.utils.datastructures import SortedDict as OrderedDict
from .utils import user_display
from .conf import settings


def account_info(request):
    return {
        'username': user_display(request.user),
    }


def empty_login_and_signup_forms(request):
    from .views import LoginView, SignupView  # TODO: make this configurable?
    return {
        'empty_login_form': LoginView.form_class(),
        'empty_signup_form': SignupView.form_class(),
    }


def django_settings(request):
    return {'settings': settings}


def notifications(request):
    if request.user.is_anonymous():
        return {}
    from .notifications import check_notifications
    return {'account_notifications': check_notifications(request.user)}
