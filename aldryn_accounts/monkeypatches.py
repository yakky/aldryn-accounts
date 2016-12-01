# -*- coding: utf-8 -*-


def patch_user_unicode():
    from django.contrib.auth.models import User
    from .utils import user_display
    User.__unicode__ = user_display
