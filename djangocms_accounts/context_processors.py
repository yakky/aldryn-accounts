# -*- coding: utf-8 -*-
from djangocms_accounts.utils import user_display


def account_info(request):
    return {
        'username': user_display(request.user)
    }
