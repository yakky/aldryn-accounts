# -*- coding: utf-8 -*-
from collections import OrderedDict
from djangocms_accounts.utils import user_display
from social_auth.backends import get_backends
from social_auth.db.django_models import UserSocialAuth
from social_auth.utils import LazyDict


def account_info(request):
    return {
        'username': user_display(request.user),
    }


def social_auth_info(request):
    """
    similar to the social_auth.context_processors.social_auth_by_name_backends,
    but uses a OrderedDict and an easier format to use in templates.
    """
    # TODO: cache (LazyDict does not work well with key value iteration in templates
    keys = get_backends().keys()
    accounts = OrderedDict(zip(keys, [None] * len(keys)))
    user = request.user
    if hasattr(user, 'is_authenticated') and user.is_authenticated():
        accounts.update((assoc.provider.replace('-', '_'), assoc)
                        for assoc in UserSocialAuth.get_social_auth_for_user(user))
    return {'social_auth': accounts}