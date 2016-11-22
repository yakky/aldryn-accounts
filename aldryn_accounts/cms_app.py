# -*- coding: utf-8 -*-
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from cms.app_base import CMSApp
from cms.apphook_pool import apphook_pool

from . import urls_i18n


class AldrynAccountsUserProfileIndexApphook(CMSApp):
    name = _("user profile: index")
    urls = [urls_i18n.profile_index_urlpatterns]


class AldrynAccountsUserProfileSettingsApphook(CMSApp):
    name = _("user profile: settings")
    urls = [urls_i18n.profile_settings_urlpatterns]


class AldrynAccountsUserProfileChangePasswordApphook(CMSApp):
    name = _("user profile: change password")
    urls = [urls_i18n.change_password_urlpatterns]


class AldrynAccountsUserProfileEmailSettingsApphook(CMSApp):
    name = _("user profile: E-Mail settings")
    urls = [urls_i18n.email_settings_urlpatterns]


if settings.ALDRYN_ACCOUNTS_USE_PROFILE_APPHOOKS:
    apphook_pool.register(AldrynAccountsUserProfileIndexApphook)
    apphook_pool.register(AldrynAccountsUserProfileSettingsApphook)
    apphook_pool.register(AldrynAccountsUserProfileChangePasswordApphook)
    apphook_pool.register(AldrynAccountsUserProfileEmailSettingsApphook)
