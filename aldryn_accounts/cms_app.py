# -*- coding: utf-8 -*-
from cms.app_base import CMSApp
from cms.apphook_pool import apphook_pool
from cms.menu_bases import CMSAttachMenu
from django.conf.urls import include, url, patterns
from django.core import urlresolvers
from django.utils.translation import ugettext_lazy as _
from menus.base import NavigationNode


#class AccountsProfileMenu(CMSAttachMenu):
#    name = _('Account Profile Menu')
#
#    def get_nodes(self, request):
#        nodes = [
#            NavigationNode(_('login'), urlresolvers.reverse('accounts:login'), 'login_id'),
#        ]
#        return nodes

# WARNING: don't use "AccountsApphook" as name, because it clashes with the shopplugnplay apphook.
# There should be multiple hooks for different parts anyway
# class AccountsStuffApphook(CMSApp):
#     name = _("Accounts")
# #    urls = [patterns('', url('^', include('aldryn_accounts.urls', namespace='accounts')))]
#     urls = ['aldryn_accounts.urls']
# #    menus = [AccountsProfileMenu]

# apphook_pool.register(AccountsApphook)