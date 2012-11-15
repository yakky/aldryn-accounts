# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, include, url
from djangocms_accounts.views import LoginView, LogoutView, PasswordResetRecoverView, PasswordResetRecoverSentView
from djangocms_accounts.views import PasswordResetChangeView, PasswordResetChangeDoneView, ChangePasswordView
from djangocms_accounts.views import ProfileView
#from social_auth.views import auth, complete, disconnect



urlpatterns = patterns('',
    url(r"^login/$", LoginView.as_view(), name="accounts_login"), #
    url(r"^logout/$", LogoutView.as_view(), name="accounts_logout"),

    url(r'^password/reset/$', PasswordResetRecoverView.as_view(), name='accounts_password_reset_recover'),
    url(r'^password/reset/sent/(?P<signature>.+)/$', PasswordResetRecoverSentView.as_view(), name='accounts_password_reset_recover_sent'),
    url(r'^password/reset/change/(?P<token>[\w:-]+)/$', PasswordResetChangeView.as_view(), name='accounts_password_reset_change'),
    url(r'^password/reset/done/$', PasswordResetChangeDoneView.as_view(), name='accounts_password_reset_change_done'),

#    url(r"^signup/$", SignupView.as_view(), name="accounts_signup"),
    url(r"^me/$", ProfileView.as_view(), name="accounts_profile"),
    url(r"^me/password/change/$", ChangePasswordView.as_view(), name="accounts_change_password"),

#    url(r"^signup/$", SignupView.as_view(), name="account_signup"), #
#    url(r"^confirm_email/(?P<key>\w+)/$", ConfirmEmailView.as_view(), name="account_confirm_email"),
#    url(r"^password/$", ChangePasswordView.as_view(), name="account_password"),
#    url(r"^password/reset/$", PasswordResetView.as_view(), name="account_password_reset"),
#    url(r"^password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$", PasswordResetTokenView.as_view(), name="account_password_reset_token"),
#
#    url(r'^profile/$', ProfileView.as_view(), name="account_profile"),
#    url(r'^profile/associations/$', ProfileAssociationChoicesView.as_view(), name="account_associations"),
#    url(r"^email/$", SettingsView.as_view(), name="account_email"),
#    url(r"^settings/$", SettingsView.as_view(), name="account_settings"),
#    url(r"^delete/$", DeleteView.as_view(), name="account_delete"),
#
#
#
#    # Social Auth
#    url(r'^login/(?P<backend>[^/]+)/$', auth, name='socialauth_begin'),
#    url(r'^complete/(?P<backend>[^/]+)/$', complete, name='socialauth_complete'),
#    url(r'^disconnect/(?P<backend>[^/]+)/$', disconnect, name='socialauth_disconnect'),
#    url(r'^disconnect/(?P<backend>[^/]+)/(?P<association_id>[^/]+)/$', disconnect, name='socialauth_disconnect_individual'),

)