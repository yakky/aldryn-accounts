# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, include, url
from djangocms_accounts.views import LoginView, LogoutView, PasswordResetRecoverView, PasswordResetRecoverSentView,\
    ProfileAssociationsView, PasswordResetChangeView, PasswordResetChangeDoneView, ChangePasswordView, \
    ProfileView, CreatePasswordView, ProfileEmailListView, ProfileEmailConfirmationCreateView, ProfileEmailConfirmationCancelView, ProfileEmailDeleteView, ProfileEmailMakePrimaryView, ConfirmEmailView
import social_auth.views



urlpatterns = patterns('',
    url(r"^login/$", LoginView.as_view(), name="accounts_login"), #
    url(r"^logout/$", LogoutView.as_view(), name="accounts_logout"),

    url(r'^password/reset/$', PasswordResetRecoverView.as_view(), name='accounts_password_reset_recover'),
    url(r'^password/reset/sent/(?P<signature>.+)/$', PasswordResetRecoverSentView.as_view(), name='accounts_password_reset_recover_sent'),
    url(r'^password/reset/change/(?P<token>[\w:-]+)/$', PasswordResetChangeView.as_view(), name='accounts_password_reset_change'),
    url(r'^password/reset/done/$', PasswordResetChangeDoneView.as_view(), name='accounts_password_reset_change_done'),

    url(r"^email/confirm/(?P<key>\w+)/$", ConfirmEmailView.as_view(), name="accounts_confirm_email"),

    #    url(r"^signup/$", SignupView.as_view(), name="accounts_signup"),
    url(r"^me/$", ProfileView.as_view(), name="accounts_profile"),
    url(r"^me/associations/$", ProfileAssociationsView.as_view(), name="accounts_profile_associations"),
    url(r"^me/password/change/$", ChangePasswordView.as_view(), name="accounts_change_password"),
    url(r"^me/password/create/$", CreatePasswordView.as_view(), name="accounts_create_password"),

    url(r"^me/emails/$", ProfileEmailListView.as_view(), name="accounts_email_list"),
    url(r"^me/email/add/$", ProfileEmailConfirmationCreateView.as_view(), name="accounts_email_create"),
    url(r"^me/email/confirmation/(?P<pk>\d+)/cancel/$", ProfileEmailConfirmationCancelView.as_view(), name="accounts_email_confirmation_cancel"),
    url(r"^me/email/(?P<pk>\d+)/delete/$", ProfileEmailDeleteView.as_view(), name="accounts_email_delete"),
    url(r"^me/email/(?P<pk>\d+)/make_primary/$", ProfileEmailMakePrimaryView.as_view(), name="accounts_email_make_primary"),

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
    # Social Auth
    url(r'^login/(?P<backend>[^/]+)/$', social_auth.views.auth, name='socialauth_begin'),
    url(r'^complete/(?P<backend>[^/]+)/$', social_auth.views.complete, name='socialauth_complete'),
    url(r'^disconnect/(?P<backend>[^/]+)/$', social_auth.views.disconnect, name='socialauth_disconnect'),
    url(r'^disconnect/(?P<backend>[^/]+)/(?P<association_id>[^/]+)/$', social_auth.views.disconnect, name='socialauth_disconnect_individual'),

)