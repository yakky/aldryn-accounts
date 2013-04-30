# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, include, url
from aldryn_accounts.views import LoginView, LogoutView, PasswordResetRecoverView, PasswordResetRecoverSentView,\
    ProfileAssociationsView, PasswordResetChangeView, PasswordResetChangeDoneView, ChangePasswordView, \
    ProfileView, CreatePasswordView, ProfileEmailListView, ProfileEmailConfirmationCreateView, \
    ProfileEmailConfirmationCancelView, ProfileEmailDeleteView, ProfileEmailMakePrimaryView, ConfirmEmailView, \
    SignupView, SignupEmailView, SignupEmailSentView, UserSettingsView
import social_auth.views



urlpatterns = patterns('',
    url(r"^signup/$", SignupView.as_view(), name="accounts_signup"),
    url(r"^signup/email/$", SignupEmailView.as_view(), name="accounts_signup_email"),
    url(r"^signup/email/sent/$", SignupEmailSentView.as_view(), name="accounts_signup_email_sent"),

    url(r"^login/$", LoginView.as_view(), name="login"), #
    url(r"^logout/$", LogoutView.as_view(), name="logout"),

    url(r'^password_reset/$', PasswordResetRecoverView.as_view(), name='accounts_password_reset_recover'),
    url(r'^password_reset/sent/(?P<signature>.+)/$', PasswordResetRecoverSentView.as_view(), name='accounts_password_reset_recover_sent'),
    url(r'^password_reset/change/(?P<token>[\w:-]+)/$', PasswordResetChangeView.as_view(), name='accounts_password_reset_change'),
    url(r'^password_reset/done/$', PasswordResetChangeDoneView.as_view(), name='accounts_password_reset_change_done'),

    url(r"^email/confirm/(?P<key>\w+)/$", ConfirmEmailView.as_view(), name="accounts_confirm_email"),

    url(r"^profile/$", ProfileView.as_view(), name="accounts_profile"),
    url(r"^profile/settings/$", UserSettingsView.as_view(), name="accounts_settings"),
    url(r"^profile/associations/$", ProfileAssociationsView.as_view(), name="accounts_profile_associations"),
    url(r"^profile/password/change/$", ChangePasswordView.as_view(), name="accounts_change_password"),
    url(r"^profile/password/create/$", CreatePasswordView.as_view(), name="accounts_create_password"),

    url(r"^profile/emails/$", ProfileEmailListView.as_view(), name="accounts_email_list"),
    url(r"^profile/email/add/$", ProfileEmailConfirmationCreateView.as_view(), name="accounts_email_create"),
    url(r"^profile/email/confirmation/(?P<pk>\d+)/cancel/$", ProfileEmailConfirmationCancelView.as_view(), name="accounts_email_confirmation_cancel"),
    url(r"^profile/email/(?P<pk>\d+)/delete/$", ProfileEmailDeleteView.as_view(), name="accounts_email_delete"),
    url(r"^profile/email/(?P<pk>\d+)/make_primary/$", ProfileEmailMakePrimaryView.as_view(), name="accounts_email_make_primary"),

    # Social Auth
    url(r'^login/(?P<backend>[^/]+)/$', social_auth.views.auth, name='socialauth_begin'),
    url(r'^complete/(?P<backend>[^/]+)/$', social_auth.views.complete, name='socialauth_complete'),
    url(r'^disconnect/(?P<backend>[^/]+)/$', social_auth.views.disconnect, name='socialauth_disconnect'),
    url(r'^disconnect/(?P<backend>[^/]+)/(?P<association_id>[^/]+)/$', social_auth.views.disconnect, name='socialauth_disconnect_individual'),

)