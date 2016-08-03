# -*- coding: utf-8 -*-
try:
    from django.conf.urls import include, patterns, url
except ImportError:
    from django.conf.urls.defaults import include, patterns, url

from .views import (
    LoginView, LogoutView, PasswordResetRecoverView, PasswordResetRecoverSentView,
    ProfileAssociationsView, PasswordResetChangeView, PasswordResetChangeDoneView,
    ChangePasswordView, ProfileView, CreatePasswordView, ProfileEmailListView,
    ProfileEmailConfirmationCancelView, ProfileEmailDeleteView, ProfileEmailMakePrimaryView,
    ConfirmEmailView, SignupView, SignupEmailResendConfirmationView,
    SignupEmailConfirmationSentView, SignupEmailSentView, UserSettingsView,
    ProfileEmailConfirmationResendView)
from .conf import settings


urlpatterns = patterns('',
    url(r"^signup/$", SignupView.as_view(), name="accounts_signup"),
    url(r"^signup/email/resend-confirmation/$", SignupEmailResendConfirmationView.as_view(), name="accounts_signup_email_resend_confirmation"),
    url(r"^signup/email/confirmation-sent/$", SignupEmailConfirmationSentView.as_view(), name="accounts_signup_email_confirmation_sent"),
    url(r"^signup/email/sent/$", SignupEmailSentView.as_view(), name="accounts_signup_email_sent"),

    url(r"^login/$", LoginView.as_view(), name="login"),
    url(r"^logout/$", LogoutView.as_view(), name="logout"),

    url(r'^password-reset/$', PasswordResetRecoverView.as_view(), name='accounts_password_reset_recover'),
    url(r'^password-reset/sent/(?P<signature>.+)/$', PasswordResetRecoverSentView.as_view(), name='accounts_password_reset_recover_sent'),
    url(r'^password-reset/change/(?P<token>[\w:-]+)/$', PasswordResetChangeView.as_view(), name='accounts_password_reset_change'),
    url(r'^password-reset/done/$', PasswordResetChangeDoneView.as_view(), name='accounts_password_reset_change_done'),

    url(r"^email/confirm/(?P<key>\w+)/$", ConfirmEmailView.as_view(), name="accounts_confirm_email"),
)


profile_index_urlpatterns = patterns('',
    url(r"^$", ProfileView.as_view(), name="accounts_profile"),
)


profile_settings_urlpatterns = patterns('',
    url(r"^$", UserSettingsView.as_view(), name="accounts_settings")
)


associations_urlpatterns = patterns('',
    url(r"^$", ProfileAssociationsView.as_view(), name="accounts_profile_associations"),
)


change_password_urlpatterns = patterns('',
    url(r"^$", ChangePasswordView.as_view(), name="accounts_change_password"),
    url(r"^create/$", CreatePasswordView.as_view(), name="accounts_create_password"),
)


email_settings_urlpatterns = patterns('',
    url(r"^$", ProfileEmailListView.as_view(), name="accounts_email_list"),
    url(r"^confirmation/(?P<pk>\d+)/re-send/$", ProfileEmailConfirmationResendView.as_view(), name="accounts_email_confirmation_resend"),
    url(r"^confirmation/(?P<pk>\d+)/cancel/$", ProfileEmailConfirmationCancelView.as_view(), name="accounts_email_confirmation_cancel"),
    url(r"^(?P<pk>\d+)/delete/$", ProfileEmailDeleteView.as_view(), name="accounts_email_delete"),
    url(r"^(?P<pk>\d+)/make_primary/$", ProfileEmailMakePrimaryView.as_view(), name="accounts_email_make_primary"),
)

ALDRYN_ACCOUNTS_USE_PROFILE_APPHOOKS = getattr(
    settings, 'ALDRYN_ACCOUNTS_USE_PROFILE_APPHOOKS', False)
if not ALDRYN_ACCOUNTS_USE_PROFILE_APPHOOKS:
    urlpatterns = urlpatterns + patterns('',
        url(r"^profile/settings/", include(profile_settings_urlpatterns)),
        url(r"^profile/associations/", include(associations_urlpatterns)),
        url(r"^profile/password/", include(change_password_urlpatterns)),
        url(r"^profile/email/", include(email_settings_urlpatterns)),
        url(r"^profile/", include(profile_index_urlpatterns)),
    )
