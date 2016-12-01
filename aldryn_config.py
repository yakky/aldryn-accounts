# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import ast
from os import getenv as env

from aldryn_client import forms


class Form(forms.BaseForm):

    use_profile_apphooks = forms.CheckboxField(
        "Use profile app hooks",
        help_text=("Plug aldryn profile views as an app hook."
                   "If not checked - you need to add aldryn-accounts urls"
                   "to your project core urls manually."),
        required=False,
        initial=True,
    )
    open_signup = forms.CheckboxField(
        "Signup is open",
        help_text=("whether any user may signup. If set to False only "
                   "users with an invite code may sign up."),
        required=False,
        initial=True,
    )
    notify_password_change = forms.CheckboxField(
        "Notify password change",
        help_text=("whether a confirmation email should be sent out "
                   "whenever the password is changed"),
        required=False,
        initial=True,
    )
    password_change_redirect_url = forms.CharField(
        "Password change redirect url",
        help_text=(
            "Where to redirect users after a successful changed password. "
            "Leave empty for default."),
        required=False,
        initial='',
    )
    email_confirmation_email = forms.CheckboxField(
        "send confirmation email",
        help_text=(
            "Whether to send out a confirmation email when a user signs up"),
        required=False,
        initial=True,
    )
    email_confirmation_expire_days = forms.NumberField(
        "Email confirmation expires after, days",
        help_text="How long a confirmation email code is valid.",
        min_value=1,
        max_value=9999,
        initial=3,
    )
    restore_password_raise_validation_error = forms.CheckboxField(
        "Restore password raise validation error",
        help_text=(
            "Whether to raise validation error when user resotres password."),
        required=False,
        initial=True,
    )
    user_display_fallback_to_username = forms.CheckboxField(
        "User display name fallback to username",
        help_text=(
            "Whether to fallback to username when displaying a user."),
        required=False,
        initial=False,
    )
    user_display_fallback_to_pk = forms.CheckboxField(
        "User display fallback to pk",
        help_text=(
            "Whether to fallback to user id when displaying a user."),
        required=False,
        initial=False,
    )
    login_redirect_url = forms.CharField(
        "Login redirect url",
        help_text=(
            "Where to redirect users after a successful login. "
            "Warning! Should be a valid url, otherwise you will get "
            "404 errors."),
        required=True,
        initial='/',
    )
    signup_redirect_url = forms.CharField(
        "Signup redirect url",
        help_text=(
            "Where to redirect users after a sign up, Use view name from urls. "
            "please make sure that this view can be reversed, "
            "include namespace if needed."),
        required=True,
        initial='accounts_profile',
    )
    display_email_notifications = forms.CheckboxField(
        "Display not confirmed emails notification",
        help_text=(
            "Whether to display not confirmed emails notification on "
            "the top of the page."),
        required=False,
        initial=True,
    )
    display_password_notifications = forms.CheckboxField(
        "Display 'password not set' notification",
        help_text=(
            "Whether to display 'password not set' notification on "
            "the top of the page."),
        required=False,
        initial=True,
    )
    urls_prefix = forms.CharField(
        "Prefix for all URLs",
        help_text=(
            "For example 'accounts' -> '/accounts/login'"
        ),
        required=False,
    )
    enable_python_social_auth = forms.CheckboxField(
        'Enable social auth',
        required=False,
        initial=False,
    )

    # https://python-social-auth.readthedocs.io/en/latest/backends/google.html#google-oauth2
    psa_google_oauth2 = forms.CheckboxField(
        'Social Auth via Google OAuth2',
        required=False,
        initial=False,
    )

    psa_facebook_oauth2 = forms.CheckboxField(
        'Social Auth via Facebook OAuth2',
        required=False,
        initial=False,
    )

    def set_psa_settings(self, key_base, settings):
        for arg in ('KEY', 'SECRET', 'SCOPE'):
            key = '{}_{}'.format(key_base, arg)
            val = env(key)
            if arg == 'SCOPE':
                if val and val.startswith('['):
                    val = ast.literal_eval(val)
                else:
                    val = []
            settings[key] = val

    def extend_context_processors(self, settings, context_processors):
        if settings.get('TEMPLATES'):
            settings['TEMPLATES'][0]['OPTIONS'][
                'context_processors'] += context_processors
        else:
            settings['TEMPLATE_CONTEXT_PROCESSORS'] += context_processors

    def to_settings(self, data, settings):
        settings.update({
            'ALDRYN_ACCOUNTS_USE_PROFILE_APPHOOKS': data['use_profile_apphooks'],
            'ALDRYN_ACCOUNTS_OPEN_SIGNUP': data['open_signup'],
            'ALDRYN_ACCOUNTS_NOTIFY_PASSWORD_CHANGE': data['notify_password_change'],
            'ALDRYN_ACCOUNTS_PASSWORD_CHANGE_REDIRECT_URL': data['password_change_redirect_url'],
            'ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EMAIL': data['email_confirmation_email'],
            'ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS': data['email_confirmation_expire_days'],
            'ALDRYN_ACCOUNTS_RESTORE_PASSWORD_RAISE_VALIDATION_ERROR': data['restore_password_raise_validation_error'],
            'ALDRYN_ACCOUNTS_USER_DISPLAY_FALLBACK_TO_USERNAME': data['user_display_fallback_to_username'],
            'ALDRYN_ACCOUNTS_USER_DISPLAY_FALLBACK_TO_PK': data['user_display_fallback_to_pk'],
            'ALDRYN_ACCOUNTS_LOGIN_REDIRECT_URL': data['login_redirect_url'],
            'ALDRYN_ACCOUNTS_SIGNUP_REDIRECT_URL': data['signup_redirect_url'],
            'ALDRYN_ACCOUNTS_DISPLAY_EMAIL_NOTIFICATION': data['display_email_notifications'],
            'ALDRYN_ACCOUNTS_DISPLAY_PASSWORD_NOTIFICATION': data['display_password_notifications'],
            'ALDRYN_ACCOUNTS_URLS_PREFIX': data['urls_prefix'],
        })

        # setup accounts login features and other urls
        # we have to specify those urls because add-on urls
        settings.update({
            'LOGIN_URL': '/login/',
            'LOGOUT_URL': '/logout/',
        })
        settings['INSTALLED_APPS'].append('aldryn_accounts')
        settings['ADDON_URLS'].append('aldryn_accounts.urls')
        settings['ADDON_URLS_I18N'].append('aldryn_accounts.urls_i18n')

        self.extend_context_processors(settings, (
            'aldryn_accounts.context_processors.notifications',
        ))

        # social auth
        enable_psa = data['enable_python_social_auth']
        settings['ALDRYN_ACCOUNTS_ENABLE_PYTHON_SOCIAL_AUTH'] = enable_psa

        if enable_psa:
            settings['INSTALLED_APPS'].append('social.apps.django_app.default')
            add_to_auth_backends = settings['AUTHENTICATION_BACKENDS'].append

            if data['psa_google_oauth2']:
                add_to_auth_backends('social.backends.google.GoogleOAuth2')
                self.set_psa_settings('SOCIAL_AUTH_GOOGLE_OAUTH2', settings)

            if data['psa_facebook_oauth2']:
                add_to_auth_backends('social.backends.facebook.FacebookOAuth2')
                self.set_psa_settings('SOCIAL_AUTH_FACEBOOK', settings)

            self.extend_context_processors(settings, (
                'social.apps.django_app.context_processors.backends',
                'social.apps.django_app.context_processors.login_redirect',
            ))

            settings['SOCIAL_AUTH_PIPELINE'] = [
                'social.pipeline.social_auth.social_details',
                'social.pipeline.social_auth.social_uid',
                'social.pipeline.social_auth.auth_allowed',
                'social.pipeline.social_auth.social_user',
                'aldryn_accounts.social_auth_pipelines.get_username',
                'aldryn_accounts.social_auth_pipelines.require_email',
                'aldryn_accounts.social_auth_pipelines.link_to_existing_user_by_email_if_backend_is_trusted',
                'aldryn_accounts.social_auth_pipelines.create_user',
                'aldryn_accounts.social_auth_pipelines.set_profile_image',
                'social.pipeline.social_auth.associate_user',
                'social.pipeline.social_auth.load_extra_data',
                'social.pipeline.user.user_details',
                'aldryn_accounts.social_auth_pipelines.redirect_to_email_form',
            ]

            settings['ALDRYN_ACCOUNTS_SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL'] = (
                'facebook',
                'google-oauth2',
            )

        return settings
