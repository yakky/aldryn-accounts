# -*- coding: utf-8 -*-
from django.conf import settings

from appconf import AppConf


ADD_TO_INSTALLED_APPS = [
    'aldryn_accounts',
    'easy_thumbnails',
    'absolute',
    'standard_form',
    'aldryn_common',
    'social_django',
]

ADD_TO_MIDDLEWARE_CLASSES = [
    'aldryn_accounts.middleware.GeoIPMiddleware',
    'aldryn_accounts.middleware.TimezoneMiddleware',  # TimezoneMiddleware relies on GeoIP location.
    'social_django.middleware.SocialAuthExceptionMiddleware',
]

# should be used if social login is configured
SOCIAL_CONTEXT_PROCESSORS = [
    'social_django.context_processors.login_redirect',
    'aldryn_accounts.context_processors.social_auth_info',
]

ADD_TO_TEMPLATE_CONTEXT_PROCESSORS = [
    'aldryn_accounts.context_processors.account_info',
    'aldryn_accounts.context_processors.django_settings',
    'aldryn_accounts.context_processors.notifications',
]

ADD_TO_AUTHENTICATION_BACKENDS = [
    'aldryn_accounts.auth_backends.PermissionBackend',
    'aldryn_accounts.auth_backends.EmailBackend',
]


class AccountsAppConf(AppConf):
    AUTOCONFIGURE = True  # whether to provide simplefied configuration by auto setting many config
    OPEN_SIGNUP = True  # whether any user may signup. If set to False only users with an invite code may sign up.
    SIGNUP_REDIRECT_URL = 'aldryn_accounts:accounts_profile'
    EMAIL_CONFIRMATION_REDIRECT_URL = 'aldryn_accounts:accounts_email_list'
    SIGNUP_VIEW = 'aldryn_accounts.views.SignupView'
    LOGIN_VIEW = 'aldryn_accounts.views.LoginView'
    NOTIFY_PASSWORD_CHANGE = True  # whether a confirmation email should be sent out whenever the password is changed
    PASSWORD_CHANGE_REDIRECT_URL = 'aldryn_accounts:accounts_profile'
    EMAIL_CONFIRMATION_REQUIRED = True  # whether emails need to be confirmed in order to get an active account. False IS NOT SUPPORTED YET!
    EMAIL_CONFIRMATION_EMAIL = True  # whether to send out a confirmation email when a user signs up
    EMAIL_CONFIRMATION_EXPIRE_DAYS = 3  # how long a confirmation email code is valid
    SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL = ['facebook', 'google-oauth2']  # which backends can be trusted to provide validated email addresses
    CONNECT_TRUSTED_ACCOUNTS = True  # connect accounts with same email if backends are trusted and emails are verified
    SUPPORT_EMAIL = settings.DEFAULT_FROM_EMAIL
    # raise validation error on password restore if user has no confirmed email
    RESTORE_PASSWORD_RAISE_VALIDATION_ERROR = True
    USER_DISPLAY_FALLBACK_TO_USERNAME = False
    USER_DISPLAY_FALLBACK_TO_PK = False

    SOCIAL_BACKEND_ORDERING = []
    # if set to True - will add SOCIAL_CONTEXT_PROCESSORS to context processors
    USE_SOCIAL_CONTEXT_PROCESSORS = False

    ENABLE_SOCIAL_AUTH = False  # controls visibility of social auth related things in the UI
    ENABLE_GITHUB_LOGIN = False
    ENABLE_FACEBOOK_LOGIN = False
    ENABLE_TWITTER_LOGIN = False
    ENABLE_GOOGLE_LOGIN = False
    ENABLE_NOTIFICATIONS = True  # by now this is only used to suppress redundant "Confirmation email" message
    # if enabled GEOIP_PATH and GEOIP_CITY (this one defaults to
    # GeoLiteCity.dat) should be configured
    USE_GEOIP = False
    LOGIN_REDIRECT_URL = '/'
    NO_REMEMBER_ME_COOKIE_AGE = 3600  # for login with 'remember me' unticked

    PROFILE_IMAGE_UPLOAD_TO = 'profile-data'

    USE_PROFILE_APPHOOKS = False

    def enable_authentication_backend(self, name):
        s = self._meta.holder
        if not name in s.AUTHENTICATION_BACKENDS:
            s.AUTHENTICATION_BACKENDS.append(name)

    def configure_enable_github_login(self, value):
        if value:
            self.enable_authentication_backend('social_core.backends.github.GithubOAuth2')

    def configure_enable_facebook_login(self, value):
        if value:
            self.enable_authentication_backend('social_core.backends.facebook.FacebookOAuth2')

    def configure_enable_twitter_login(self, value):
        if value:
            self.enable_authentication_backend('social_core.backends.twitter.TwitterOAuth')

    def configure_enable_google_login(self, value):
        if value:
            self.enable_authentication_backend('social_core.backends.google.GoogleOAuth2')

    def configure(self):
        if not self.configured_data['AUTOCONFIGURE']:
            return self.configured_data
        # do auto configuration
        s = self._meta.holder
        # insert our middlewares after the session middleware
        pos = s.MIDDLEWARE_CLASSES.index('django.contrib.sessions.middleware.SessionMiddleware') + 1
        for app in ADD_TO_INSTALLED_APPS:
            if app not in s.INSTALLED_APPS:
                s.INSTALLED_APPS.append(app)
        for middleware in ADD_TO_MIDDLEWARE_CLASSES:
            if not middleware in s.MIDDLEWARE_CLASSES:
                s.MIDDLEWARE_CLASSES.insert(pos, middleware)
                pos += 1
        # add social context processors if needed.
        if self.configured_data['USE_SOCIAL_CONTEXT_PROCESSORS']:
            s.TEMPLATE_CONTEXT_PROCESSORS.extend(SOCIAL_CONTEXT_PROCESSORS)
        # insert our template context processors
        s.TEMPLATE_CONTEXT_PROCESSORS.extend(ADD_TO_TEMPLATE_CONTEXT_PROCESSORS)
        if not getattr(s, 'GITHUB_EXTENDED_PERMISSIONS', None):
            s.GITHUB_EXTENDED_PERMISSIONS = ['user:email']
        if not getattr(s, 'FACEBOOK_EXTENDED_PERMISSIONS', None):
            s.FACEBOOK_EXTENDED_PERMISSIONS = ['email']
        # insert our AUTHENTICATION_BACKENDS
        if not isinstance(s.AUTHENTICATION_BACKENDS, list):
            s.AUTHENTICATION_BACKENDS = list(s.AUTHENTICATION_BACKENDS)
        for auth_backend in ADD_TO_AUTHENTICATION_BACKENDS:
            if not auth_backend in s.AUTHENTICATION_BACKENDS:
                s.AUTHENTICATION_BACKENDS.append(auth_backend)
        return self.configured_data


class SocialAuthConf(AppConf):
    LOGIN_ERROR_URL = '/'  # TODO: make this something prettier (but needs changes in django-social-auth to allow multilingual urls)
    SIGNUP_ERROR_URL = '/'  # TODO: make this something prettier (but needs changes in django-social-auth to allow multilingual urls)

    class Meta:
        prefix = ''
