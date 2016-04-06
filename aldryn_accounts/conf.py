# -*- coding: utf-8 -*-
from django.conf import settings
from appconf import AppConf

ADD_TO_INSTALLED_APPS = [
    'password_reset',
    'social_auth',
    'absolute',
    # 'django_gravatar',
    'aldryn_common',
    'standard_form',
]

ADD_TO_MIDDLEWARE_CLASSES = [
    'aldryn_accounts.middleware.GeoIPMiddleware',
    'aldryn_accounts.middleware.TimezoneMiddleware',  # TimezoneMiddleware relies on GeoIP location.
    'aldryn_accounts.middleware.SocialAuthExceptionMiddleware',
]

# should be used if social login is configured
SOCIAL_CONTEXT_PROCESSORS = [
    'social_auth.context_processors.social_auth_login_redirect',
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
    SIGNUP_REDIRECT_URL = 'accounts_profile'
    NOTIFY_PASSWORD_CHANGE = True  # whether a confirmation email should be sent out whenever the password is changed
    PASSWORD_CHANGE_REDIRECT_URL = 'accounts_profile'
    EMAIL_CONFIRMATION_REQUIRED = True  # whether emails need to be confirmed in order to get an active account. False IS NOT SUPPORTED YET!
    EMAIL_CONFIRMATION_EMAIL = True  # whether to send out a confirmation email when a user signs up
    EMAIL_CONFIRMATION_EXPIRE_DAYS = 3  # how long a confirmation email code is valid
    SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL = ['google']  # which backends can be trusted to provide validated email addresses
    SUPPORT_EMAIL = settings.DEFAULT_FROM_EMAIL

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

    LOGIN_REDIRECT_URL = '/'

    PROFILE_IMAGE_UPLOAD_TO = 'profile-data'

    USE_PROFILE_APPHOOKS = False

    def enable_authentication_backend(self, name):
        s = self._meta.holder
        if not name in s.AUTHENTICATION_BACKENDS:
            s.AUTHENTICATION_BACKENDS.append(name)

    def configure_enable_github_login(self, value):
        if value:
            self.enable_authentication_backend('social_auth.backends.contrib.github.GithubBackend')

    def configure_enable_facebook_login(self, value):
        if value:
            self.enable_authentication_backend('social_auth.backends.facebook.FacebookBackend')

    def configure_enable_twitter_login(self, value):
        if value:
            self.enable_authentication_backend('social_auth.backends.twitter.TwitterBackend')

    def configure_enable_google_login(self, value):
        if value:
            self.enable_authentication_backend('social_auth.backends.google.GoogleBackend')

    def configure(self):
        if not self.configured_data['AUTOCONFIGURE']:
            return self.configured_data
        # do auto configuration
        s = self._meta.holder
        # add our apps to INSTALLED_APPS
        for app in ADD_TO_INSTALLED_APPS:
            if not app in s.INSTALLED_APPS:
                s.INSTALLED_APPS.append(app)
        # insert our middlewares after the session middleware
        pos = s.MIDDLEWARE_CLASSES.index('django.contrib.sessions.middleware.SessionMiddleware') + 1
        for middleware in ADD_TO_MIDDLEWARE_CLASSES:
            if not middleware in s.MIDDLEWARE_CLASSES:
                s.MIDDLEWARE_CLASSES.insert(pos, middleware)
                pos = pos + 1
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
