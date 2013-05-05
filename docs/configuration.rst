Manual Configuration
====================

incomplete!

``INSTALLED_APPS``::

    'aldryn_accounts',
    'password_reset',
    'social_auth',
    'absolute',
    'django_gravatar',


``TEMPLATE_CONTEXT_PROCESSORS``::

    'social_auth.context_processors.social_auth_backends',
    'social_auth.context_processors.social_auth_login_redirect',
    'aldryn_accounts.context_processors.account_info',



``AUTHENTICATION_BACKENDS``::

    'aldryn_accounts.auth_backends.EmailBackend',
    'aldryn_accounts.auth_backends.PermissionBackend',


Add any social-auth backends to ``AUTHENTICATION_BACKENDS`` you'd like to use.
See http://django-social-auth.readthedocs.org/en/latest/backends/index.html on details how to configure the individual backends. Currently only
Github, Gmail, Twitter and Facebook have been tested.