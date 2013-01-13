==================
djangocms-accounts
==================

Warning:: this is still work in progress.

``djangocms-accounts`` provides a packaged and opinionated app to provide:

* user signup
* login
* logout
* password change
* password reset
* adding and removing emails (with confirmation)
* login with external providers (gmail, github, facebook, twitter, ...)

Some assumptions:

* Emails

  * User can have multiple email adresses. Each is verified individually.
  * Each user only has one primary email at any given time.
  * To change an email the user can add a new one, verify it and then make it his new primary email. Then he can delete the old one.
  * Users can use any of his email addresses to login (if he has defined a password)

* Social Login

  * User that login with an external service are not forced to have an email (TODO: bug the user to add/validate an email)
  * Multiple external services and a local password can all be assigned to the same user. Although only one account per service type is possible.


Installation
============

as package (make sure to use ``--extra-index-url http://...`` to use the internal divio package server)::

    pip install djangocms-accounts


from source for local development (*whilst in the project virtualenv*)::

    git clone git@github.com:divio/djangocms-accounts.git
    cd djangocms-accounts
    pip install -e .  # installs all the dependencies in setup.py
    python setup.py develop  # adds this source directory to the python path


Configuration
=============

``INSTALLED_APPS``::

    'djangocms_accounts',
    'password_reset',
    'social_auth',
    'absolute',



``TEMPLATE_CONTEXT_PROCESSORS``::

    'social_auth.context_processors.social_auth_backends',
    'social_auth.context_processors.social_auth_login_redirect',
    'djangocms_accounts.context_processors.account_info',



``AUTHENTICATION_BACKENDS``::

    'djangocms_accounts.auth_backends.EmailBackend',


Add any social-auth backends to ``AUTHENTICATION_BACKENDS`` you'd like to use.
See https://github.com/omab/django-social-auth on details how to configure the individual backends. Currently only
Github, Gmail, Twitter and Facebook have been tested.

Then either add ``AccountsApphook`` to a page or include ``accounts.urls``. Preferrably at ``/account/``.

Run migrations.

``djangocms-accounts`` requires the django messages framework to display notifications.
see https://docs.djangoproject.com/en/dev/ref/contrib/messages/


Related Apps:

* https://github.com/omab/django-social-auth
