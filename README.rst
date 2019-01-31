**Deprecated**

This project is no longer supported.

Divio will undertake no further development or maintenance of this project. If you are interested in  taking responsibility for this project as its maintainer, please contact us via www.divio.com.


===============
aldryn-accounts
===============

Warning:: this is still work in progress.

``aldryn-accounts`` provides a packaged and opinionated app to provide:

* user signup
* login
* logout
* password change
* password reset
* adding and removing emails (with verification)
* login with external providers (gmail, github, facebook, twitter, ...)

Some assumptions:

* Login works with social logins or email. But there is no custom username.

* Emails

  * Users can have multiple email adresses. Each is verified individually.
  * Each user only has one primary email at any given time.
  * To change an email the user can add a new one, verify it and then make it his new primary email. Then he can delete the old one.
  * Users can use any of his email addresses to login (if he has defined a password)
  * Users are not forced to validate their email right away. Instead we nag them about it and provide a permission
    that can be checked to see if a user hat at least one validated email.

* Social Login

  * Users that login with an external service are not forced to have an email (TODO: bug the user to add/validate an email)
  * Multiple external services and a local password can all be assigned to the same user. Although only one account per service type is possible.


Installation
============

as package (make sure to use ``--extra-index-url http://...`` to use the internal divio package server)::

    pip install aldryn-accounts


from source for local development (*whilst in the project virtualenv*)::

    git clone git@github.com:divio/djangocms-accounts.git
    cd djangocms-accounts
    pip install -e .  # installs all the dependencies in setup.py
    python setup.py develop  # adds this source directory to the python path


Configuration
=============


In your project’s settings.py make sure you have all of:

``INSTALLED_APPS``::

    'aldryn_accounts',
    'easy_thumbnails',
    'absolute',
    'password_reset',
    'standard_form',
    'aldryn_common',

listed in INSTALLED_APPS, after 'cms'.
Then either add ``AccountsApphook`` to a page or include ``aldryn_accounts.urls``. Preferrably at ``/accounts/``.

WARN:: currently the app must be connected at ``/accounts/`` to work properly.


Run migrations.

``aldryn-accounts`` requires the django messages framework to display notifications.
see https://docs.djangoproject.com/en/dev/ref/contrib/messages/


WARN:: make sure you have the correct domain set in ``django.contrib.sites``. It is used for redirect urls and will
       result in ``redirect_uri_mismatch`` errors with many social auth backends.

Setup in templates
==================

The bundled templates assume the template layout of the default aldryn boilerplate.
Additionally it is required to include ``aldryn_accounts/inc/notifications.html``. These are sticky notifications
similar to those of ``django.contrib.messages``, but stay until the corresponding situation is resolved.


Extending
=========

Custom Profile
--------------

Currently the basic tabs for social auth, emails and passwords are hardcoded. But the profile navigation can be extended
using django-cms apphooks. In order for this to work, create a cms page with the page_id ``profile_navigation`` and
choose ``aldryn_accounts/profile/base.html`` as the template. To add an element to the navigation just create a
subpage and assign your view logic as an AppHook.

Overriding
----------

To override login/signup and the core profile view (and anything else really), a custom ``urls`` can be defined and
included before the builtin ``aldryn_accounts.urls``. Overriding the builtin Views with customized subclasses.

Email Sending
-------------

Email sending is handled in ``aldryn_accounts.email.EmailSender`` and can be inherited and overwritten. To make
``aldryn-accounts`` use your custom ``EmailSender`` class, specify a setting like so::

  ALDRYN_ACCOUNTS_EMAIL_SENDER = 'path.to.MyEmailSender'


Related Apps:
=============

* https://github.com/omab/django-social-auth
* TODO: add all the other dependencies
