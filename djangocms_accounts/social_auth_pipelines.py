# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.core import urlresolvers
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.shortcuts import redirect
from social_auth.backends import USERNAME

from social_auth.models import UserSocialAuth
from social_auth.exceptions import AuthException
from social_auth.signals import pre_update, socialauth_registered

from djangocms_accounts.conf import settings
from social_auth.utils import setting as social_auth_setting
from djangocms_accounts.models import EmailAddress

# TODO: finish (the code here does not work yet)


def associate_by_email_if_backend_is_trusted(details, user=None, backend=None, **kwargs):
    """Return user entry with same email address as one returned on details."""
    if user:
        return None
    if not backend.name in settings.ACCOUNTS_SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL:
        return None

    email = details.get('email')

    if email:
        # try to associate accounts registered with the same email address,
        # only if it's a single object. AuthException is raised if multiple
        # objects are returned
        try:
            return {'user': EmailAddress.objects.get(email=email).user}
        except MultipleObjectsReturned:
            raise AuthException(kwargs['backend'], 'Not unique email address.')
        except ObjectDoesNotExist:
            pass


def create_user(backend, details, response, uid, username, user=None, request=None, **kwargs):
    """Create user. Depends on get_username pipeline."""
    email = details.get('email')
    verified_email = None
    try:
        verified_email = EmailAddress.objects.get(email=email).email
    except EmailAddress.DoesNotExist:
        pass
    if user or not username:
        return {'user': user, 'verified_email': verified_email}

    user = User.objects.create_user(username=username, email='')
    if email and backend.name in settings.ACCOUNTS_SOCIAL_BACKENDS_WITH_TRUSTED_EMAIL:
        email_address = EmailAddress.objects.add_email(user=user, email=email)
        verified_email = email_address.email
    else:
        user.is_active = False
        user.save()

    return {
        'user': user,
        'is_new': True,
        'verified_email': verified_email
    }


def update_user_details(backend, details, response, user=None, is_new=False, *args, **kwargs):
    """
    Same as the one from social auth, except that we never save the email directly on the user object.
    # TODO: maybe we should strictly only update any user information on first signup and from then on ignore what social auth provides.
    Update user details using data from provider.
    """
    if user is None:
        return

    changed = False  # flag to track changes

    for name, value in details.iteritems():
        # do not update username, it was already generated
        # do not update configured fields if user already existed
        if name in (USERNAME, 'id', 'pk', 'email') or (not is_new and
                                              name in social_auth_setting('SOCIAL_AUTH_PROTECTED_USER_FIELDS', [])):
            continue
        if value and value != getattr(user, name, None):
            setattr(user, name, value)
            changed = True

    # Fire a pre-update signal sending current backend instance,
    # user instance (created or retrieved from database), service
    # response and processed details.
    #
    # Also fire socialauth_registered signal for newly registered
    # users.
    #
    # Signal handlers must return True or False to signal instance
    # changes. Send method returns a list of tuples with receiver
    # and it's response.
    signal_response = lambda (receiver, response): response
    signal_kwargs = {'sender': backend.__class__, 'user': user,
                     'response': response, 'details': details}

    changed |= any(filter(signal_response, pre_update.send(**signal_kwargs)))

    # Fire socialauth_registered signal on new user registration
    if is_new:
        changed |= any(filter(signal_response,
            socialauth_registered.send(**signal_kwargs)))

    if changed:
        user.save()


def redirect_to_email_form(backend, details, user=None, verified_email=None, request=None, **kwargs):
    if not user:
        return None
    if verified_email:
        return None

    # we don't have a verified email yet
    return redirect(urlresolvers.reverse('accounts_signup_email'))