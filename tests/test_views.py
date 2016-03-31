# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.contrib.auth import  SESSION_KEY

from django.core import mail
from django.test import  override_settings
from django.core.urlresolvers import reverse
from django.utils.translation import override

from aldryn_accounts.models import SignupCode, EmailConfirmation
from .base import AllAccountsApphooksTestCase


# session engine is hardcoded in djangocms-helper (atm v0.9.4), so override
# per test case
@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cached_db')
class SignupViewTestCase(AllAccountsApphooksTestCase):
    veiw_name = "accounts_signup"

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=True)
    def test_get_not_logged_in_no_code(self):
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.get(view_url)
        self.assertContains(response, 'New? Register now')

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_get_not_logged_in_no_code(self):
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.get(view_url)
        self.assertContains(response, 'Signup is currently closed')

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_get_not_logged_with_not_valid_code(self):
        data = {
            'code': 'not valid code',
        }
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.get(view_url, data=data)
        self.assertContains(response, 'Signup is currently closed')

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_get_not_logged_with_valid_code(self):
        random_code = self.rand_str()
        new_code = SignupCode.create(code=random_code)
        new_code.save()
        data = {
            'code': new_code.code,
        }
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.get(view_url, data=data)
        self.assertContains(response, 'New? Register now')

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_post_with_not_valid_code(self):
        data = {
            'code': 'not valid code',
            'email': 'test@example.com',
        }
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.post(view_url, data=data)
        self.assertContains(response, 'Signup is currently closed')

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_get_with_valid_code(self):
        # ensure there is no users
        self.assertEqual(User.objects.count(), 0)

        random_code = self.rand_str()
        new_code = SignupCode.create(code=random_code)
        new_code.save()
        data = {
            'code': new_code.code,
            'email': 'test@example.com',
        }
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.post(view_url, data=data)
        self.assertEqual(User.objects.count(), 1)

    @override_settings(ALDRYN_ACCOUNTS_OPEN_SIGNUP=False)
    def test_get_with_logged_in_user(self):
        user = self.get_standard_user()
        with override('en'):
            view_url = reverse(self.veiw_name)
        self.client.login(username='standard', password='standard')
        response = self.client.get(view_url, follow=True)
        self.assertEqual(response.status_code, 302)


class SignupEmailResendConfirmationViewTestCase(AllAccountsApphooksTestCase):
    veiw_name = "accounts_signup_email_resend_confirmation"

    def test_get(self):
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.get(view_url)
        # test that there is the text from template
        self.assertContains(response, 'Send again the confirmation email')
        # and submit button
        self.assertContains(
            response, 'Yes, send me the confirmation email again')

    def test_post_with_invalid_email(self):
        data = {
            'email': 'wrong@example.com',
        }
        mail.outbox = []
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.post(view_url, data=data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 0)

    def test_post_with_valid_email(self):
        user = self.get_standard_user()
        test_email = 'test@example.com'
        new_confirmation = EmailConfirmation.objects.request(
            user=user,
            email=test_email,
        )
        mail.outbox = []
        data = {
            'email': new_confirmation.email,
        }
        with override('en'):
            view_url = reverse(self.veiw_name)
        response = self.client.post(view_url, data=data)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(response.status_code, 302)


class SignupEmailConfirmationSentViewTestCase(AllAccountsApphooksTestCase):
    view_name = 'accounts_signup_email_confirmation_sent'

    def test_get_no_email(self):
        with override('en'):
            view_url = reverse(self.view_name)
        response = self.client.get(view_url)
        self.assertContains(response, 'We have sent you an email to')

    def test_getwith_email(self):
        test_email = 'test@examole.com'
        data = {
            'email': test_email,
        }
        lookup_string = 'We have sent you an email to <b>{0}</b>'
        with override('en'):
            view_url = reverse(self.view_name)
        response = self.client.get(view_url, data=data)
        self.assertContains(response, lookup_string.format(test_email))


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.cached_db')
class LoginViewTestCase(AllAccountsApphooksTestCase):

    def login(self, username='standard', password='standard'):
        with override('en'):
            login_url = reverse('login')
        response = self.client.post(login_url, {
            'username': username,
            'password': password,
        })
        self.assertIn(SESSION_KEY, self.client.session)
        return response

    def test_login_view_get(self):
        with override('en'):
            login_url = reverse('login')
        response = self.client.get(login_url)
        self.assertEqual(response.status_code, 200)

    def test_login_view_logins(self):
        self.get_standard_user()
        self.login()

    def test_logout(self):
        self.get_standard_user()
        self.login()
        # test logout
        with override('en'):
            logout_url = reverse('login')
        response = self.client.get(logout_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_KEY, self.client.session)