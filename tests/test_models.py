# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime

from django.conf import settings
from django.core import mail
from django.contrib.auth.models import User
from django.utils import timezone

from aldryn_accounts.models import (
    SignupCode, SignupCodeResult, EmailAddress, EmailConfirmation,
    UserSettings,
)
from aldryn_accounts.exceptions import (
    EmailAlreadyVerified, VerificationKeyExpired,
)

from .base import AllAccountsApphooksTestCase


class TestDataAttrsMixin(object):
    test_code1 = 'test_code1'
    test_email1 = 'test@example.com'
    user_email1 = 'test1@example.com'
    user_email2 = 'test2@example.com'


class SignupCodeTestCase(TestDataAttrsMixin, AllAccountsApphooksTestCase):

    def test_create_method_creates_no_args(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        created_code = SignupCode.create()
        created_code.save()
        self.assertEqual(SignupCode.objects.count(), 1)

    def test_create_method_creates_with_email(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        created_code = SignupCode.create(email=self.test_email1)
        created_code.save()
        self.assertEqual(SignupCode.objects.count(), 1)

    def test_create_method_creates_with_code(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        created_code = SignupCode.create(code=self.test_code1)
        created_code.save()
        self.assertEqual(SignupCode.objects.count(), 1)

    def test_exists_method_not_existing_email(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        self.assertFalse(SignupCode.exists(email=self.test_email1))

    def test_exists_method_not_existing_code(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        self.assertFalse(SignupCode.exists(code=self.test_code1))

    def test_exists_method_not_existing_code_and_email(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        self.assertFalse(SignupCode.exists(self.test_code1, self.test_email1))

    def test_exists_method_existing_email(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(email=self.test_email1)
        new_code.save()
        self.assertTrue(SignupCode.exists(email=self.test_email1))

    def test_exists_method_existing_code(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        self.assertTrue(SignupCode.exists(code=self.test_code1))

    def test_exists_method_existing_code_and_email(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(email=self.test_email1,
                                     code=self.test_code1)
        new_code.save()
        self.assertTrue(SignupCode.exists(self.test_code1, self.test_email1))

    def test_is_valid_with_valid_code(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        self.assertTrue(new_code.is_valid())

    def test_calculate_use_count_not_updaetes_if_no_usages(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        self.assertEqual(new_code.use_count, 0)
        # refresh and test db results
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 0)
        new_code.calculate_use_count()
        self.assertEqual(new_code.use_count, 0)
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 0)

    def test_calculate_use_count_updates_to_correct_value(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode(code=self.test_code1, use_count=1)
        new_code.save()
        self.assertEqual(new_code.use_count, 1)
        # refresh and test db results
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 1)
        new_code.calculate_use_count()
        self.assertEqual(new_code.use_count, 0)
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 0)

    def test_use_increases_use_counts(self):
        user = self.get_standard_user()
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        new_code.use(user)
        self.assertEqual(new_code.use_count, 1)
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 1)

    def test_send_sends_email_with_correct_code(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1,
                                     email=self.test_email1)
        new_code.save()
        mail.outbox = []
        new_code.send()
        self.assertEqual(len(mail.outbox), 1)
        invite_message = mail.outbox[0]
        self.assertIn(self.test_email1, invite_message.to)
        self.assertGreater(invite_message.body.find(self.test_code1), 0)


class SignupCodeResultTestCase(TestDataAttrsMixin,
                               AllAccountsApphooksTestCase):

    def test_save_increases_signup_code_use_count(self):
        self.assertEqual(SignupCode.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        self.assertEqual(new_code.use_count, 0)

        self.assertEqual(new_code.signupcoderesult_set.count(), 0)
        user = self.get_standard_user()
        signup_result = SignupCodeResult(
            signup_code=new_code,
            user=user
        )
        signup_result.save()
        self.assertEqual(new_code.use_count, 1)
        new_code = SignupCode.objects.get(pk=new_code.pk)
        self.assertEqual(new_code.use_count, 1)

    def test_if_signup_code_result_is_created_on_code_use(self):
        user = self.get_standard_user()
        self.assertEqual(SignupCode.objects.count(), 0)
        self.assertEqual(SignupCodeResult.objects.count(), 0)
        new_code = SignupCode.create(code=self.test_code1)
        new_code.save()
        new_code.use(user)
        self.assertEqual(SignupCodeResult.objects.count(), 1)
        code_result = SignupCodeResult.objects.get()
        self.assertEqual(code_result.signup_code.pk, new_code.pk)
        self.assertEqual(code_result.user, user)


class EmailAddressTestCase(TestDataAttrsMixin,
                           AllAccountsApphooksTestCase):

    def test_creation(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        email_address = EmailAddress(
            user=user,
            email=self.user_email1
        )
        email_address.save()
        self.assertEqual(EmailAddress.objects.count(), 1)

    def test_save_not_primary(self):
        user = self.get_standard_user()
        old_email = user.email

        self.assertEqual(EmailAddress.objects.count(), 0)
        email_address = EmailAddress(
            user=user,
            email=self.user_email1,
            is_primary=True,
        )
        email_address.save()
        self.assertEqual(EmailAddress.objects.count(), 1)
        user = User.objects.get(pk=user.pk)
        self.assertEqual(user.email, self.user_email1)

    def test_add_email_new(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        new_email = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email1
        )
        self.assertEqual(EmailAddress.objects.count(), 1)
        new_email = EmailAddress.objects.get(pk=new_email.pk)
        self.assertEqual(new_email.user, user)
        self.assertEqual(new_email.email, self.user_email1)

    def test_add_email_two_emails(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        new_email = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email1
        )
        self.assertEqual(EmailAddress.objects.count(), 1)
        new_email = EmailAddress.objects.get(pk=new_email.pk)
        self.assertEqual(new_email.user, user)
        self.assertEqual(new_email.email, self.user_email1)

        new_email2 = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email2
        )
        self.assertEqual(EmailAddress.objects.count(), 2)
        new_email2 = EmailAddress.objects.get(pk=new_email2.pk)

        self.assertEqual(new_email2.user, user)
        self.assertEqual(new_email2.email, self.user_email2)

    def test_get_primary(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        # test if no emails present
        self.assertIsNone(EmailAddress.objects.get_primary(
            user=user
        ))
        # test with one email
        new_email = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email1
        )
        self.assertEqual(EmailAddress.objects.count(), 1)
        primary = EmailAddress.objects.get_primary(user=user)
        self.assertEqual(new_email.pk, primary.pk)

        # test with two emails
        EmailAddress.objects.add_email(
            user=user,
            email=self.user_email2
        )
        self.assertEqual(EmailAddress.objects.count(), 2)
        primary = EmailAddress.objects.get_primary(user)
        # since second email was not primary - should be equal to the first one
        self.assertEqual(new_email.pk, primary.pk)

        # test with three emails
        new_email3 = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email2,
            make_primary=True,
        )
        self.assertEqual(EmailAddress.objects.count(), 2)
        primary = EmailAddress.objects.get_primary(user=user)
        # should be the last created primary email
        self.assertEqual(new_email3.pk, primary.pk)

    def test_get_user_for(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        new_email = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email1
        )
        self.assertEqual(EmailAddress.objects.count(), 1)
        # actually returns EmailAddress object, not user object
        result_email = EmailAddress.objects.get_user_for(new_email.email)
        self.assertEqual(user.pk, result_email.user.pk)

    def test_has_verified_email(self):
        user = self.get_standard_user()
        self.assertEqual(EmailAddress.objects.count(), 0)
        self.assertFalse(EmailAddress.objects.has_verified_email(user))
        new_email = EmailAddress.objects.add_email(
            user=user,
            email=self.user_email1
        )
        self.assertEqual(EmailAddress.objects.count(), 1)
        self.assertTrue(EmailAddress.objects.has_verified_email(user))


class EmailConfirmationTestCase(TestDataAttrsMixin,
                                AllAccountsApphooksTestCase):

    @property
    def test_key(self):
        return self.rand_str()

    def test_creation(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        new_confirmation = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
        )
        new_confirmation.save()
        self.assertEqual(EmailConfirmation.objects.count(), 1)

    def test_creation_from_request(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        new_confirmation = EmailConfirmation.objects.request(
            user=user,
            email=self.user_email1,
        )
        self.assertEqual(EmailConfirmation.objects.count(), 1)

    def test_creation_from_request_sends_email(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        mail.outbox = []
        new_confirmation = EmailConfirmation.objects.request(
            user=user,
            email=self.user_email1,
            send=True,
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(EmailConfirmation.objects.count(), 1)

    def test_delete_expired_confirmations(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        expire_days = getattr(
            settings,
            'ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS', 5)
        now = timezone.now()
        sent_at = now - datetime.timedelta(days=expire_days + 1)
        new_confirmation = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
            sent_at=sent_at,
        )
        new_confirmation.save()
        # ensure that confirmation was created
        self.assertEqual(EmailConfirmation.objects.count(), 1)
        # delete expired.
        EmailConfirmation.objects.delete_expired_confirmations()
        self.assertEqual(EmailConfirmation.objects.count(), 0)

        # test if there is no sent_at
        new_confirmation2 = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
        )
        new_confirmation2.save()
        self.assertEqual(EmailConfirmation.objects.count(), 1)
        EmailConfirmation.objects.delete_expired_confirmations()
        self.assertEqual(EmailConfirmation.objects.count(), 1)

    def test_key_expired(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        expire_days = getattr(
            settings,
            'ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS', 5)
        now = timezone.now()
        sent_at = now - datetime.timedelta(days=expire_days + 1)
        new_confirmation = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
            sent_at=sent_at,
        )
        new_confirmation.save()
        # ensure that confirmation was created
        self.assertEqual(EmailConfirmation.objects.count(), 1)
        self.assertTrue(new_confirmation.key_expired())

        # test for not expired key
        sent_at = now
        new_confirmation2 = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
            sent_at=sent_at,
        )
        new_confirmation2.save()
        self.assertFalse(new_confirmation2.key_expired())

    def test_confirm(self):
        user = self.get_standard_user()
        self.assertEqual(EmailConfirmation.objects.count(), 0)
        self.assertEqual(EmailAddress.objects.count(), 0)
        expire_days = getattr(
            settings,
            'ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS', 5)
        now = timezone.now()
        sent_at = now - datetime.timedelta(days=expire_days + 1)
        new_confirmation = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
            sent_at=sent_at,
        )
        new_confirmation.save()
        # ensure that confirmation was created
        self.assertEqual(EmailConfirmation.objects.count(), 1)
        self.assertRaises(VerificationKeyExpired, new_confirmation.confirm)

        # test for not expired key
        sent_at = now
        new_confirmation2 = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
            sent_at=sent_at,
        )
        new_confirmation2.save()
        new_confirmation2.confirm()
        self.assertEqual(EmailAddress.objects.count(), 1)

    def test_send_sents_confirmation(self):
        user = self.get_standard_user()
        new_confirmation = EmailConfirmation(
            user=user,
            email=self.user_email1,
            key=self.test_key,
        )
        new_confirmation.save()
        mail.outbox = []
        new_confirmation.send()
        self.assertEqual(len(mail.outbox), 1)
        self.assertIsNotNone(new_confirmation.sent_at)


class UserSettingsTestCase(AllAccountsApphooksTestCase):

    def test_user_settings_creation_with_defaults(self):
        user = self.get_standard_user()
        self.assertEqual(UserSettings.objects.count(), 0)
        new_settings = UserSettings(
            user=user,
        )
        new_settings.save()
        self.assertEqual(UserSettings.objects.count(), 1)
