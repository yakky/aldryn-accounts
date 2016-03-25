# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.core import mail

from aldryn_accounts.models import (
    SignupCode, SignupCodeResult, EmailAddress, EmailConfirmation,
    UserSettings,
)

from .base import AllAccountsApphooksTestCase


class SignupCodeTestCase(AllAccountsApphooksTestCase):
    test_code1 = 'test_code1'
    test_email1 = 'test@example.com'

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
