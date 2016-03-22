# -*- coding: utf-8 -*-
from django.test import TestCase


class TestEnvironment(TestCase):

    def test_running_test_cases(self):
        self.assertEqual(1+1, 2)
