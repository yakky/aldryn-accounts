# -*- coding: utf-8 -*-
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _
from django import forms


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label=_("Email"), max_length=100)