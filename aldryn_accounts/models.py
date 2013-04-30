# -*- coding: utf-8 -*-
import datetime
import urllib
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import models, IntegrityError
from django.db.models import Q
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import operator
from aldryn_accounts import signals
from aldryn_accounts.signals import signup_code_used, signup_code_sent
from aldryn_accounts.utils import random_token, user_display
from aldryn_accounts.conf import *
import timezone_field


class SignupCode(models.Model):

    class AlreadyExists(Exception):
        pass

    class InvalidCode(Exception):
        pass

    code = models.CharField(max_length=64, unique=True)
    max_uses = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(null=True, blank=True)
    invited_by = models.ForeignKey(User, null=True, blank=True)
    email = models.EmailField(blank=True)
    notes = models.TextField(blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    use_count = models.PositiveIntegerField(editable=False, default=0)

    def __unicode__(self):
        if self.email:
            return u"%s [%s]" % (self.email, self.code)
        else:
            return self.code

    @classmethod
    def exists(cls, code=None, email=None):
        checks = []
        if code:
            checks.append(Q(code=code))
        if email:
            checks.append(Q(email=code))
        return cls._default_manager.filter(reduce(operator.or_, checks)).exists()

    @classmethod
    def create(cls, **kwargs):
        email, code = kwargs.get("email"), kwargs.get("code")
        if kwargs.get("check_exists", True) and cls.exists(code=code, email=email):
            raise cls.AlreadyExists()
        expires_at = timezone.now() + datetime.timedelta(hours=kwargs.get("expires_at", 24))
        if not code:
            code = random_token([email]) if email else random_token()
        params = {
            "code": code,
            "max_uses": kwargs.get("max_uses", 0),
            "expires_at": expires_at,
            "invited_by": kwargs.get("invited_by"),
            "notes": kwargs.get("notes", "")
        }
        if email:
            params["email"] = email
        return cls(**params)

    @classmethod
    def check(cls, code):
        try:
            signup_code = cls._default_manager.get(code=code)
        except cls.DoesNotExist:
            raise cls.InvalidCode()
        else:
            if signup_code.max_uses and signup_code.max_uses <= signup_code.use_count:
                raise cls.InvalidCode()
            else:
                if signup_code.expiry and timezone.now() > signup_code.expiry:
                    raise cls.InvalidCode()
                else:
                    return signup_code

    def calculate_use_count(self):
        self.use_count = self.signupcoderesult_set.count()
        self.save()

    def use(self, user):
        """
        Add a SignupCode result attached to the given user.
        """
        result = SignupCodeResult()
        result.signup_code = self
        result.user = user
        result.save()
        signup_code_used.send(sender=result.__class__, signup_code_result=result)

    def send(self, **kwargs):
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = kwargs["site"] if "site" in kwargs else Site.objects.get_current()
        signup_url = u"%s://%s%s?%s" % (
            protocol,
            unicode(current_site.domain),
            reverse("account_signup"),
            urllib.urlencode({"code": self.code})
            )
        ctx = {
            "signup_code": self,
            "current_site": current_site,
            "signup_url": signup_url,
            }
        subject = render_to_string("account/email/invite_user_subject.txt", ctx)
        message = render_to_string("account/email/invite_user.txt", ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [self.email])
        self.sent_at = timezone.now()
        self.save()
        signup_code_sent.send(sender=SignupCode, signup_code=self)


class SignupCodeResult(models.Model):

    signup_code = models.ForeignKey(SignupCode)
    user = models.ForeignKey(User)
    timestamp = models.DateTimeField(default=datetime.datetime.now)

    def save(self, **kwargs):
        super(SignupCodeResult, self).save(**kwargs)
        self.signup_code.calculate_use_count()


class EmailAddressManager(models.Manager):

    def add_email(self, user, email, make_primary=False, **kwargs):
        try:
            is_first_email = user and email and not self.filter(user=user).exists()
            email_address, created = self.get_or_create(user=user, email=email, defaults=kwargs)
            if not created:
                for key, value in kwargs.items():
                    setattr(email_address, key, value)
                email_address.save()
            if is_first_email or make_primary:
                email_address.set_as_primary()
            return email_address
        except IntegrityError:
            return None

    def get_primary(self, user):
        try:
            return self.get(user=user, is_primary=True)
        except self.model.DoesNotExist:
            return None

    def get_user_for(self, email):
        return self.get(email=email)

    def has_verified_email(self, user):
        return self.filter(user=user).exists()


class EmailAddress(models.Model):
    """
    All verified email addresses. If it's not verified it should not be here.
    """
    is_verified = True
    user = models.ForeignKey(User)
    email = models.EmailField(unique=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    verification_method = models.CharField(max_length=255, blank=True, default='unknown')
    is_primary = models.BooleanField(default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")

    def clean(self):
        self.email = self.email.strip().lower()

    def __unicode__(self):
        return u"%s (%s)" % (self.email, self.user)

    def set_as_primary(self):
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            old_primary.is_primary = False
            old_primary.save()
        self.is_primary = True
        self.save()
        self.user.email = self.email
        self.user.save()
        return True


class EmailConfirmationManager(models.Manager):
    def delete_expired_confirmations(self):
        for confirmation in self.all():
            if confirmation.key_expired():
                confirmation.delete()

    def request(self, user, email, is_primary=False, send=False):
        key = random_token([email])
        email_confirmation = self.create(user=user, email=email, key=key, is_primary=is_primary)
        if send:
            email_confirmation.send()
        return email_confirmation


class EmailConfirmation(models.Model):
    user = models.ForeignKey(User)
    email = models.EmailField()
    is_primary = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now())
    sent_at = models.DateTimeField(null=True)
    key = models.CharField(max_length=64, unique=True)

    objects = EmailConfirmationManager()

    class Meta:
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")

    def __unicode__(self):
        return u"confirmation for %s (%s)" % (self.email, self.user)

    def clean(self):
        self.email = self.email.strip().lower()

    def key_expired(self):
        expiration_date = self.sent_at + datetime.timedelta(days=settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS)
        return expiration_date <= timezone.now()
    key_expired.boolean = True

    def confirm(self, verification_method='unknown', delete=True):
        if self.sent_at and not self.key_expired():
            data = dict(
                verified_at=timezone.now(),
                verification_method=verification_method,
            )
            email_address = EmailAddress.objects.add_email(
                user=self.user, email=self.email, make_primary=self.is_primary, **data)
            signals.email_confirmed.send(sender=self.__class__, email_address=email_address)
            self.delete()
            return email_address

    def send(self, **kwargs):
        # TODO: send as HTML email
        site = kwargs["site"] if "site" in kwargs else Site.objects.get_current()
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        activate_url = u"%s://%s%s" % (
            protocol,
            unicode(site.domain),
            reverse("accounts_confirm_email", args=[self.key])
            )
        ctx = {
            "email": self.email,
            "user": self.user,
            "name": user_display(self.user),
            "activate_url": activate_url,
            "site": site,
            "site_name": site.name,
            "site_domain": site.domain,
            "key": self.key,
            }
        subject = render_to_string("aldryn_accounts/email/email_confirmation.subject.txt", ctx)
        subject = "".join(subject.splitlines()) # remove superfluous line breaks
        message = render_to_string("aldryn_accounts/email/email_confirmation.body.txt", ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [self.email])
        self.sent_at = timezone.now()
        self.save()
        signals.email_confirmation_sent.send(sender=self.__class__, confirmation=self)


class UserSettings(models.Model):
    user = models.OneToOneField(User, related_name='settings', unique=True, db_index=True)
    timezone = timezone_field.TimeZoneField(blank=True, null=True, default=None)
