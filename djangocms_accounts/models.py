# -*- coding: utf-8 -*-
import datetime
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import models, IntegrityError
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from djangocms_accounts import signals
from djangocms_accounts.utils import random_token
from djangocms_accounts.conf import settings
from uuidfield import UUIDField


class EmailAddressManager(models.Manager):

    def add_email(self, user, email, **kwargs):
        try:
            email_address = self.create(user=user, email=email, **kwargs)
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


class EmailAddress(models.Model):
    """
    All verified email addresses. If it's not verified it should not be here.
    """
    is_verified = True
    user = models.ForeignKey(User)
    email = models.EmailField(unique=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    verification_method = models.CharField(max_length=255, blank=True, default='')
    is_primary = models.BooleanField(default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")

    def clean(self):
        self.email = self.email.lower()

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

    def request(self, user, email, send=False):
        key = random_token([email])
        email_confirmation = self.create(user=user, email=email, key=key)
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
        self.email = self.email.lower()

    def key_expired(self):
        expiration_date = self.sent_at + datetime.timedelta(days=settings.ACCOUNTS_EMAIL_CONFIRMATION_EXPIRE_DAYS)
        return expiration_date <= timezone.now()
    key_expired.boolean = True

    def confirm(self, method='default', delete=True):
        if self.sent_at and not self.key_expired():
            data = dict(
                verified_at=timezone.now(),
                verification_method=method,
            )
            email_address, created = EmailAddress.objects.get_or_create(user=self.user, email=self.email, defaults=data)
            if not created:
                for key, value in data.items():
                    setattr(email_address, key, value)
                email_address.save()
            if self.is_primary:
                email_address.set_as_primary()
            signals.email_confirmed.send(sender=self.__class__, email_address=email_address)
            self.delete()
            return email_address

    def send(self, **kwargs):
        # TODO: send as HTML email
        current_site = kwargs["site"] if "site" in kwargs else Site.objects.get_current()
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        activate_url = u"%s://%s%s" % (
            protocol,
            unicode(current_site.domain),
            reverse("accounts_confirm_email", args=[self.key])
            )
        ctx = {
            "email": self.email,
            "user": self.user,
            "activate_url": activate_url,
            "current_site": current_site,
            "key": self.key,
            }
        subject = render_to_string("accounts/email/email_confirmation.subject.txt", ctx)
        subject = "".join(subject.splitlines()) # remove superfluous line breaks
        message = render_to_string("accounts/email/email_confirmation.body.txt", ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [self.email])
        self.sent_at = timezone.now()
        self.save()
        signals.email_confirmation_sent.send(sender=self.__class__, confirmation=self)