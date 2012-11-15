# -*- coding: utf-8 -*-
from class_based_auth_views.utils import default_redirect
import class_based_auth_views.views
from django.contrib import messages
from django.contrib.sites.models import get_current_site
from django.core import urlresolvers
from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.views.generic import FormView, TemplateView
from djangocms_accounts import conf, signals
from djangocms_accounts.forms import EmailAuthenticationForm, ChangePasswordForm
from django.utils.translation import ugettext_lazy as _
import password_reset.views


class LoginView(class_based_auth_views.views.LoginView):
    template_name = 'accounts/login.html'
    form_class = EmailAuthenticationForm


class LogoutView(class_based_auth_views.views.LogoutView):
    template_name = 'accounts/logout.html'


class PasswordResetRecoverView(password_reset.views.Recover):
    case_sensitive = False
    template_name = 'accounts/password_reset_recover.html'
    email_template_name = 'accounts/email/password_reset_recover.body.txt'
    email_html_template_name = 'accounts/email/password_reset_recover.body.html'
    email_subject_template_name = 'accounts/email/password_reset_recover.subject.txt'

    def send_notification(self):
        # TODO: send HTML email
        super(PasswordResetRecoverView, self).send_notification()

    def get_success_url(self):
        return urlresolvers.reverse('accounts_password_reset_recover_sent', args=[self.mail_signature])

class PasswordResetRecoverSentView(password_reset.views.RecoverDone):
    template_name = "accounts/password_reset_recover_sent.html"


class PasswordResetChangeView(password_reset.views.Reset):
    template_name = 'accounts/password_reset_change.html'

    def get_success_url(self):
        return urlresolvers.reverse('accounts_password_reset_change_done')


class PasswordResetChangeDoneView(password_reset.views.ResetDone):
    template_name = 'accounts/password_reset_change_done.html'


class ProfileView(TemplateView):
    template_name = 'accounts/profile.html'


class ChangePasswordView(FormView):
    template_name = "accounts/profile_change_password.html"
    email_template_name = "accounts/email/change_password.body.txt"
    email_html_template_name = "accounts/email/change_password.body.html"
    email_subject_template_name = "accounts/email/change_password.subject.txt"
    form_class = ChangePasswordForm
    redirect_field_name = "next"
    messages = {
        "password_changed": {
            "level": messages.SUCCESS,
            "text": _(u"Password successfully changed.")
        }
    }

    def get(self, *args, **kwargs):
        if not self.request.user.is_authenticated():
            return redirect("accounts_password_reset_recover")
        return super(ChangePasswordView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden()
        return super(ChangePasswordView, self).post(*args, **kwargs)

    def change_password(self, form):
        user = self.request.user
        form.save(user)
        if conf.NOTIFY_PASSWORD_CHANGE:
            self.send_email(user)
        if self.messages.get("password_changed"):
            messages.add_message(
                self.request,
                self.messages["password_changed"]["level"],
                self.messages["password_changed"]["text"]
            )
        signals.password_changed.send(sender=ChangePasswordForm, user=user)

    def get_form_kwargs(self):
        """
        Returns the keyword arguments for instantiating the form.
        """
        kwargs = {"user": self.request.user, "initial": self.get_initial()}
        if self.request.method in ["POST", "PUT"]:
            kwargs.update({
                "data": self.request.POST,
                "files": self.request.FILES,
                })
        return kwargs

    def form_valid(self, form):
        self.change_password(form)
        return redirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        ctx = kwargs
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.REQUEST.get(redirect_field_name),
            })
        return ctx

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = conf.PASSWORD_CHANGE_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def send_email(self, user):
        # TODO: send html mail
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = get_current_site(self.request)
        ctx = {
            "user": user,
            "protocol": protocol,
            "current_site": current_site,
            }
        subject = render_to_string(self.email_template_name, ctx)
        subject = "".join(subject.splitlines())
        message = render_to_string(self.email_subject_template_name, ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])