# -*- coding: utf-8 -*-
import class_based_auth_views.views
from django.core import urlresolvers
from djangocms_accounts.forms import EmailAuthenticationForm
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

