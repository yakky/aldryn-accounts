# -*- coding: utf-8 -*-
from class_based_auth_views.utils import default_redirect
import class_based_auth_views.views
import datetime
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.sites.models import get_current_site
from django.core import urlresolvers
from django.core.mail import send_mail
from django import forms
from django.http import HttpResponseForbidden, Http404
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.generic import FormView, TemplateView, ListView, DeleteView, UpdateView, View
from django.views.generic.base import TemplateResponseMixin
from djangocms_accounts import signals
from djangocms_accounts.conf import settings
from djangocms_accounts.forms import EmailAuthenticationForm, ChangePasswordForm, CreatePasswordForm, EmailForm, PasswordRecoveryForm
from django.utils.translation import ugettext_lazy as _
import password_reset.views
from djangocms_accounts.models import EmailAddress, EmailConfirmation
from djangocms_accounts.view_mixins import OnlyOwnedObjectsMixin
from dj.chain import chain


class LoginView(class_based_auth_views.views.LoginView):
    template_name = 'accounts/login.html'
    form_class = EmailAuthenticationForm


class LogoutView(class_based_auth_views.views.LogoutView):
    template_name = 'accounts/logout.html'


class PasswordResetRecoverView(password_reset.views.Recover):
    form_class = PasswordRecoveryForm
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


class ConfirmEmailView(TemplateResponseMixin, View):
    template_name = "accounts/email_confirm.html"
    messages = {
        "email_confirmed": {
            "level": messages.SUCCESS,
            "text": _("You have confirmed %(email)s.")
        }
    }

    def get(self, *args, **kwargs):
        self.object = self.get_object()
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        confirmation.confirm()
        redirect_url = self.get_redirect_url()
        if not redirect_url:
            ctx = self.get_context_data()
            return self.render_to_response(ctx)
        if self.messages.get("email_confirmed"):
            messages.add_message(
                self.request,
                self.messages["email_confirmed"]["level"],
                self.messages["email_confirmed"]["text"] % {
                    "email": confirmation.email
                }
            )
        return redirect(redirect_url)

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        try:
            return queryset.get(key=self.kwargs["key"].lower())
        except EmailConfirmation.DoesNotExist:
            raise Http404()

    def get_queryset(self):
        qs = EmailConfirmation.objects.all()
        qs = qs.select_related("user")
        return qs

    def get_context_data(self, **kwargs):
        ctx = kwargs
        ctx["confirmation"] = self.object
        return ctx

    def get_redirect_url(self):
        if self.request.user.is_authenticated():
            return urlresolvers.reverse('accounts_email_list')
        else:
            return urlresolvers.reverse('accounts_login')


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
        if settings.ACCOUNTS_NOTIFY_PASSWORD_CHANGE:
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
            fallback_url = settings.ACCOUNTS_PASSWORD_CHANGE_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def send_email(self, user):
        # TODO: send html mail
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = get_current_site(self.request)
        ctx = {
            "user": user,
            "now": datetime.datetime.now(),
            "protocol": protocol,
            "current_site": current_site,
        }
        subject = render_to_string(self.email_subject_template_name, ctx)
        subject = "".join(subject.splitlines())
        message = render_to_string(self.email_template_name, ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


class CreatePasswordView(ChangePasswordView):
    form_class = CreatePasswordForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.has_usable_password():
            # user who already have a password must use ChangePasswordView
            return redirect(urlresolvers.reverse('accounts_change_password'))
        else:
            return super(CreatePasswordView, self).dispatch(request, *args, **kwargs)


class ProfileAssociationsView(TemplateView):
    template_name = 'accounts/profile_social_accounts.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileAssociationsView, self).dispatch(*args, **kwargs)


class ProfileEmailListView(ListView):
    template_name = 'accounts/profile_email_list.html'

    def get_queryset(self):
        return chain(EmailAddress.objects.all(), EmailConfirmation.objects.all()).filter(user=self.request.user)


class ProfileEmailConfirmationCreateView(FormView):
    template_name = 'accounts/profile_email_confirmation_create.html'
    form_class = EmailForm

    def form_valid(self, form):
        email = form.cleaned_data['email']
        email_confirmation = EmailConfirmation.objects.request(user=self.request.user, email=email, send=True)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')


class ProfileEmailDeleteView(OnlyOwnedObjectsMixin, DeleteView):
    template_name = 'accounts/profile_email_delete.html'
    model = EmailAddress

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')

    def get_queryset(self):
        # don't allow deleting the primary email address
        return super(ProfileEmailDeleteView, self).get_queryset().filter(is_primary=False)


class ProfileEmailConfirmationCancelView(OnlyOwnedObjectsMixin, DeleteView):
    template_name = 'accounts/profile_email_confirmation_cancel.html'
    model = EmailConfirmation

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')


class ProfileEmailMakePrimaryView(OnlyOwnedObjectsMixin, UpdateView):
    template_name = 'accounts/profile_email_make_primary.html'
    model = EmailAddress

    def get_form_class(self):
        class MiniForm(forms.ModelForm):
            class Meta:
                model = EmailAddress
                fields = []
        return MiniForm

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')

    def form_valid(self, form):
        self.object.set_as_primary()
        return redirect(self.get_success_url())



#class ProfileEmailListView(FormView):
#    template_name = 'accounts/profile_email_list.html'
#    form_class = ChangeEmailForm
#    messages = {
#        "email_updated": {
#            "level": messages.SUCCESS,
#            "text": _("Account settings updated.")
#        },
#    }


class ProfileEmailChangeView(FormView):
    template_name = 'accounts/profile_email_list.html'
    form_class = EmailForm
    messages = {
        "email_updated": {
            "level": messages.SUCCESS,
            "text": _("Account settings updated.")
        },
        }