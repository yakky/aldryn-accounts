# -*- coding: utf-8 -*-
from uuid import uuid4
from absolute.templatetags.absolute_future import site
from django.contrib.auth.models import User
from class_based_auth_views.utils import default_redirect
import class_based_auth_views.views
import datetime
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.contrib.sites.models import get_current_site
from django.core import urlresolvers
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django import forms
from django.http import HttpResponseForbidden, Http404, HttpResponseRedirect
from django.shortcuts import redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.generic import FormView, TemplateView, ListView, DeleteView, UpdateView, View
from django.views.generic.base import TemplateResponseMixin
from aldryn_accounts import signals
from aldryn_accounts.conf import settings
from aldryn_accounts.context_processors import empty_login_and_signup_forms
import pytz
from social_auth.utils import setting as social_auth_setting
from aldryn_accounts.forms import EmailAuthenticationForm, ChangePasswordForm, CreatePasswordForm, EmailForm, PasswordRecoveryForm, SignupForm, UserSettingsForm, PasswordResetForm
from django.utils.translation import ugettext_lazy as _
from aldryn_accounts.utils import user_display
import password_reset.views
from aldryn_accounts.models import EmailAddress, EmailConfirmation, SignupCode, UserSettings
from aldryn_accounts.view_mixins import OnlyOwnedObjectsMixin
from dj.chain import chain


class SignupView(FormView):
    template_name = "aldryn_accounts/signup.html"
    template_name_email_confirmation_sent = "aldryn_accounts/signup_email_confirmation_sent.html"
    template_name_signup_closed = "aldryn_accounts/signup_closed.html"
    form_class = SignupForm
    form_kwargs = {}
    redirect_field_name = "next"
    messages = {
        "email_confirmation_sent": {
            "level": messages.INFO,
            "text": _("Confirmation email sent to %(email)s.")
        },
        "logged_in": {
            "level": messages.SUCCESS,
            "text": _("Successfully logged in as %(user)s.")
        },
        "invalid_signup_code": {
            "level": messages.WARNING,
            "text": _("The code %(code)s is invalid.")
        }
    }

    def __init__(self, *args, **kwargs):
        self.created_user = None
        kwargs["signup_code"] = None
        super(SignupView, self).__init__(*args, **kwargs)

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            return redirect(default_redirect(self.request, settings.ALDRYN_ACCOUNTS_LOGIN_REDIRECT_URL))
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).post(*args, **kwargs)

    def get_initial(self):
        initial = super(SignupView, self).get_initial()
        if self.signup_code:
            initial["code"] = self.signup_code.code
            if self.signup_code.email:
                initial["email"] = self.signup_code.email
        return initial

    def get_context_data(self, **kwargs):
        ctx = kwargs
        redirect_field_name = self.get_redirect_field_name()
        # adds the empty login and signup forms to the context, so that
        # the shared login/signup view works even if the context processor
        # was not added globally
        ctx.update(empty_login_and_signup_forms(self.request))  # TODO: make configurable?
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.REQUEST.get(redirect_field_name),
        })
        return ctx

    def get_form_kwargs(self):
        kwargs = super(SignupView, self).get_form_kwargs()
        kwargs.update(self.form_kwargs)
        return kwargs

    def form_invalid(self, form):
        signals.user_sign_up_attempt.send(
            sender=SignupForm,
            email=form.data.get("email"),
            result=form.is_valid()
        )
        return self.render_to_response(self.get_context_data(form=form, signup_form=form))

    def form_valid(self, form):
        email_is_trusted = False
        email = form.cleaned_data.get('email')
        self.created_user = self.create_user(form, commit=False)
        if settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_REQUIRED:
            self.created_user.is_active = False
        self.created_user._disable_account_creation = True
        self.created_user.save()
        if self.signup_code:
            self.signup_code.use(self.created_user)
            if self.signup_code.email and self.created_user.email == self.signup_code.email:
                email_is_trusted = True
        if not email_is_trusted and settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_REQUIRED:
            email_address_verification = EmailConfirmation.objects.request(self.created_user, email=email, send=settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EMAIL)
        elif email_is_trusted:
            email_address = EmailAddress.objects.add_email(self.created_user, self.created_user.email)
        self.after_signup(form)
        if settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_REQUIRED and (email_is_trusted is False):
            response_kwargs = {
                "request": self.request,
                "template": self.template_name_email_confirmation_sent,
                "context": {
                    "email": self.created_user.email,
                    "success_url": self.get_success_url(),
                    }
            }
            return self.response_class(**response_kwargs)
        else:
            # we already know we can trust the provided email and can go ahead and log the user straight in.
            show_message = [
                settings.ALDRYN_ACCOUNTS_EMAIL_CONFIRMATION_EMAIL,
                self.messages.get("email_confirmation_sent"),
                not email_is_trusted,
            ]
            if all(show_message):
                messages.add_message(
                    self.request,
                    self.messages["email_confirmation_sent"]["level"],
                    self.messages["email_confirmation_sent"]["text"] % {
                        "email": form.cleaned_data["email"]
                    }
                )
            self.login_user()
            if self.messages.get("logged_in"):
                messages.add_message(
                    self.request,
                    self.messages["logged_in"]["level"],
                    self.messages["logged_in"]["text"] % {
                        "user": user_display(self.created_user)
                    }
                )
        return redirect(self.get_success_url())

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ALDRYN_ACCOUNTS_SIGNUP_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def create_user(self, form, commit=True, **kwargs):
        user = User(**kwargs)
        username = form.cleaned_data.get("username")
        if username is None:
            username = self.generate_username(form)
        user.username = username
        #user.email = form.cleaned_data["email"].strip()  #  email must be confirmed first!
        password = form.cleaned_data.get("password")
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        if commit:
            user.save()
        return user

    def create_account(self, form):
        return Account.create(request=self.request, user=self.created_user, create_email=False)

    def generate_username(self, form):
        return uuid4().get_hex()[:30]

    def after_signup(self, form):
        signals.user_signed_up.send(sender=SignupForm, user=self.created_user, form=form)

    def login_user(self):
        # set backend on User object to bypass needing to call auth.authenticate
        self.created_user.backend = "django.contrib.auth.backends.ModelBackend"
        auth.login(self.request, self.created_user)
        self.request.session.set_expiry(0)

    def is_open(self):
        code = self.request.REQUEST.get("code")
        if code:
            try:
                self.signup_code = SignupCode.check(code)
            except SignupCode.InvalidCode:
                if not settings.ALDRYN_ACCOUNTS_OPEN_SIGNUP:
                    return False
                else:
                    if self.messages.get("invalid_signup_code"):
                        messages.add_message(
                            self.request,
                            self.messages["invalid_signup_code"]["level"],
                            self.messages["invalid_signup_code"]["text"] % {
                                "code": code
                            }
                        )
                    return True
            else:
                return True
        else:
            return settings.ALDRYN_ACCOUNTS_OPEN_SIGNUP

    def closed(self):
        response_kwargs = {
            "request": self.request,
            "template": self.template_name_signup_closed,
            }
        return self.response_class(**response_kwargs)


class SignupEmailView(FormView):
    template_name = 'aldryn_accounts/signup_email.html'
    form_class = EmailForm

    def get_initial(self):
        email = self.request.session.get('social_auth_email')
        if email:
            return {'email': email}
        else:
            return {}

    def form_valid(self, form):
        verified_email = self.request.session.get('social_auth_verified_email')
        email = form.cleaned_data['email']
        social_auth_data_varname = social_auth_setting('SOCIAL_AUTH_PARTIAL_PIPELINE_KEY', 'partial_pipeline')
        social_auth_data = self.request.session[social_auth_data_varname]
        user = User.objects.get(pk=social_auth_data['kwargs']['user']['pk'])
        if email and verified_email and email == verified_email:
            # we know all is ok with that email. Activate it right away
            EmailAddress.objects.add_email(user=user, email=verified_email)
        else:
            EmailConfirmation.objects.request(user=user, email=email, send=True)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return self.social_auth_continue_url()

    def social_auth_continue_url(self):
        name = social_auth_setting('SOCIAL_AUTH_PARTIAL_PIPELINE_KEY', 'partial_pipeline')
        backend = self.request.session[name]['backend']
        return urlresolvers.reverse('socialauth_complete', kwargs=dict(backend=backend))


class SignupEmailSentView(TemplateView):
    template_name = 'aldryn_accounts/signup_email_sent.html'


class LoginView(class_based_auth_views.views.LoginView):
    template_name = 'aldryn_accounts/login.html'
    form_class = EmailAuthenticationForm

    def get_context_data(self, **kwargs):
        ctx = super(LoginView, self).get_context_data(**kwargs)
        # add the empty login and signup forms to the context, so that
        # the shared login/signup view works even if the context processor
        # was not added globally
        ctx.update(empty_login_and_signup_forms(self.request))  # TODO: make configurable?
        return ctx

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form, login_form=form))


class LogoutView(class_based_auth_views.views.LogoutView):
    template_name = 'aldryn_accounts/logout.html'


class PasswordResetRecoverView(password_reset.views.Recover):
    form_class = PasswordRecoveryForm
    case_sensitive = False
    template_name = 'aldryn_accounts/password_reset_recover.html'
    email_template_name = 'aldryn_accounts/email/password_reset_recover.body.txt'
    email_html_template_name = 'aldryn_accounts/email/password_reset_recover.body.html'
    email_subject_template_name = 'aldryn_accounts/email/password_reset_recover.subject.txt'

    def send_notification(self):
        # TODO: send HTML email
        super(PasswordResetRecoverView, self).send_notification()

    def get_success_url(self):
        return urlresolvers.reverse('accounts_password_reset_recover_sent', args=[self.mail_signature])

class PasswordResetRecoverSentView(password_reset.views.RecoverDone):
    template_name = "aldryn_accounts/password_reset_recover_sent.html"


class PasswordResetChangeView(password_reset.views.Reset):
    form_class = PasswordResetForm
    template_name = 'aldryn_accounts/password_reset_change.html'

    def get_success_url(self):
        return urlresolvers.reverse('accounts_password_reset_change_done')


class PasswordResetChangeDoneView(password_reset.views.ResetDone):
    template_name = 'aldryn_accounts/password_reset_change_done.html'


class ConfirmEmailView(TemplateResponseMixin, View):
    template_name = "aldryn_accounts/email_confirm.html"
    messages = {
        "email_confirmed": {
            "level": messages.SUCCESS,
            "text": _("You have confirmed %(email)s.")
        },
    }

    def get(self, *args, **kwargs):
        self.object = self.get_object()
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        email_address = confirmation.confirm(verification_method="email")
        if email_address:
            if not self.object.user.is_active:
                self.object.user.is_active = True
                self.object.user.save()
        else:
            # the key has expired
            raise Http404()
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
            return urlresolvers.reverse('login')


class ProfileView(TemplateView):
    template_name = 'aldryn_accounts/profile/index.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileView, self).dispatch(*args, **kwargs)


class ChangePasswordView(FormView):
    template_name = "aldryn_accounts/profile/change_password.html"
    email_template_name = "aldryn_accounts/email/change_password.body.txt"
    email_html_template_name = "aldryn_accounts/email/change_password.body.html"
    email_subject_template_name = "aldryn_accounts/email/change_password.subject.txt"
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
        if settings.ALDRYN_ACCOUNTS_NOTIFY_PASSWORD_CHANGE and user.email:
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
            fallback_url = settings.ALDRYN_ACCOUNTS_PASSWORD_CHANGE_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def send_email(self, user):
        # TODO: send html mail
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        site = get_current_site(self.request)
        # TODO: use a shared tool to generate an absulute url
        site_url = u"%s://%s%s" % (protocol, site.domain, '/')
        ctx = {
            "user": user,
            "name": user_display(user),
            "now": datetime.datetime.now(),
            "protocol": protocol,
            "current_site": site,
            "site_url": site_url,
            "site_name": site.name,
            "site_domain": site.domain,
            "support_email": settings.ALDRYN_ACCOUNTS_SUPPORT_EMAIL,
        }
        subject = render_to_string(self.email_subject_template_name, ctx)
        subject = "".join(subject.splitlines())
        message = render_to_string(self.email_template_name, ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


class CreatePasswordView(ChangePasswordView):
    form_class = CreatePasswordForm

    @method_decorator(login_required())
    def dispatch(self, request, *args, **kwargs):
        if request.user.has_usable_password():
            # user who already have a password must use ChangePasswordView
            return redirect(urlresolvers.reverse('accounts_change_password'))
        else:
            return super(CreatePasswordView, self).dispatch(request, *args, **kwargs)


class ProfileAssociationsView(TemplateView):
    template_name = 'aldryn_accounts/profile/social_accounts.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileAssociationsView, self).dispatch(*args, **kwargs)


class ProfileEmailListView(ListView):
    template_name = 'aldryn_accounts/profile/email_list.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailListView, self).dispatch(*args, **kwargs)

    def get_queryset(self):
        return chain(EmailAddress.objects.all(), EmailConfirmation.objects.all()).filter(user=self.request.user)


class ProfileEmailConfirmationCreateView(FormView):
    template_name = 'aldryn_accounts/profile/email_confirmation_create.html'
    form_class = EmailForm

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailConfirmationCreateView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        email = form.cleaned_data['email']
        email_confirmation = EmailConfirmation.objects.request(user=self.request.user, email=email, send=True)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')


class ProfileEmailDeleteView(OnlyOwnedObjectsMixin, DeleteView):
    template_name = 'aldryn_accounts/profile/email_delete.html'
    model = EmailAddress

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailDeleteView, self).dispatch(*args, **kwargs)

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')

    def get_queryset(self):
        # don't allow deleting the primary email address
        return super(ProfileEmailDeleteView, self).get_queryset().filter(is_primary=False)


class ProfileEmailConfirmationCancelView(OnlyOwnedObjectsMixin, DeleteView):
    template_name = 'aldryn_accounts/profile/email_confirmation_cancel.html'
    model = EmailConfirmation

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailConfirmationCancelView, self).dispatch(*args, **kwargs)

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')


class ProfileEmailMakePrimaryView(OnlyOwnedObjectsMixin, UpdateView):
    template_name = 'aldryn_accounts/profile/email_make_primary.html'
    model = EmailAddress

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailMakePrimaryView, self).dispatch(*args, **kwargs)

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


class UserSettingsView(UpdateView):
    model = UserSettings
    form_class = UserSettingsForm
    template_name = "aldryn_accounts/profile/usersettings_form.html"

    def get_object(self, queryset=None):
        if self.request.user.is_anonymous():
            raise PermissionDenied()
        if queryset is None:
            queryset = self.get_queryset()
        user_settings, created = queryset.get_or_create(user=self.request.user)
        return user_settings

    def get_form_kwargs(self):
        kwargs = super(UserSettingsView, self).get_form_kwargs()
        if not self.object.timezone:
            self.object.timezone = self.request.session.get('django_timezone')
        return kwargs

    def form_valid(self, form):
        self.object = form.save()
        # set timezone
        if self.object.timezone:
            self.request.session['django_timezone'] = self.object.timezone
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return urlresolvers.reverse('accounts_profile')
