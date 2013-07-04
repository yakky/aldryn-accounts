# -*- coding: utf-8 -*-
from uuid import uuid4
import datetime
import urllib

from aldryn_accounts.exceptions import EmailAlreadyVerified, VerificationKeyExpired
from class_based_auth_views.utils import default_redirect
from dj.chain import chain
from django import forms
from django.contrib import messages, auth
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.sites.models import get_current_site, RequestSite
from django.core import urlresolvers, signing
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.http import HttpResponseForbidden, Http404, HttpResponseRedirect
from django.shortcuts import redirect
from django.template import loader
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.generic import FormView, TemplateView, ListView, DeleteView, UpdateView, View
from django.views.generic.base import TemplateResponseMixin
from social_auth.utils import setting as social_auth_setting
import class_based_auth_views.views
import password_reset.views

from .conf import settings
from .context_processors import empty_login_and_signup_forms
from .forms import (
    EmailAuthenticationForm, ChangePasswordForm, CreatePasswordForm, EmailForm,
    PasswordRecoveryForm, SignupForm, SignupEmailResendConfirmationForm,
    UserSettingsForm, PasswordResetForm)
from .models import EmailAddress, EmailConfirmation, SignupCode, UserSettings
from .signals import user_sign_up_attempt, user_signed_up, password_changed
from .utils import user_display
from .view_mixins import OnlyOwnedObjectsMixin


class SignupView(FormView):
    template_name = "aldryn_accounts/signup.html"
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
            "text": _("Logged in as %(user)s.")
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
        user_sign_up_attempt.send(
            sender=SignupForm,
            email=form.data.get("email"),
            result=form.is_valid()
        )
        return self.render_to_response(self.get_context_data(form=form, signup_form=form))

    def form_valid(self, form):
        email_is_trusted = False
        email = form.cleaned_data.get('email')
        self.created_user = self.create_user(form)
        if self.signup_code:
            self.signup_code.use(self.created_user)
            if self.signup_code.email and self.created_user.email == self.signup_code.email:
                email_is_trusted = True
        if email_is_trusted:
            email_address = EmailAddress.objects.add_email(self.created_user, self.created_user.email)
        else:
            # send a verification email
            email_address_verification = EmailConfirmation.objects.request(self.created_user, email=email, send=True)
            if not settings.ALDRYN_ACCOUNTS_ENABLE_NOTIFICATIONS:
                if self.messages.get("email_confirmation_sent"):
                    messages.add_message(
                        self.request,
                        self.messages["email_confirmation_sent"]["level"],
                        self.messages["email_confirmation_sent"]["text"] % {
                            "email": form.cleaned_data["email"]
                        }
                    )
        self.after_signup(form)
        self.login_user(show_message=False)
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
        password = form.cleaned_data.get("password")
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        if commit:
            user.save()
        return user

    def generate_username(self, form):
        return uuid4().get_hex()[:30]

    def after_signup(self, form):
        # TODO: SignupForm as sender might suck, because it might be replaced by something else.
        user_signed_up.send(sender=SignupForm, user=self.created_user, form=form)

    def login_user(self, show_message=True):
        # set backend on User object to bypass needing to call auth.authenticate
        self.created_user.backend = "django.contrib.auth.backends.ModelBackend"
        auth.login(self.request, self.created_user)
        self.request.session.set_expiry(0)

        if show_message and self.messages.get("logged_in"):
            messages.add_message(
                self.request,
                self.messages["logged_in"]["level"],
                self.messages["logged_in"]["text"] % {
                    "user": user_display(self.created_user)
                }
            )

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
    """
    experimental: used when someone signs up with a social login and has to also add an email.
    """
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


class SignupEmailResendConfirmationView(FormView):
    template_name = 'aldryn_accounts/signup_email_resend_confirmation.html'
    form_class = SignupEmailResendConfirmationForm

    def get_form_kwargs(self):
        kwargs = super(SignupEmailResendConfirmationView, self).get_form_kwargs()
        return kwargs

    def _get_email(self):
        if not hasattr(self, '_email'):
            email = self.request.GET.get('email', '')
            self._email = urllib.unquote(email)
        return self._email

    def get_context_data(self, **kwargs):
        context = super(SignupEmailResendConfirmationView, self).get_context_data(**kwargs)
        email = self._get_email()
        context['email'] = email
        return context

    def get_initial(self):
        initial = super(SignupEmailResendConfirmationView, self).get_initial()
        email = self._get_email()
        initial["email"] = email
        return initial

    def get_success_url(self):
        email = self._get_email()
        url = reverse('accounts_signup_email_confirmation_sent')
        url += '?' + urllib.urlencode({'email': email})
        return url

    def form_valid(self, form):
        email = form.cleaned_data['email']
        try:
            email_confirmation = EmailConfirmation.objects.get(email=email)
        except EmailConfirmation.DoesNotExist:
            messages.error(self.request, _('This email does not have any pending confirmations.'))
            return self.form_invalid(form)
        else:
            email_confirmation.send()
        return redirect(self.get_success_url())

    def form_invalid(self, form):
        # This shouldn't happen unless someone was tampering with the email parameter
        # or somehow managed to have invalid email in the database
        return HttpResponseRedirect(reverse('accounts_signup'))


class SignupEmailConfirmationSentView(TemplateView):
    template_name = 'aldryn_accounts/signup_email_confirmation_sent.html'

    def get_the_email(self):
        email = self.request.GET.get('email', None)
        email = urllib.unquote(email)
        return email

    def get_context_data(self, **kwargs):
        context = super(SignupEmailConfirmationSentView, self).get_context_data(**kwargs)
        email = self.get_the_email()
        context['email'] = email
        return context


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
        context = {
            'site': RequestSite(self.request),
            'user': self.user,
            'token': signing.dumps(self.user.pk, salt=self.salt),
            'secure': self.request.is_secure(),
        }
        body = loader.render_to_string(self.email_template_name,
                                       context).strip()
        subject = loader.render_to_string(self.email_subject_template_name,
                                          context).strip()
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL,
                  [self.email])

    def form_valid(self, form):
        self.user = form.cleaned_data['user']
        self.email = form.cleaned_data['username_or_email']
        self.send_notification()
        self.mail_signature = signing.dumps(self.email, salt=self.url_salt)
        return super(password_reset.views.Recover, self).form_valid(form)

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
    # TODO: add edge case handling (see divio/djangocms-account#39 )
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
        try:
            email_address = confirmation.confirm(verification_method="email")
        except EmailAlreadyVerified:
            messages.error(self.request, _('This email has already been verified with an other account.'))
            return HttpResponseRedirect(self.request.path)
        except VerificationKeyExpired:
            messages.error(self.request, _('The activation key has expired.'))
            return HttpResponseRedirect(self.request.path)
        if not self.object.user.is_active:
            self.object.user.is_active = True
            self.object.user.save()
        user = email_address.user
        user.backend = "django.contrib.auth.backends.ModelBackend"
        login(self.request, user)
        redirect_url = self.get_redirect_url()
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
        password_changed.send(sender=ChangePasswordForm, user=user)

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


class ProfileEmailListView(OnlyOwnedObjectsMixin, ListView):
    template_name = 'aldryn_accounts/profile/email_list.html'
    queryset = chain(EmailAddress.objects.all(), EmailConfirmation.objects.all())

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ProfileEmailListView, self).dispatch(*args, **kwargs)

    def get(self, *args, **kwargs):
        self.form = EmailForm()
        return super(ProfileEmailListView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        self.form = EmailForm(self.request.POST)
        if self.form.is_valid():
            return self.form_valid(self.form)
        else:
            return super(ProfileEmailListView, self).get(*args, **kwargs)

    def form_valid(self, form):
        email = form.cleaned_data['email']
        EmailConfirmation.objects.request(user=self.request.user, email=email, send=True)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return urlresolvers.reverse('accounts_email_list')

    def get_context_data(self, **kwargs):
        context = super(ProfileEmailListView, self).get_context_data(**kwargs)
        context['add_email_form'] = self.form
        return context


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


class MyExceptionTestView(View):
    def dispatch(self, request, *args, **kwargs):
        from social_auth.exceptions import SocialAuthBaseException
        raise SocialAuthBaseException("This is an exception test")
my_exception_test_view = MyExceptionTestView.as_view()
