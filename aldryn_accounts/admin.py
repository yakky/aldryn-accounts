# -*- coding: utf-8 -*-
from aldryn_accounts.admin_forms import UserCreationForm
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import EmailConfirmation, EmailAddress, UserSettings
from django.utils.translation import ugettext_lazy as _


class EmailInline(admin.TabularInline):
    model = EmailAddress
    extra = 1


class UserSettingsInline(admin.StackedInline):
    model = UserSettings
    extra = 1
    max_num = 1


class AccountsUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_staff',)
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    inlines = [UserSettingsInline, EmailInline]
    readonly_fields = UserAdmin.readonly_fields + ('email', 'last_login', 'date_joined')
    add_readonly_fields = UserAdmin.readonly_fields + ('last_login', 'date_joined')
    search_fields = ('username', 'first_name', 'last_name', 'email', 'emailaddress__email')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name',)}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined', 'username')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password',)}
        ),
        (_('Personal info'), {'fields': ('first_name', 'last_name',)}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
    )
    add_form = UserCreationForm

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.pk:
            return self.readonly_fields
        else:
            # add form
            return self.add_readonly_fields

    def save_formset(self, request, form, formset, change):
        """
        Given an inline formset save it to the database.
        """
        # do the regular save
        super(AccountsUserAdmin, self).save_formset(request, form, formset, change)
        if not change and formset.model == EmailAddress:
            # we are adding a new user and this is the EmailAddress formset
            # make sure the email entered on the user is also added as the primary email
            if formset.instance.email:
                EmailAddress.objects.add_email(formset.instance, formset.instance.email, make_primary=True)


class EmailConfirmationAdmin(admin.ModelAdmin):
    list_display = ('email', 'user')
    actions = ('manual_confirmation', )
    raw_id_fields = ('user',)

    def manual_confirmation(self, request, queryset):
        for obj in queryset:
            obj.confirm(method='manual')


class UserProxy(User):
    class Meta:
        proxy = True
        verbose_name = _('User')
        verbose_name_plural = _('Users')

admin.site.register(UserProxy, AccountsUserAdmin)
admin.site.register(EmailConfirmation, EmailConfirmationAdmin)
