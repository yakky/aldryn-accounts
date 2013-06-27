# -*- coding: utf-8 -*-
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import EmailConfirmation, EmailAddress, UserSettings
from social_auth.db.django_models import UserSocialAuth


class EmailInline(admin.TabularInline):
    model = EmailAddress
    extra = 1


class UserSocialAuthInline(admin.TabularInline):
    model = UserSocialAuth
    extra = 0


class UserSettingsInline(admin.StackedInline):
    model = UserSettings
    extra = 1
    max_num = 1


class AccountsUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'social_logins',)
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    inlines = [UserSettingsInline, EmailInline, UserSocialAuthInline]

    def social_logins(self, obj):
        return u", ".join([u"%s (%s)" % (i.provider, i.uid) for i in obj.social_auth.all()])


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

admin.site.register(UserProxy, AccountsUserAdmin)
admin.site.register(EmailConfirmation, EmailConfirmationAdmin)