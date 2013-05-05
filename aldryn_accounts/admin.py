# -*- coding: utf-8 -*-
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import EmailConfirmation, EmailAddress, UserSettings

import social_auth
from social_auth.db.django_models import UserSocialAuth


class UserSocialAuthInline(admin.TabularInline):
    model = UserSocialAuth
    extra = 0


class UserSettingsInline(admin.StackedInline):
    model = UserSettings
    extra = 0
    max_num = 1


class AccountsUserAdmin(UserAdmin):
    inlines = [UserSettingsInline, UserSocialAuthInline]


class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ('email', 'user', 'is_primary', 'verification_method', 'verified_at',)
    list_filter = ('is_primary', 'verification_method',)
    date_hierarchy = 'verified_at'
    search_fields = ('email', 'user__username', 'user__first_name', 'user__last_name', 'user__email',)


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
admin.site.register(EmailAddress, EmailAddressAdmin)