# -*- coding: utf-8 -*-
from django.contrib import admin
from aldryn_accounts.models import EmailConfirmation, EmailAddress


class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ('email', 'user', 'is_primary', 'verification_method', 'verified_at',)
    list_filter = ('is_primary', 'verification_method',)
    date_hierarchy = 'verified_at'
    search_fields = ('email', 'user__username', 'user__first_name', 'user__last_name', 'user__email',)


class EmailConfirmationAdmin(admin.ModelAdmin):
    list_display = ('email', 'user')
    actions = ('manual_confirmation', )

    def manual_confirmation(self, request, queryset):
        for obj in queryset:
            obj.confirm(method='manual')



admin.site.register(EmailConfirmation, EmailConfirmationAdmin)
admin.site.register(EmailAddress, EmailAddressAdmin)