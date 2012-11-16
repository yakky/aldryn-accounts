# -*- coding: utf-8 -*-
from django.contrib import admin
from djangocms_accounts.models import EmailConfirmation, EmailAddress


class EmailConfirmationAdmin(admin.ModelAdmin):
    list_display = ('email', 'user')
    actions = ('manual_confirmation', )

    def manual_confirmation(self, request, queryset):
        for obj in queryset:
            obj.confirm(method='manual')



admin.site.register(EmailConfirmation, EmailConfirmationAdmin)
admin.site.register([EmailAddress])