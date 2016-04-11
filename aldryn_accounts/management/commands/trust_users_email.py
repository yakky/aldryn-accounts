# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from aldryn_accounts.models import EmailAddress


class Command(BaseCommand):
    help = ("Creates confirmed email addresses for existing users.\n"
            "Uses user.email as a source.\n"
            "Doesn't requires confirmation of the email address.")

    def handle(self, *args, **options):
        self.stdout.write("Starting to process existing users...")
        users_with_confirmed_emails = EmailAddress.objects.all().values_list(
            'user', flat=True)
        self.stdout.write(
            "Found {0} users with confirmed emails. excluding them".format(
                users_with_confirmed_emails.count()))
        users_qs = User.objects.all().exclude(pk__in=users_with_confirmed_emails)
        self.stdout.write(
            "Starting to process {0} users with not confirmed emails".format(
                users_qs.count()))
        no_email_users = []
        for user in users_qs.iterator():
            # if there is no email - can't do anything.
            if not user.email:
                no_email_users.append(user)
                continue
            EmailAddress.objects.add_email(user, user.email)
        no_email_template = "({pk}) {username}"
        formatted_users = [
            no_email_template.format(pk=user.pk, username=user.get_username())
            for user in no_email_users]
        no_email_txt = '\n'.join(formatted_users)
        if no_email_txt:
            self.stdout.write(
                'Following users had no email setted up:\n{0}'.format(
                    no_email_txt))
        self.stdout.write("Done.")
