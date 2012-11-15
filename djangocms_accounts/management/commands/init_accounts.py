# -*- coding: utf-8 -*-
from django.contrib.sites.models import Site
from cms.models import Page, Title
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

class Command(BaseCommand):
    help = 'setup the base apphook'

    def handle(self, *args, **options):
        for site in Site.objects.all():
            qs = Title.objects.filter(application_urls='AccountsApphook', page__site=site)
            if len(qs):
                for title in qs:
                    self.stdout.info('apphook already attached to %s (%s)' % (title, site))
                # TODO: check if they are all on the some page and issue a warning otherwise
            else:
                page, created = Page.objects.get_or_create(site=site, reverse_id='accounts', defaults={'is_published': True})
                for language in dict(settings.LANGUAGES).keys():
                    defaults = {
                        'title': 'Accounts',
                        'slug': 'accounts',
                    }
                    title, created = Title.objects.get_or_create(page=page, language=language, defaults=defaults)
                    title.application_urls = 'AccountsApphook'
                    title.save()
