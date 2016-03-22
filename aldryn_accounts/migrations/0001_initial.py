# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.utils.timezone import utc
import django.utils.timezone
from django.conf import settings
import timezone_field.fields
import aldryn_accounts.utils
import annoying.fields


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailAddress',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('email', models.EmailField(unique=True, max_length=75)),
                ('verified_at', models.DateTimeField(null=True, blank=True)),
                ('verification_method', models.CharField(default=b'unknown', max_length=255, blank=True)),
                ('is_primary', models.BooleanField(default=False)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'email address',
                'verbose_name_plural': 'email addresses',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='EmailConfirmation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('email', models.EmailField(max_length=75)),
                ('is_primary', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(default=datetime.datetime(2016, 3, 22, 14, 3, 44, 27660, tzinfo=utc))),
                ('sent_at', models.DateTimeField(null=True)),
                ('key', models.CharField(unique=True, max_length=64)),
                ('user', models.ForeignKey(related_name='email_verifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'email confirmation',
                'verbose_name_plural': 'email confirmations',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SignupCode',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('code', models.CharField(unique=True, max_length=64)),
                ('max_uses', models.PositiveIntegerField(default=0)),
                ('expires_at', models.DateTimeField(null=True, blank=True)),
                ('email', models.EmailField(max_length=75, blank=True)),
                ('notes', models.TextField(blank=True)),
                ('sent_at', models.DateTimeField(null=True, blank=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('use_count', models.PositiveIntegerField(default=0, editable=False)),
                ('invited_by', models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SignupCodeResult',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('timestamp', models.DateTimeField(default=datetime.datetime.now)),
                ('signup_code', models.ForeignKey(to='aldryn_accounts.SignupCode')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserSettings',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('birth_date', models.DateField(null=True, verbose_name='birth date', blank=True)),
                ('timezone', timezone_field.fields.TimeZoneField(default=None, blank=True, null=True, verbose_name='time zone')),
                ('location_name', models.CharField(default=b'', max_length=255, verbose_name='location', blank=True)),
                ('location_latitude', models.FloatField(default=None, null=True, blank=True)),
                ('location_longitude', models.FloatField(default=None, null=True, blank=True)),
                ('profile_image', models.ImageField(default=b'', upload_to=aldryn_accounts.utils.profile_image_upload_to, max_length=255, verbose_name='profile image', blank=True)),
                ('preferred_language', models.CharField(default=b'', max_length=32, verbose_name='language', blank=True, choices=[(b'en', b'en'), (b'de', b'de')])),
                ('user', annoying.fields.AutoOneToOneField(related_name='settings', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user settings',
                'verbose_name_plural': 'user settings',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserProxy',
            fields=[
            ],
            options={
                'verbose_name': 'User',
                'proxy': True,
                'verbose_name_plural': 'Users',
            },
            bases=('auth.user',),
        ),
    ]
