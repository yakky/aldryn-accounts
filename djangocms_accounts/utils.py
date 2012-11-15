# -*- coding: utf-8 -*-


def user_display(user):
    if user.is_anonymous():
        return 'Anonymous user'
    if user.email:
        return user.email
    elif user.first_name or user.last_name:
        return (u"%s %s" % (user.first_name, user.last_name)).strip()
    elif user.username:
        return user.username
    elif user.pk:
        return user.pk
    else:
        return '<unknown user>'
