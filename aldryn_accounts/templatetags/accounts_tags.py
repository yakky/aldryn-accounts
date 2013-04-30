# -*- coding: utf-8 -*-
from classytags.core import Tag, Options
from classytags.arguments import Argument
from django import template
from ..utils import user_display


register = template.Library()


class PrettyUsername(Tag):
    name = 'pretty_username'
    options = Options(
        Argument('user', required=False, default=None),
        'as',
        Argument('varname', required=False, resolve=False),
    )

    def render_tag(self, context, user, varname):
        if not user:
            if 'request' in context:
                user = context['request'].user
            else:
                return ''
        result = user_display(user)
        if varname:
            context[varname] = result
            return ''
        return result

register.tag(PrettyUsername)