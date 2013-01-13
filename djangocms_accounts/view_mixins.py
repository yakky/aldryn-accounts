# -*- coding: utf-8 -*-


class OnlyOwnedObjectsMixin(object):
    """
    A view mixing that limits queryset to item model instances where ``user`` it equal to ``request.user``.
    """

    def get_queryset(self):
        return super(OnlyOwnedObjectsMixin, self).get_queryset().filter(user=self.request.user)
