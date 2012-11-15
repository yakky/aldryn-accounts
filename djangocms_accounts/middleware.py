# -*- coding: utf-8 -*-
import social_auth.middleware


class SocialAuthExceptionMiddleware(social_auth.middleware.SocialAuthExceptionMiddleware):
    def raise_exception(self, request, exception):
        return False