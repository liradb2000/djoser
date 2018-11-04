from django.contrib.auth import user_logged_in, user_logged_out
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils import timezone

from djoser.conf import settings


if getattr(settings,'USE_KNOX', False):
    try:
        from knox.settings import knox_settings
    except ImportError:
        raise ImportError("knox needs to be added to INSTALLED_APPS.")

def encode_uid(pk):
    return urlsafe_base64_encode(force_bytes(pk)).decode()


def decode_uid(pk):
    return force_text(urlsafe_base64_decode(pk))


def login_user(request, user):
    if getattr(settings,'USE_KNOX', False):
        if knox_settings.TOKEN_LIMIT_PER_USER is not None:
            now = timezone.now()
            token = user.auth_token_set.filter(expires__gt=now)
            if token.count() >= knox_settings.TOKEN_LIMIT_PER_USER:
                return None
        token = settings.TOKEN_MODEL.objects.create(user=user)
    else:
        token, _ = settings.TOKEN_MODEL.objects.get_or_create(user=user)
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    return token


def logout_user(request):
    if settings.TOKEN_MODEL:
        settings.TOKEN_MODEL.objects.filter(user=request.user).delete()
        user_logged_out.send(
            sender=request.user.__class__, request=request, user=request.user
        )


class ActionViewMixin(object):
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._action(serializer)
