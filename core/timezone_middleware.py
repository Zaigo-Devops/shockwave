# This file is added for the admin to show the data in there time zone.
# In this the data save in a db in UTC format,for admin panel view we show in admin local time zone.

from django.utils import timezone
import pytz


class TimezoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        timezone.activate(pytz.timezone("America/Denver"))
        return self.get_response(request)
