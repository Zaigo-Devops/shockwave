from django.shortcuts import render
from rest_framework.decorators import api_view
from django.db import models
from rest_framework.response import Response
from rest_framework import status

from sw_admin_app.models import Subscription
from .serilaizer import BillingAddressSerializer

# Create your views here.
from .utils import get_member_id


class BillingAddressView(models.Model):
    serializer_class = BillingAddressSerializer


@api_view(['POST'])
def device_registration(request):
    if request.method == 'POST':
        try:
            device_id = request.data.get('device_id', '')
            user_id = get_member_id(request)
            subscription = Subscription.objects.get(user_id=user_id, device_id=device_id)
            if subscription.status == 1:
                return Response(True, status=status.HTTP_200_OK)
            else:
                return Response(False, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print('Error Detail', str(e))

