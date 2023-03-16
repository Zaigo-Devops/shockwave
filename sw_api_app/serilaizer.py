from rest_framework import serializers
from sw_admin_app.models import BillingAddress


class BillingAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillingAddress
        fields = '__all__'


