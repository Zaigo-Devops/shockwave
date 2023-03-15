from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class BillingAddress(models.Model):
    name = models.CharField(max_length=256)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    line_1 = models.CharField(max_length=256)
    line_2 = models.CharField(max_length=256, null=True, blank=True)
    city = models.CharField(max_length=256)
    state = models.CharField(max_length=256, null=True, blank=True)
    country = models.CharField(max_length=256, null=True, blank=True)
    pin_code = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Device(models.Model):
    device_unique_id = models.CharField(max_length=256)
    device_name = models.CharField(max_length=256, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Session(models.Model):
    environment = models.CharField(max_length=256)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    location = models.CharField(max_length=256)
    city = models.CharField(max_length=256, null=True, blank=True)
    state = models.CharField(max_length=256, null=True, blank=True)
    country = models.CharField(max_length=256, null=True, blank=True)
    pin_code = models.CharField(max_length=256, null=True, blank=True)
    latitude = models.CharField(max_length=256, null=True, blank=True)
    longitude = models.CharField(max_length=256, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SessionData(models.Model):
    energy_data = models.JSONField(default=None, null=True)
    session_id = models.ForeignKey(Session, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class PaymentMethod(models.Model):
    stripe_payment_id = models.CharField(max_length=256)
    stripe_customer_id = models.CharField(max_length=256)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class subscription(models.Model):
    status = models.PositiveIntegerField(choices=((0, "InActive"), (1, "Active"), (2, "Delete")), default=0)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    payment_method_id = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
