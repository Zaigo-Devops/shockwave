from django.core.validators import RegexValidator
from django.db import models
from django.contrib.auth.models import User

from sw_admin_app.utils import get_expire_time


# Create your models here.


class BillingAddress(models.Model):
    name = models.CharField(max_length=256)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    line_1 = models.CharField(max_length=256)
    line_2 = models.CharField(max_length=256, blank=True, null=True, default=None)
    city = models.CharField(max_length=256)
    state = models.CharField(max_length=256, blank=True, null=True, default=None)
    country = models.CharField(max_length=256, blank=True, null=True, default=None)
    pin_code = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Device(models.Model):
    device_serial_no = models.CharField(max_length=256)
    device_name = models.CharField(max_length=256, blank=True, null=True, default=None)
    # device_price_id = models.CharField(max_length=256, blank=True, null=True, default=None)  # price id for
    # subscription
    price_id = models.CharField(max_length=256, blank=True, null=True, default=None)  # price id for subscription
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.device_name


class Session(models.Model):
    environment = models.CharField(max_length=256)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    location = models.CharField(max_length=256)
    city = models.CharField(max_length=256, blank=True, null=True, default=None)
    state = models.CharField(max_length=256, blank=True, null=True, default=None)
    country = models.CharField(max_length=256, blank=True, null=True, default=None)
    pin_code = models.CharField(max_length=256, blank=True, null=True, default=None)
    latitude = models.CharField(max_length=256, blank=True, null=True, default=None)
    longitude = models.CharField(max_length=256, blank=True, null=True, default=None)
    device_name = models.CharField(max_length=256, null=True, blank=True)
    session_end_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SessionData(models.Model):
    energy_data = models.JSONField(default=None, null=True)
    lowest_energy_level = models.FloatField(default=None, null=True)
    highest_energy_level = models.FloatField(default=None, null=True)
    session_id = models.ForeignKey(Session, on_delete=models.SET_NULL, null=True)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class PaymentMethod(models.Model):
    payment_id = models.CharField(max_length=256)  ## stripe payment method id is save in this column
    card_last4_no = models.IntegerField(default=0)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.payment_id


class Subscription(models.Model):
    status = models.PositiveIntegerField(choices=((0, "InActive"), (1, "Active"), (2, "Cancelled")), default=0)
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)  # Not used.
    app_subscribed = models.BooleanField(default=False)  # Newly add for app subscription validation.
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    payment_method_id = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, null=True)
    stripe_payment_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_customer_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_subscription_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_product_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_price_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_intent_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    subscription_price = models.FloatField(default=0, null=True)
    start_date = models.DateTimeField(blank=True, null=True)
    end_date = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        payments = self.stripe_intent_id
        return payments


class UserOtp(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    otp = models.CharField(max_length=6, default=None)
    is_validated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now=True)
    expired_at = models.DateTimeField(default=get_expire_time)


class UserProfile(models.Model):
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$')
    user_id = models.OneToOneField(User, on_delete=models.SET_NULL, default=None, null=True,
                                   related_name="user_profile")
    insurance_provider = models.CharField(max_length=256, null=True, default=None)
    is_promotion_email = models.BooleanField(default=True, null=True)
    user_profile_image = models.ImageField(default=None, null=True, blank=True)
    user_address = models.TextField(blank=True, null=True, default=None)
    user_phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True, null=True,
                                         unique=True)
    stripe_customer_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_ephemeral_key = models.CharField(max_length=256, blank=True, null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class UserDevice(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True,
                                related_name="user_device")
    device_id = models.ForeignKey(Device, on_delete=models.SET_NULL, default=None, null=True, blank=True,
                                  related_name="device") # Field add for mapped device against the user
    mobile_device_id = models.CharField(max_length=256, null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SubscriptionPeriod(models.Model):
    subscription_id = models.ForeignKey(Subscription, on_delete=models.SET_NULL, null=True)
    stripe_subscription_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_customer_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_product_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_price_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    stripe_intent_id = models.CharField(max_length=256, blank=True, null=True, default=None)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


""" Price update for app is Handled"""


class SubscriptionPrice(models.Model):  # DevicePrice changed to SubscriptionPrice
    price = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.price)


# class Test(models.Model):
#     Test = models.BooleanField(default=False)
