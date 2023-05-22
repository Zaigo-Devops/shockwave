from django.contrib import admin, messages
from django.contrib.auth.models import Group, User

from sw_admin_app.models import Device, Subscription, PaymentMethod, DevicePrice
from sw_api_app.stripe import delete_subscription


class DeviceAdmin(admin.ModelAdmin):
    model = Device
    fields = ('device_name', 'device_serial_no')
    list_display = ('device_name', 'device_serial_no', 'created_at', 'updated_at')
    actions_on_top = False
    actions_on_bottom = False

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class DevicePriceAdmin(admin.ModelAdmin):
    model = DevicePrice

    list_display = ('price', 'updated_at')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class SubscriptionAdmin(admin.ModelAdmin):
    model = Subscription
    fields = ('device_id', 'user_id', 'payment_method_id', 'status', 'start_date', 'end_date')
    list_display = (
        'device_id', 'user_id', 'payment_method_id', 'status', 'stripe_payment_id', 'stripe_customer_id', 'created_at',
        'updated_at')

    readonly_fields = ('device_id', 'user_id', 'payment_method_id', 'status', 'stripe_payment_id', 'stripe_customer_id')
    actions_on_top = False
    actions_on_bottom = False

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def message_user(self, request, message, level=messages.INFO, extra_tags='', fail_silently=False):
        message = 'Selected Subscription is cancelled !!!'
        messages.add_message(request, level, message)

    def save_model(self, request, obj, form, change):
        return False

    def delete_model(self, request, obj):
        if obj:
            obj.status = 0
            obj.save()
            subscription_id = Subscription.objects.filter(id=obj.id).first().stripe_subscription_id
            if subscription_id:
                delete_subscription(subscription_id)


class PaymentMethodAdmin(admin.ModelAdmin):
    model = PaymentMethod
    # fields = ('payment_id', 'card_last4_no', 'user_id', 'created_at', 'updated_at')
    list_display = ('payment_id', 'card_last4_no', 'user_id', 'created_at', 'updated_at')

    def has_add_permission(self, request):
        return False

    # def has_change_permission(self, request, obj=None):
    #     return False
    # l
    # def save_model(self, request, obj, form, change):
    #     return False
    #
    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(Device, DeviceAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(PaymentMethod, PaymentMethodAdmin)
admin.site.register(DevicePrice, DevicePriceAdmin)
admin.site.unregister(Group)
