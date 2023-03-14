from django.contrib import admin
from sw_admin_app.models import Device, Subscription, PaymentMethod


# Register your models here.

class DeviceAdmin(admin.ModelAdmin):
    model = Device
    list_display = ('device_name', 'device_unique_id',)


class SubscriptionAdmin(admin.ModelAdmin):
    model = Subscription
    list_display = ('device_id', 'user_id', 'payment_method_id', 'status', 'created_at', 'updated_at')
    readonly_fields = ('device_id', 'user_id', 'payment_method_id', 'status')


admin.site.register(Device, DeviceAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(PaymentMethod)
