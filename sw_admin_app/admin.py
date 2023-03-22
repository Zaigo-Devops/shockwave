from django.contrib import admin, messages
from django.contrib.admin.actions import delete_selected
from django.shortcuts import render

from sw_admin_app.models import Device, Subscription, PaymentMethod
from sw_api_app.stripe import create_product, create_price


class DeviceAdmin(admin.ModelAdmin):
    model = Device
    fields = ('device_name', 'device_serial_no',)
    list_display = ('device_name', 'device_serial_no',)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        product_name = obj.device_name
        description = f'Product name : {product_name}, Product id : {obj.id}'
        product_id = create_product(product_name, description)['id']
        price_id = create_price(25, 'usd', 'month', product_id)['id']
        obj.device_price_id = price_id
        obj.save()


class SubscriptionAdmin(admin.ModelAdmin):
    # delete_confirmation_template = "admin/custom_base.html"
    model = Subscription
    fields = ('device_id', 'user_id', 'payment_method_id', 'status')
    list_display = (
        'device_id', 'user_id', 'payment_method_id', 'status', 'stripe_payment_id', 'stripe_customer_id', 'created_at',
        'updated_at')

    readonly_fields = ('device_id', 'user_id', 'payment_method_id', 'status', 'stripe_payment_id', 'stripe_customer_id')

    def delete_selected(self, request, queryset):
        queryset.delete()
        delete_selected.short_description = "New Button Label"

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
        # super().delete_model(request, obj)
        if obj:
            obj.status = 0
            obj.save()


admin.site.register(Device, DeviceAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(PaymentMethod)
