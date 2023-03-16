from django.contrib import admin, messages
from sw_admin_app.models import Device, Subscription, PaymentMethod
from sw_api_app.stripe import create_product, create_price


class DeviceAdmin(admin.ModelAdmin):
    model = Device
    fields = ('device_name', 'device_unique_id',)
    list_display = ('device_name', 'device_unique_id',)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        product_name = obj.device_name
        description = f'Product name : {product_name}, Product id : {obj.id}'
        product_id = create_product(product_name, description)['id']
        price_id = create_price(25, 'usd', 'month', product_id)['id']
        obj.device_price_id = price_id
        obj.save()


class SubscriptionAdmin(admin.ModelAdmin):
    model = Subscription
    list_display = ('device_id', 'user_id', 'payment_method_id', 'status', 'created_at', 'updated_at')
    readonly_fields = ('device_id', 'user_id', 'payment_method_id', 'status')

    def message_user(self, request, message, level=messages.INFO, extra_tags='', fail_silently=False):
        message = 'Subscriptions Cannot be Deleted !!!'
        messages.add_message(request, level, message)

    def delete_model(self, request, obj):
        print(obj.user_id)
        return


admin.site.register(Device, DeviceAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(PaymentMethod)
