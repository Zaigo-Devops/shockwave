from django.contrib import admin, messages
from django.shortcuts import render
# from django.contrib.flatpages.models import FlatPage
from sw_admin_app.models import Device, Subscription, PaymentMethod


# Register your models here.
# class MyFlatPage(FlatPage):
#     class Meta:
#         verbose_name = 'Static Page'


class DeviceAdmin(admin.ModelAdmin):
    model = Device
    list_display = ('device_name', 'device_unique_id',)


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

    # def queryset(self, request):
    #     qs = super().queryset(request)
    #     return qs.filter(author=request


admin.site.register(Device, DeviceAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
admin.site.register(PaymentMethod)
# admin.site.unregister(FlatPage)
# admin.site.register(MyFlatPage, admin.ModelAdmin)