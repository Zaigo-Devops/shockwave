from SHOCK_WAVE import urls
from django.urls import path
from rest_framework import routers

from sw_api_app import views
from sw_api_app.views import BillingAddressView

router = routers.DefaultRouter()
# router.register('billing', viewset=BillingAddressView)

urlpatterns = [
    path('device_registration/', views.device_registration)
]

urlpatterns += router.urls
