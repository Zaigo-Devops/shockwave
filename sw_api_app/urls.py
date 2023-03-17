from rest_framework import routers
from django.urls import path, include
from .views import *

router = routers.DefaultRouter()
router.register('billing_address', viewset=BillingAddressViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path("get-details", UserDetailAPI.as_view()),
    path('register/', RegisterUserAPIView.as_view()),
    path('login/', LoginView.as_view(), name='login_api'),
    path('trigger_otp/', TriggerOtp.as_view()),
    path('Verify_otp/', OtpVerified.as_view())
]