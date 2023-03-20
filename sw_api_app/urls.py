from SHOCK_WAVE import urls
from django.urls import path, include
from rest_framework import routers
from . import views
from .views import *

router = routers.DefaultRouter()
router.register('billing_address', viewset=BillingAddressViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path("get-details", UserDetailAPI.as_view()),
    path('register/', RegisterUserAPIView.as_view()),
    path('login/', LoginView.as_view(), name='login_api'),
    path('device_registration/', views.device_registration),
    path('trigger_otp/', TriggerOtp.as_view()),
    path('Verify_otp/', OtpVerified.as_view()),
    path('session_setup/', views.session_setup)
]
