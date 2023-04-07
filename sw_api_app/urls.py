from SHOCK_WAVE import urls
from django.urls import path, include
from rest_framework import routers
from . import views
from .views import *

router = routers.DefaultRouter()
router.register('billing_address', viewset=BillingAddressViewSet)
router.register('device', viewset=DeviceViewSet)
router.register('Subscription', viewset=SubscriptionViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path("get-details", UserDetailAPI.as_view()),
    path('register/', RegisterUserAPIView.as_view()),
    path('login/', LoginView.as_view(), name='login_api'),
    path('is_device_registration/', views.is_device_registration),
    path('trigger_otp/', TriggerOtp.as_view()),
    path('Verify_otp/', OtpVerified.as_view()),
    path('session_setup/', views.session_setup),
    path('session_data_save/<int:session_id>/', views.session_data_save),
    path('session_list/<int:device_id>/', views.session_list),
    path('swipe_to_cancel/', views.cancel_registration),
    path('create_super_user/', views.save_users),
    path('my_profile/', UserView.as_view()),
    path('registered_list', views.previous_connected_list),
    path('device_session_history/', views.device_session_history),
    path('payment_method_create/', views.payment_method_creation)
]
