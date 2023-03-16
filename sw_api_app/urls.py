from SHOCK_WAVE import urls
from django.urls import path, include
from rest_framework import routers

from sw_api_app import views
from sw_api_app.views import  UserDetailAPI, LoginView, RegisterUserAPIView

router = routers.DefaultRouter()

urlpatterns = [
    path('', include(router.urls)),
    path("get-details", UserDetailAPI.as_view()),
    path('register/', RegisterUserAPIView.as_view()),
    path('login/', LoginView.as_view(), name='login_api'),
    path('device_registration/', views.device_registration)
]
