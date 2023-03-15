from rest_framework import routers
from django.urls import path, include, re_path

from .views import *
from . import views

router = routers.DefaultRouter()
urlpatterns = [
    path('', include(router.urls)),
    # path('register/', views.UserRegistration.as_view()),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
]