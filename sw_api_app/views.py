from rest_framework.decorators import api_view
from rest_framework import status
from .serilaizer import BillingAddressSerializer
from .utils import get_member_id
from django.contrib.auth import authenticate
from requests import Response
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.response import Response
from sw_admin_app.models import *
from sw_api_app.serializers import UserSerializer, RegisterSerializer
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken


# Class based view to Get User Details using Token Authentication
class BillingAddressView(models.Model):
    serializer_class = BillingAddressSerializer


class UserDetailAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=request.user.id)
        serializer = UserSerializer(user)
        return Response(serializer.data)


# Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def create(self, request, *args, **kwargs):
        register_serializer = RegisterSerializer(data=request.data)
        register_serializer.is_valid(raise_exception=True)
        register_serializer.save()
        response = register_serializer.data
        email_of_user = response['email']
        user = User.objects.get(email=email_of_user)
        token = RefreshToken.for_user(user)  # generate token without username & password
        payment_method = user.subscription_set.filter(status=1).count()
        payment_method_added = False
        if payment_method > 0:
            payment_method_added = True
        session_count = user.session_set.count()
        user_name = user.first_name
        if len(user.last_name) > 0:
            user_name = user.first_name + ' ' + user.last_name
        token_items = {
            'id': user.pk,
            'name': user_name,
            'email_id': user.email
        }
        for item in token_items:
            if item != "id":
                RefreshToken.__setitem__(token, item, token_items[item])
        token_items['access_token'] = str(token.access_token)
        token_items['refresh_token'] = str(token)
        token_items['device_count'] = payment_method
        token_items['payment_method_added'] = payment_method_added
        token_items['payment_method_count'] = payment_method
        token_items['session_count'] = session_count
        response = token_items
        return Response(response)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(username=email, password=password)
        if user is not None:
            token = RefreshToken.for_user(user)  # generate token without username & password
            user_name = user.first_name
            if len(user.last_name) > 0:
                user_name = user.first_name + ' ' + user.last_name
            payment_method = user.subscription_set.filter(status=1).count()
            payment_method_added = False
            if payment_method > 0:
                payment_method_added = True
            session_count = user.session_set.count()

            token_items = {
                'id': user.pk,
                'name': user_name,
                'email_id': user.email
            }
            for item in token_items:
                if item != "id":
                    RefreshToken.__setitem__(token, item, token_items[item])
            token_items['access_token'] = str(token.access_token)
            token_items['refresh_token'] = str(token)
            token_items['device_count'] = payment_method
            token_items['payment_method_added'] = payment_method_added
            token_items['payment_method_count'] = payment_method
            token_items['session_count'] = session_count
            response = token_items
            return Response(response)
        else:
            content = {'message': 'Invalid User Information Provided'}
            return Response(content)


@api_view(['POST'])
def device_registration(request):
    if request.method == 'POST':
        try:
            device_id = request.data.get('device_id', '')
            user_id = get_member_id(request)
            subscription = Subscription.objects.get(user_id=user_id, device_id=device_id)
            if subscription.status == 1:
                return Response(True, status=status.HTTP_200_OK)
            else:
                return Response(False, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print('Error Detail', str(e))
