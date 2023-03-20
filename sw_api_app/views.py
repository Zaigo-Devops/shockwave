from rest_framework.decorators import api_view
from rest_framework import status
from .utils import get_member_id
from django.contrib.auth import authenticate
from requests import Response
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from django.utils import timezone
from sw_admin_app.models import *
from sw_admin_app.utils import generate_otp
from sw_api_app.serializers import UserSerializer, RegisterSerializer, BillingAddressSerializer
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from sw_api_app.utlis import Send_Mail_Notification


# Class based view to Get User Details using Token Authentication


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


class TriggerOtp(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        if email:
            user = User.objects.get(email=email)
            if user:
                otp = generate_otp()
                user_otp = UserOtp(user_id=user, otp=otp)
                user_otp.save()
                Send_Mail_Notification(otp, user).start()
                return Response({"status": "success", "message": "OTP has been triggered Successfully"},
                                status=status.HTTP_200_OK)
            else:
                return Response({"error": "Email does not exists"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "Please provide valid Email"}, status=status.HTTP_400_BAD_REQUEST)


class OtpVerified(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        otp = request.data.get('otp', None)
        password = request.data.get('password', None)
        conform_password = request.data.get('conform_password', None)
        now = timezone.now()
        try:
            user = User.objects.filter(email=email).get()
            if user.email == email:
                user_otp = user.userotp_set.order_by('-created_at').first()
                if user_otp.otp == otp:
                    if user_otp.created_at <= now <= user_otp.expired_at:
                        user_otp.__dict__.update({'is_validated': True})
                        user_otp.save()
                        if password == conform_password:
                            user.set_password(password)
                            user.save()
                            return Response({"status": "success", "message": "Otp has been Verified and Created "
                                                                             "Password"
                                                                             "Successfully"},
                                            status=status.HTTP_200_OK)
                        else:
                            return Response({"error": "Password fields didn't match."})
                    else:
                        return Response({"error": 'Otp is expired'}, status.HTTP_422_UNPROCESSABLE_ENTITY)

                else:
                    return Response({'error': 'Otp is Invalid, please provide valid otp'},
                                    status.HTTP_422_UNPROCESSABLE_ENTITY)
            else:
                return Response({'error': 'Email does not exists, please provide valid email'},
                                status.HTTP_422_UNPROCESSABLE_ENTITY)
        except Exception as e:
            print(str(e))
            return Response({'error': 'Please provide valid email information', "msg": str(e)},
                            status.HTTP_400_BAD_REQUEST)


class BillingAddressViewSet(viewsets.ModelViewSet):
    serializer_class = BillingAddressSerializer
    queryset = BillingAddress.objects.all()


@api_view(['POST'])
def session_setup(request):
    if request.method == 'POST':
        data = request.data
        environment = data.get('environment', None)
        location = data.get('location', None)
        device_id = data.get('device_id', None)
        user_id = data.get('user_id', None)
        if environment and location and device_id:
            device = Device.objects.filter(pk=device_id).first()
            user = User.objects.filter(pk=user_id).first()
            session_create = Session.objects.create(environment=environment, device_id=device, user_id=user,
                                                    location=location)
            return Response('Session Created Successfully', status=status.HTTP_200_OK)

