from datetime import timedelta

from django.contrib.auth.models import User

from sw_admin_app.models import Subscription, UserOtp, BillingAddress, Device, Session, SessionData, PaymentMethod
from .serializers import UserSerializer, RegisterSerializer, UserProfileSerializer, UserDetailSerializer, \
    BillingAddressSerializer, DeviceSerializer
from .stripe import delete_subscription, create_payment_customer, create_payment_method
from .utils import get_member_id, get_paginated_response, generate_user_cards, get_attachment_from_name

from django.contrib.auth import authenticate
from requests import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from django.utils import timezone
from sw_admin_app.utils import generate_otp
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from sw_api_app.utils import SendMailNotification
from rest_framework.permissions import IsAuthenticated


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
        at = token.access_token
        at.set_exp(from_time=None, lifetime=timedelta(days=360))
        access_token = str(at)
        token.set_exp(from_time=None, lifetime=timedelta(days=367))

        payment_method = user.subscription_set.filter(status=1).count()
        payment_method_added = False
        if payment_method > 0:
            payment_method_added = True
        session_count = user.session_set.count()
        user_name = user.first_name
        if len(user.last_name) > 0:
            user_name = user.first_name + ' ' + user.last_name
        token_items = {
            'user_id': user.pk,
            'name': user_name,
            'email_id': user.email
        }
        for item in token_items:
            if item != "user_id":
                RefreshToken.__setitem__(token, item, token_items[item])
        token_items['access_token'] = access_token
        token_items['refresh_token'] = str(token)
        token_items['device_count'] = payment_method
        token_items['payment_method_added'] = payment_method_added
        token_items['payment_method_count'] = payment_method
        token_items['session_count'] = session_count
        token_items['stripe_customer_id'] = user.user_profile.stripe_customer_id
        response = token_items
        return Response(response)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(username=email, password=password)
        if user is not None:
            token = RefreshToken.for_user(user)  # generate token without username & password

            at = token.access_token
            at.set_exp(from_time=None, lifetime=timedelta(days=360))
            access_token = str(at)
            token.set_exp(from_time=None, lifetime=timedelta(days=367))

            user_name = user.first_name
            if len(user.last_name) > 0:
                user_name = user.first_name + ' ' + user.last_name
            payment_method = user.subscription_set.filter(status=1).count()
            payment_method_added = False
            if payment_method > 0:
                payment_method_added = True
            session_count = user.session_set.count()

            token_items = {
                'user_id': user.pk,
                'name': user_name,
                'email_id': user.email
            }
            for item in token_items:
                if item != "user_id":
                    RefreshToken.__setitem__(token, item, token_items[item])
            token_items['access_token'] = access_token
            token_items['refresh_token'] = str(token)
            token_items['device_count'] = payment_method
            token_items['payment_method_added'] = payment_method_added
            token_items['payment_method_count'] = payment_method
            token_items['session_count'] = session_count
            response = token_items
            if not hasattr(user, "user_profile"):
                customer_create = create_payment_customer(user_name, email)
                response['stripe_customer_id'] = customer_create['id']
                user_name = f"{user.first_name} {user.last_name}"
                user_profile_serializer = UserProfileSerializer(
                    data={"user_id": user.pk, "user_profile_image": get_attachment_from_name(user_name),
                          "stripe_customer_id": customer_create['id']})
                if user_profile_serializer.is_valid():
                    user_profile_serializer.save()
            if hasattr(user, "user_profile"):
                response['stripe_customer_id'] = user.user_profile.stripe_customer_id
            return Response(response, status=status.HTTP_200_OK)
        else:
            content = {'message': 'Invalid User Information Provided'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_device_registration(request):
    if request.method == 'POST':
        try:
            device_id = request.data.get('device_id', None)
            user_id = get_member_id(request)
            subscription = Subscription.objects.get(user_id=user_id, device_id=device_id)
            if subscription:
                if subscription.status == 1:
                    return Response({"is subscribed": True}, status=status.HTTP_200_OK)
                else:
                    return Response({"is subscribed": False}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print('Error Detail', str(e))


class TriggerOtp(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        if email:
            try:
                user = User.objects.get(email=email)
                if user:
                    otp = generate_otp()
                    user_otp = UserOtp(user_id=user, otp=otp)
                    user_otp.save()
                    SendMailNotification(otp, user).start()
                    return Response({"status": "success", "message": "OTP has been triggered Successfully"},
                                    status=status.HTTP_200_OK)
            except:
                return Response({"error": "Email does not exists"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "Please provide valid Email"}, status=status.HTTP_400_BAD_REQUEST)


class OtpVerified(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        otp = request.data.get('otp', None)
        password = request.data.get('password', None)
        confirm_password = request.data.get('confirm_password', None)
        now = timezone.now()
        try:
            user = User.objects.filter(email=email).get()
            if user.email == email:
                user_otp = user.userotp_set.order_by('-created_at').first()
                if user_otp.otp == otp:
                    if user_otp.created_at <= now <= user_otp.expired_at:
                        user_otp.__dict__.update({'is_validated': True})
                        user_otp.save()
                        if password == confirm_password:
                            user.set_password(password)
                            user.save()
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
                                'user_id': user.pk,
                                'name': user_name,
                                'email_id': user.email
                            }
                            for item in token_items:
                                if item != "user_id":
                                    RefreshToken.__setitem__(token, item, token_items[item])
                            token_items['access_token'] = str(token.access_token)
                            token_items['refresh_token'] = str(token)
                            token_items['device_count'] = payment_method
                            token_items['payment_method_added'] = payment_method_added
                            token_items['payment_method_count'] = payment_method
                            token_items['session_count'] = session_count
                            response = token_items
                            if not hasattr(user, "user_profile"):
                                customer_create = create_payment_customer(user_name, email)
                                response['stripe_customer_id'] = customer_create['id']
                                user_name = f"{user.first_name} {user.last_name}"
                                user_profile_serializer = UserProfileSerializer(
                                    data={"user_id": user.pk, "user_profile_image": get_attachment_from_name(user_name),
                                          "stripe_customer_id": customer_create['id']})
                                if user_profile_serializer.is_valid():
                                    user_profile_serializer.save()
                            if hasattr(user, "user_profile"):
                                response['stripe_customer_id'] = user.user_profile.stripe_customer_id
                            return Response(response)
                        else:
                            return Response({"error": "Password fields didn't match."},
                                            status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({"error": 'Otp is expired'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

                else:
                    return Response({'error': 'Otp is Invalid, please provide valid otp'},
                                    status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            else:
                return Response({'error': 'Email does not exists, please provide valid email'},
                                status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        except Exception as e:
            print(str(e))
            return Response({'error': 'Please provide valid email information', "msg": str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        member_id = get_member_id(request)
        user = User.objects.get(pk=member_id)
        user_detail = UserDetailSerializer(instance=user, read_only=True, many=False)
        user_details = user_detail.data
        return Response(user_details, status.HTTP_200_OK)

    def patch(self, request):
        member_id = get_member_id(request)
        user = User.objects.get(pk=member_id)
        user_detail = UserDetailSerializer(instance=user, data=request.data, many=False, partial=True)
        user_detail.is_valid(raise_exception=True)
        user_detail.save()
        if hasattr(user, 'user_profile'):
            user_profile = UserProfileSerializer(instance=user.user_profile, data=request.data, many=False,
                                                 partial=True)
            user_profile.is_valid(raise_exception=True)
            user_profile.save()
        return Response(user_detail.data, status=status.HTTP_200_OK)


class BillingAddressViewSet(viewsets.ModelViewSet):
    serializer_class = BillingAddressSerializer
    queryset = BillingAddress.objects.all()


class DeviceViewSet(viewsets.ModelViewSet):
    serializer_class = DeviceSerializer
    queryset = Device.objects.all()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def session_setup(request):
    if request.method == 'POST':
        data = request.data
        user_id = get_member_id(request)
        environment = data.get('environment', None)
        location = data.get('location', None)
        device_serial_no = data.get('device_serial_no', None)
        city = data.get('city', None)
        state = data.get('state', None)
        country = data.get('country', None)
        pin_code = data.get('pin_code', None)
        latitude = data.get('latitude', None)
        longitude = data.get('longitude', None)
        try:
            if device_serial_no:
                is_device = Device.objects.get(device_serial_no=device_serial_no)
                if is_device:
                    is_subscribed = Subscription.objects.filter(device_id__device_serial_no=device_serial_no, status=1)
                    if is_subscribed:
                        if environment and location and is_device and user_id:
                            user = User.objects.filter(pk=user_id).first()
                            session_create = Session.objects.create(environment=environment, device_id=is_device,
                                                                    user_id=user, location=location, city=city,
                                                                    state=state, country=country,
                                                                    pin_code=pin_code, latitude=latitude,
                                                                    longitude=longitude)
                            return Response({'message': 'Session Created Successfully'}, status=status.HTTP_200_OK)
                        else:
                            return Response({'message': 'Please provide valid data information'},
                                            status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({"message": "No Subscription is Active for this device, Please do payment for "
                                                    "further process "}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"message": "Failed, to setup the session", "reason": str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_registration(request):
    user_id = get_member_id(request)
    subscription_id = request.data.get('subscription_id', None)
    subscription = Subscription.objects.filter(id=subscription_id, user_id=user_id).exists()
    if subscription:
        delete_subscription(subscription_id)
        Subscription.objects.filter(id=subscription_id).update(status=0)
        return Response('Subscription Cancelled !!!', status=status.HTTP_200_OK)
    else:
        return Response('Invalid Subscription ID Provided', status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_data_save(request, session_id):
    data = request.data
    session_data = data.get('session_data', None)
    device_serial_no = data.get('device_serial_no', None)
    user_id = get_member_id(request)
    if session_id and session_data and device_serial_no and user_id:
        device = Device.objects.filter(device_serial_no=device_serial_no).first()
        user = User.objects.filter(pk=user_id).first()
        session = Session.objects.filter(pk=session_id).first()
        energy_list = session_data['energy_levels']
        low_energy_level = min(energy_list)
        high_energy_level = max(energy_list)
        session_data = SessionData.objects.create(energy_data=session_data, lowest_energy_level=low_energy_level,
                                                  highest_energy_level=high_energy_level, session_id=session,
                                                  device_id=device, user_id=user)
        return Response({'message': "Session Data Save Successfully"}, status=status.HTTP_200_OK)
    else:
        return Response({'message': "Please provide valid data"}, status=status.HTTP_404_NOT_FOUND)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def session_list(request, device_id):
    user_id = get_member_id(request)
    location = request.GET.get('location', None)
    start_date = request.GET.get('start_date', None)
    end_date = request.GET.get('end_date', None)
    if start_date and not end_date:
        return Response("please provide End_date")
    if not start_date and end_date:
        return Response("please provide Start_date")
    session = Session.objects.filter(device_id=device_id, user_id=user_id)
    if start_date and end_date:
        session = session.filter(created_at__range=(start_date, end_date))
    if location:
        session = session.filter(location__icontains=location)

    return Response(session.values())


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_users(request):
    if request.method == 'POST':
        user_name = request.data.get('user_name')
        email = request.data.get('email')
        password = request.data.get('password')
        if user_name and email and password:
            if 'zaigoinfotech' in email:
                User.objects.create_superuser(user_name, email, password)
                return Response('User created successfully', status=status.HTTP_200_OK)
            else:
                return Response('Sorry, Access Denied', status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response('Please Provide Valid Credentials', status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def previous_connected_list(request):
    if request.method == 'GET':
        try:
            user_id = get_member_id(request)
            subscriptions = Subscription.objects.filter(user_id=user_id)
            final_list = []
            for subscription in subscriptions:
                registered_list = {'subscription_id': subscription.id,
                                   'subscription_stripe_payment_id': subscription.stripe_payment_id,
                                   'subscription_stripe_customer_id': subscription.stripe_customer_id,
                                   'device_name': subscription.device_id.device_name,
                                   'device_serial_no': subscription.device_id.device_serial_no,
                                   'is_subscription_active': subscription.status,
                                   'subscription_start_date': subscription.start_date,
                                   'subscription_end_date': subscription.end_date}
                final_list.append(registered_list)
            return Response(final_list, status=status.HTTP_200_OK)
        except Exception as e:
            return Response('No Devices !!', status=status.HTTP_204_NO_CONTENT), print(str(e))


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def device_session_history(request):
    user_id = get_member_id(request)
    device_serial_no = request.data.get('device_serial_no', None)
    limit = request.GET.get('per_page', 9)
    page_number = request.GET.get('page', 1)
    current_url = f'{request.build_absolute_uri()}'
    extras = {
        "per_page": limit
    }
    device_id_list = Subscription.objects.filter(user_id=user_id, status=1).values_list('device_id', flat=True)
    if device_id_list:
        sub_device = SessionData.objects.filter(user_id=user_id, device_id__in=device_id_list).order_by('created_at')
        if device_serial_no:
            sub_device = sub_device.filter(device_id__device_serial_no=device_serial_no).order_by('created_at')
        response = get_paginated_response(sub_device, current_url, page_number, limit, extras)
        response['data'] = generate_user_cards(response['data'], True)
        return Response(response, status=status.HTTP_200_OK)
    return Response(get_paginated_response(Device.objects.none(), current_url, 1, limit, extras, True))


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def payment_method_creation(request):
    if request.method == 'POST':
        try:
            card_type = request.data.get('card_type', None)
            card_number = request.data.get('card_number', None)
            card_exp_month = request.data.get('card_exp_month', None)
            card_exp_year = request.data.get('card_exp_year', None)
            card_cvc = request.data.get('card_cvc', None)
            name = request.data.get('name', None)
            email = request.data.get('email', None)
            address = request.data.get('address', None)
            user_id = get_member_id(request)
            payment_id = create_payment_method(card_type, card_number, card_exp_month, card_exp_year, card_cvc, name,
                                               email, address)
            PaymentMethod.objects.create(payment_id=payment_id, user_id=user_id)
            return Response('Payment method saved successfully', status=status.HTTP_200_OK)
        except Exception as e:
            return Response('Error Occurred', status=status.HTTP_400_BAD_REQUEST), print(str(e))
