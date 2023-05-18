import binascii
import datetime
import hashlib
from datetime import timedelta
from itertools import count

import pytz
import stripe
from django.contrib.auth.models import User
from django.db.models import Subquery, OuterRef, Max, Min, Q
from ecdsa import SigningKey, NIST256p

from SHOCK_WAVE import settings
from sw_admin_app.models import Subscription, UserOtp, BillingAddress, Device, Session, SessionData, PaymentMethod, \
    UserProfile, DevicePrice, SubscriptionPeriod
from .serializers import UserSerializer, RegisterSerializer, UserProfileSerializer, UserDetailSerializer, \
    BillingAddressSerializer, DeviceSerializer, SubscriptionSerializer
from .stripe import delete_subscription, create_payment_customer, create_payment_method, attach_payment_method, \
    create_address, create_product, create_price, create_subscription, delete_stripe_payment_method
from .utils import get_member_id, get_paginated_response, generate_user_cards, get_attachment_from_name, \
    get_recuring_periods, \
    unix_timestamp_format, INACTIVE

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
import pdfkit
from django.template.loader import render_to_string


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

        payment_method = user.paymentmethod_set.count()
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
            payment_method = user.paymentmethod_set.count()
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
                          "stripe_customer_id": customer_create['id']
                          })
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
            device_serial_no = request.data.get('device_serial_no', None)
            user_id = get_member_id(request)
            subscription = Subscription.objects.filter(user_id=user_id,
                                                       device_id__device_serial_no=device_serial_no, status=1).first()
            device_price = DevicePrice.objects.get()
            if subscription:
                if subscription.status == 1:
                    return Response({"is_subscribed": True,
                                     "device_price": device_price.price}, status=status.HTTP_200_OK)
            else:
                return Response({"is_subscribed": False,
                                 "device_price": device_price.price}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"is_subscribed": False, "message": "From Exception", "error": "From Exception"},
                            status=status.HTTP_200_OK)


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
            if user:
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

    def get(self, request):
        user_id = get_member_id(request)
        billing_address = self.request.query_params.get(user_id=user_id)
        billing_address_detail = BillingAddressSerializer(instance=billing_address, read_only=True, many=False)
        billing_address_details = billing_address_detail.data
        return Response(billing_address_details, status.HTTP_200_OK)

    def put(self, request):
        user_id = get_member_id(request)
        billing_address = BillingAddress.objects.get(user_id=user_id)
        serializer = BillingAddressSerializer(instance=billing_address, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        user_id = get_member_id(request)
        billing_address = BillingAddress.objects.get(user_id=user_id)
        serializer = BillingAddressSerializer(instance=billing_address, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


class DeviceViewSet(viewsets.ModelViewSet):
    serializer_class = DeviceSerializer
    queryset = Device.objects.all()


class SubscriptionViewSet(viewsets.ModelViewSet):
    serializer_class = SubscriptionSerializer
    queryset = Subscription.objects.all()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def session_setup(request):
    try:
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
            if device_serial_no:
                is_device = Device.objects.filter(device_serial_no=device_serial_no).first()
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
                            return Response(
                                {'message': 'Session Created Successfully', 'session_id': session_create.pk},
                                status=status.HTTP_200_OK)
                        else:
                            return Response({'message': 'Please provide valid data information'},
                                            status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({"message": "No Subscription is Active for this device, Please do payment for "
                                                    "further process "}, status=status.HTTP_204_NO_CONTENT)
                else:
                    return Response({"message": "Device not found,please provide valid device id"},
                                    status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return Response({"message": "Failed, to setup the session", "reason": str(e)},
                        status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_registration(request):
    if request.method == 'POST':
        try:
            user_id = get_member_id(request)
            device_serial_no = request.data['device_serial_no']
            subscription = Subscription.objects.filter(user_id=user_id,
                                                       device_id__device_serial_no=device_serial_no, status=1).first()
            if subscription:
                delete_subscription(subscription.stripe_subscription_id)
                # setattr(subscription, 'status', 0)
                subscription.status = 0
                subscription.save()
                return Response({'message': 'Subscription Cancelled !!!'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid ID Provided'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error_message": str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_data_save(request, session_id):
    """
    Api for save the session data history against the respective user,device and session.
    """
    try:
        data = request.data
        session_data = data.get('session_data', None)
        device_serial_no = data.get('device_serial_no', None)
        user_id = get_member_id(request)
        if session_id and session_data and device_serial_no and user_id:
            # device = Device.objects.filter(device_serial_no=device_serial_no).order_by('-created_at').first()
            subscription = Subscription.objects.filter(device_id__device_serial_no=device_serial_no, user_id=user_id,
                                                       status=1).order_by('-created_at').first()
            if subscription.device_id:
                user = User.objects.filter(pk=user_id).first()
                session = Session.objects.filter(pk=session_id).first()
                # session data value provide as list so save as json with key "energy_levels"
                energy_list = session_data['energy_levels']
                # In list take overall minimum and maximum for a session by using below function.
                low_energy_level = min(energy_list)
                high_energy_level = max(energy_list)
                session_data = SessionData.objects.create(energy_data=energy_list, lowest_energy_level=low_energy_level,
                                                          highest_energy_level=high_energy_level, session_id=session,
                                                          device_id_id=subscription.device_id.id, user_id=user)
                end_date = session_data.created_at
                Session.objects.filter(pk=session_id).update(session_end_date=end_date)
                return Response({"message": "Session Data Save Successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({'message': "Device not found"}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'message': "Please provide valid data"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def session_list(request, device_id):
#     user_id = get_member_id(request)
#     location = request.GET.get('location', None)
#     start_date = request.GET.get('start_date', None)
#     end_date = request.GET.get('end_date', None)
#     if start_date and not end_date:
#         return Response("please provide End_date")
#     if not start_date and end_date:
#         return Response("please provide Start_date")
#     session = Session.objects.filter(device_id=device_id, user_id=user_id)
#     if start_date and end_date:
#         session = session.filter(created_at__range=(start_date, end_date))
#     if location:
#         session = session.filter(location__icontains=location)
#
#     return Response(session.values())

# @api_view(["POST"])
# @permission_classes([IsAuthenticated])
# def session_list(request):
#     if request.method == 'POST':
#     user_id = get_member_id(request)
#     start_date = request.data.get('start_date', None)
#     end_date = request.data.get('end_date', None)
#     device_id = request.data.get('device_id', None)
#     if start_date and not end_date:
#         return Response("please provide End_date")
#     if not start_date and end_date:
#         return Response("please provide Start_date")
#     if start_date and end_date:
#         device_list = Subscription.objects.filter(user_id=user_id, status=1, device_id=device_id).values_list(
#             'device_id', flat=True)
#         sessions = Session.objects.filter(device_id__in=device_list,
#                                           created_at__range=(start_date, end_date)).values_list('id', flat=True)
#         environment_type = Session.objects.filter(device_id__in=device_list).first().environment
#         max_values = []
#         for session in sessions:
#             session_data = {}
#             data = SessionData.objects.filter(session_id=session).aggregate(Max('highest_energy_level')).values(
#                 'created_at', 'highest_energy_level__max')
#
#             # data = SessionData.objects.filter(session_id=session).values('created_at').annotate(max=Max(
#             # 'highest_energy_level'))
#             print(data)
#         return Response(
#             {'device': device_id, 'date': f"{start_date} to {end_date}", 'no_of_section': len(sessions),
#              'environment_type': environment_type})

# @api_view(["POST"])
# @permission_classes([IsAuthenticated])
# def session_list(request):
#     if request.method == 'POST':
#         try:
#             user_id = get_member_id(request)
#             device_serial_no = request.data.get('device_serial_no', None)
#             if not device_serial_no:
#                 return Response({"status": "failure", "error": "Device Serial Number is required."})
#             start_date = request.data.get('start_date', None)
#             end_date = request.data.get('end_date', None)
#             if start_date and not end_date:
#                 return Response("please provide End_date")
#             if not start_date and end_date:
#                 return Response("please provide Start_date")
#             from_date_time_obj = timezone.datetime.strptime(start_date, "%Y-%m-%d")
#             end_date_time_obj = timezone.datetime.strptime(end_date, "%Y-%m-%d")
#             date_range = end_date_time_obj - from_date_time_obj
#             dates = list()
#             for days in range(0, date_range.days + 1):
#                 dates.append((from_date_time_obj + datetime.timedelta(days)).strftime('%Y-%m-%d'))
#             # device_id = Device.objects.filter(device_serial_no=device_serial_no).first().id
#             date_values = []
#             for date in dates:
#                 from_date = timezone.datetime.strptime(date, "%Y-%m-%d")
#                 to_date = from_date + timedelta(hours=23, minutes=59)
#                 sessions = Session.objects.filter(user_id=user_id,
#                                                   created_at__range=(from_date, to_date))
#                 time_zone = get_local_time_zone(request)
#                 values_list = []
#                 for session in sessions:
#                     sub_values = {}
#                     qs = SessionData.objects.filter(session_id=session)
#                     data = qs.values_list('highest_energy_level', flat=True)
#                     if data:
#                         sub_values['session'] = session.pk
#                         date_time = qs.order_by('-highest_energy_level').first().created_at
#                         # sub_values['timestamp'] = str(qs.order_by('-highest_energy_level').first().created_at)
#                         sub_values['timestamp'] = convert_to_local_time(date_time, time_zone)
#                         sub_values['session_environment'] = session.environment
#                         sub_values['maximum_value'] = max(data)
#                         date_values.append(sub_values)
#                         # values_list.append(sub_values)
#                 # date_values.append(values_list)
#             return Response(date_values, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
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


@api_view(['POST'])
def create_device_price_admin(request):
    if request.method == 'POST':
        try:
            device_price = request.data['device_price']
            DevicePrice.objects.create(price=device_price)
            return Response('Device price created successfully', status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def previous_connected_list(request):
    if request.method == 'GET':
        try:
            user_id = get_member_id(request)
            subscriptions = Subscription.objects.filter(user_id=user_id, status=1)
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
            return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def device_session_data_history(request):
    user_id = get_member_id(request)
    device_serial_no = request.data.get('device_serial_no', None)
    session_id = request.data.get('session_id', None)
    start_date = request.data.get('start_date', None)
    end_date = request.data.get('end_date', None)
    limit = request.GET.get('per_page', 9)
    page_number = request.GET.get('page', 1)
    time_zone = get_local_time_zone(request)
    current_url = f'{request.build_absolute_uri()}'
    extras = {
        "per_page": limit
    }
    if start_date and not end_date:
        return Response("please provide End_date")
    if not start_date and end_date:
        return Response("please provide Start_date")
    subscription_qs = Subscription.objects.filter(user_id=user_id, device_id__device_serial_no=device_serial_no,
                                                  status=1)
    subscription = subscription_qs.order_by('-created_at').first()
    device_id_list = []
    if subscription:
        device_id_list = [subscription.device_id]
    if subscription_qs.exists():
        sub_device = SessionData.objects.filter(session_id__id=session_id).order_by('created_at')
        # if session_id:
        #     sub_device = sub_device.filter(session_id__id=session_id).order_by('created_at')
        if start_date and end_date:
            sub_device = sub_device.filter(created_at__range=(start_date, end_date)).order_by('created_at')
        session_data = get_session_data(sub_device, session_id, time_zone)

        return Response(session_data, status.HTTP_200_OK)
        # subscription = subscription_qs.first()

        # response = get_paginated_response(sub_device, current_url, page_number, limit, extras)
        # response['data'] = generate_user_cards(response['data'], True)
        # return Response(response, status=status.HTTP_200_OK)
    return Response({"data": "No Data", "message": "No Subscribed device against the user"})


def get_session_data(sub_device, session_id, time_zone):
    data_list = []
    for sub_dev in sub_device:
        data = {"created_at": convert_to_local_time(sub_dev.created_at, time_zone),
                "highest_energy_level": sub_dev.highest_energy_level}
        data_list.append(data)
    session = Session.objects.filter(pk=session_id).first()
    if not session:
        return Response({"data": "Failure", "message": "Invalid Session ID Provided"}, status.HTTP_400_BAD_REQUEST)
    session_max_min = SessionData.objects.filter(session_id=session).aggregate(
        max_value=Max('highest_energy_level'),
        min_value=Min('highest_energy_level'))
    response = {
        "device_id": session.device_id.pk,
        "device_serial_no": session.device_id.device_serial_no,
        "session_created_at": convert_to_local_time(session.created_at, time_zone),
        "location": session.location,
        "environment_type": session.environment,
        "session_maximum_value": session_max_min.get('max_value', 0.0),
        "session_minimum_value": session_max_min.get('min_value', 0.0),
        # "data": sub_device.values('created_at', 'highest_energy_level')
        "pdf_export_url": pdf_generate(sub_device, time_zone),
        "data": data_list
    }
    return response


def pdf_generate(sub_device, time_zone):
    try:
        data_list = []
        for data in sub_device:
            session_data = {}
            session_data.update({"device_id": data.device_id.device_serial_no})
            session_data.update({"device_name": data.device_id.device_name})
            session_data.update({"environment": data.session_id.environment})
            session_data.update({"highest_energy_level": data.highest_energy_level})
            session_data.update({"lowest_energy_level": data.lowest_energy_level})
            session_data.update({"session_date": convert_to_local_time(data.created_at, time_zone)})
            data_list.append(session_data)

        initial_session_data = sub_device.first()
        if initial_session_data:
            location = initial_session_data.session_id.location
            device_name = initial_session_data.device_id.device_name
            session_id = initial_session_data.session_id.pk
            environment = initial_session_data.session_id.environment
        else:
            location = device_name = session_id = environment = "-"
        context = {'datas': data_list,
                   'location': location,
                   'device_name': device_name,
                   'session_id': session_id,
                   'environment': environment}
        html_string = render_to_string('email/export.html', context)
        # Convert the HTML to a PDF and save it to a file
        file_name = f'media/{session_id}_{timezone.now().strftime("%Y%m%d%s%f")}.pdf'
        d = pdfkit.from_string(html_string, file_name)
        # Send the PDF file as a response to the user
        url = f'{settings.MY_DOMAIN}{file_name}'
    except:
        url = None
    return url


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
            line1 = request.data.get('line1', None)
            line2 = request.data.get('line2', None)
            city = request.data.get('city', None)
            state = request.data.get('state', None)
            postal_code = request.data.get('postal_code', None)
            country = request.data.get('country', None)
            address = create_address(line1, line2, city, state, postal_code, country)
            user_id = get_member_id(request)
            user = User.objects.get(pk=user_id)
            user_profile = UserProfile.objects.get(user_id=user_id)
            stripe_customer_id = user_profile.stripe_customer_id
            created_payment_method_id = create_payment_method(card_type, card_number, card_exp_month, card_exp_year,
                                                              card_cvc,
                                                              name, email, address)
            card_last4_number = created_payment_method_id['card']['last4']

            payment_method_id = PaymentMethod.objects.create(payment_id=created_payment_method_id['id'],
                                                             card_last4_no=card_last4_number,
                                                             user_id_id=user_id)
            attach_payment_method(stripe_customer_id, created_payment_method_id['id'])
            customer_update = stripe.Customer.modify(stripe_customer_id,
                                                     invoice_settings={
                                                         'default_payment_method': created_payment_method_id['id']})
            billing_address = BillingAddress.objects.create(name=name, user_id_id=user_id, line_1=line1, line_2=line2,
                                                            city=city,
                                                            state=state, country=country, pin_code=postal_code)
            if billing_address:
                address_format = f"{line1} {line2} {city} {state} {postal_code}"
                address_format = address_format.strip()
                user_address = UserProfile.objects.filter(user_id=user_id).update(user_address=address_format)
            return Response(
                {'detail': 'Payment method created successfully', 'payment_method_id': payment_method_id.id,
                 "card_last4_number": card_last4_number},
                status=status.HTTP_200_OK)
        except Exception as e:
            error_msg = str(e)
            split_error_msg = str(e).split(":")
            if len(split_error_msg) > 1:
                error_msg = split_error_msg[1].strip()
            return Response({"status": "failure", "error": error_msg, "message": error_msg},
                            status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def my_payment_method(request):
    if request.method == 'GET':
        try:
            user_id = get_member_id(request)
            payment_method_list = PaymentMethod.objects.filter(user_id=user_id)
            payment_list = []
            for payment_method in payment_method_list:
                subscriptions = payment_method.subscription_set.filter(status=1)
                payment_method_added = bool(subscriptions)
                data_list = {
                    "is_subscribed_card": payment_method_added,
                    "id": payment_method.id,
                    "payment_id": payment_method.payment_id,
                    "card_last4_no": payment_method.card_last4_no,
                    "user_id": payment_method.user_id.id,
                    "created_at": payment_method.created_at,
                    "updated_at": payment_method.updated_at
                }
                payment_list.append(data_list)
            return Response(payment_list, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


""" function for get the updated price for recuring"""


def device_price_update():
    device_price = DevicePrice.objects.order_by('-created_at').first()
    if device_price:
        price = int(device_price.price * 100)
    else:
        price = '2500'
    return price


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def payment_method_initialized(request):
    try:
        if request.method == "POST":
            device_serial_no = request.data.get('device_serial_no')
            device_name = request.data.get('device_name')
            payment_method_id = request.data.get('payment_method_id')

            user_id = get_member_id(request)
            user = User.objects.get(pk=user_id)
            user_profile = UserProfile.objects.get(user_id=user_id)
            stripe_customer_id = user_profile.stripe_customer_id
            is_device_exists = Subscription.objects.filter(user_id=user_id,
                                                           device_id__device_serial_no=device_serial_no,
                                                           status=1).exists()
            if not is_device_exists:
                if payment_method_id:
                    payment_method = PaymentMethod.objects.filter(pk=payment_method_id, user_id=user_id).order_by(
                        '-created_at').first()
                else:
                    payment_method = PaymentMethod.objects.filter(user_id=user_id).order_by('-created_at').first()
                stripe_payment_id = payment_method.payment_id
                if device_serial_no and device_name and stripe_customer_id:
                    stripe_product_id = create_product(product_name=device_serial_no,
                                                       description=f'The {device_name},{device_serial_no} device is '
                                                                   f'registered.')['id']
                    device_price = device_price_update()
                    stripe_product_price_id = \
                        create_price(amount=device_price, currency='usd', interval='month',
                                     product_id=stripe_product_id)['id']
                    stripe_Subscription_id = \
                        create_subscription(customer_id=stripe_customer_id, price_id=stripe_product_price_id,
                                            default_payment_method=stripe_payment_id)

                    if stripe_Subscription_id.status == "active":
                        recuring_period = get_recuring_periods(stripe_Subscription_id.current_period_start,
                                                               stripe_Subscription_id.current_period_end)
                        start_date = recuring_period["start_date"]
                        end_date = recuring_period["end_date"]
                    else:
                        # Pay Latest Invoice of Subscription 
                        invoice = stripe.Invoice.pay(stripe_Subscription_id.latest_invoice)  # Invoice already not paid
                        # payment_intent = stripe.PaymentIntent.create(amount=2500, currency='usd')
                        # need to register the device in our table
                        recuring_period = get_recuring_periods(invoice.lines.data[0].period.start,
                                                               invoice.lines.data[0].period.end)
                        start_date = recuring_period["start_date"]
                        end_date = recuring_period["end_date"]

                    register_device = Device.objects.create(device_serial_no=device_serial_no, device_name=device_name,
                                                            device_price_id=stripe_product_price_id)
                    subscription = Subscription.objects.create(status=INACTIVE, device_id=register_device, user_id=user,
                                                               payment_method_id=payment_method,
                                                               stripe_payment_id=stripe_payment_id,
                                                               stripe_subscription_id=stripe_Subscription_id['id'],
                                                               stripe_customer_id=stripe_customer_id,
                                                               start_date=start_date,
                                                               end_date=end_date)
                    return Response({"message": "payment done successfully"}, status=status.HTTP_200_OK)
                return Response({"message": "Please provide valid data"}, status=status.HTTP_204_NO_CONTENT)
            else:
                return Response({"message": "This device is already Subscribed"}, status=status.HTTP_200_OK)
    except Exception as e:
        error_msg = str(e)
        split_error_msg = str(e).split(":")
        if len(split_error_msg) > 1:
            error_msg = split_error_msg[1].strip()
        return Response({"status": "failure", "error": error_msg, "message": error_msg},
                        status=status.HTTP_400_BAD_REQUEST)


# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def delete_payment_method(request):
#     if request.method == 'POST':
#         try:
#             user_id = get_member_id(request)
#             PaymentMethod.objects.filter(user_id=user_id).delete()
#             return Response('Payment method deleted successfully', status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_password(request):
    if request.method == "PUT":
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not user.check_password(old_password):
            return Response({'error': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def export_session_data_history_as_pdf(request):
#     user_id = get_member_id(request)
#     device_serial_no = request.data.get('device_serial_no', None)
#     session_id = request.data.get('session_id', None)
#     start_date = request.data.get('start_date', None)
#     end_date = request.data.get('end_date', None)
#     export_data = request.data.get('export_data', None)
#     limit = request.GET.get('per_page', 9)
#     page_number = request.GET.get('page', 1)
#     current_url = f'{request.build_absolute_uri()}'
#     extras = {
#         "per_page": limit
#     }
#     if start_date and not end_date:
#         return Response("please provide End_date")
#     if not start_date and end_date:
#         return Response("please provide Start_date")
#     device_id_list = Subscription.objects.filter(user_id=user_id, status=1).values_list('device_id', flat=True)
#     if device_id_list:
#         sub_device = SessionData.objects.filter(user_id=user_id, device_id__in=device_id_list).order_by('created_at')
#         if device_serial_no and session_id:
#             sub_device = sub_device.filter(device_id__device_serial_no=device_serial_no,
#                                            session_id__id=session_id).order_by('created_at')
#         if start_date and end_date:
#             sub_device = sub_device.filter(created_at__range=(start_date, end_date)).order_by('created_at')
#         response = get_paginated_response(sub_device, current_url, page_number, limit, extras)
#         response['data'] = generate_user_cards(response['data'], True)
#         # if export_data:
#         # context = {'datas': response['data']}
#         # return render(request, 'email/export.html', context)
#         session_list = []
#         for data in response['data']:
#             session_data = {}
#             session_data.update({"device_id": data["device_serial_no"]})
#             session_data.update({"device_name": data["device_name"]})
#             session_data.update({"environment": data["environment"]})
#             session_data.update({"highest_energy_level": data["highest_energy_level"]})
#             session_data.update({"lowest_energy_level": data["lowest_energy_level"]})
#             session_data.update({"session_date": data["created_at"]})
#             session_list.append(session_data)
#         initial_session_data = sub_device.first()
#         if initial_session_data:
#             location = initial_session_data.session_id.location
#             device_name = initial_session_data.device_id.device_name
#             session_id = initial_session_data.session_id.pk
#             environment = initial_session_data.session_id.environment
#         else:
#             location = device_name = session_id = environment = "-"
#         context = {'datas': session_list,
#                    'location': location,
#                    'device_name': device_name,
#                    'session_id': session_id,
#                    'environment': environment}
#         html_string = render_to_string('email/export.html', context)
#         # Convert the HTML to a PDF and save it to a file
#         file_name = f'media/{session_id}_{timezone.now().strftime("%Y%m%d%s%f")}.pdf'
#         d = pdfkit.from_string(html_string, file_name)
#         # Send the PDF file as a response to the user
#         url = f'{settings.MY_DOMAIN}{file_name}'
#         return Response({"url": url}, status.HTTP_200_OK)
#     return Response({"data": "NO data"})


# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_session_detail_history_for_graph(request):
#     device_serial_no = request.data.get('device_serial_no')
#     member_id = get_member_id(request)
#     # if not device_serial_no:
#     #     return Response({"status": "failure", "error": "Device Serial Number is required"}, status.HTTP_400_BAD_REQUEST)
#
#     # devices = Device.objects.filter(device_serial_no=device_serial_no).order_by('-created_at').values_list('pk',
#     #                                                                                                        flat=True)
#
#     subscription = Subscription.objects.filter(device_id__device_serial_no=device_serial_no, user_id=member_id,
#                                                status=1).order_by(
#         '-created_at').first()
#
#     if not subscription:
#         return Response({"status": "failure", "error": "Subscription is invalid or not exists"},
#                         status.HTTP_400_BAD_REQUEST)
#
#     active_device_id = subscription.device_id
#
#     # if session_id:
#
#     session_id = request.data.get('session_id', None)
#
#     if session_id:
#         params = {
#             "device_id": active_device_id,
#             "session_id": session_id
#         }
#     else:
#         params = {
#             "device_id": active_device_id
#         }
#     if active_device_id.session_set.count() > 1:
#
#         get_max_highest_energy_level_query = SessionData.objects.filter(session_id=OuterRef('session_id'),
#                                                                         device_id=OuterRef('device_id')).order_by(
#             'created_at').values('id')
#         session_datas = SessionData.objects.filter(**params).filter(
#             id=Subquery(get_max_highest_energy_level_query[:1])).values(
#             'created_at', 'highest_energy_level')
#
#         highest_session_data = utc_to_ist_timezone(session_datas)
#     else:
#         session_datas = list(
#             SessionData.objects.filter(device_id=active_device_id).order_by('created_at').values(
#                 'created_at', 'highest_energy_level')[:10])
#
#         highest_session_data = utc_to_ist_timezone(session_datas, request)
#         highest_session_data.reverse()
#
#     # session_data = SessionData.objects.filter(**params).values('created_at', 'highest_energy_level')
#
#     return Response(highest_session_data, status.HTTP_200_OK)


def utc_to_ist_timezone(session_datas, request):
    session_data_list = []
    local_time_zone = get_local_time_zone(request)
    for session_data in session_datas:
        session_data_dict = {}
        created_at_utc = convert_to_local_time(session_data['created_at'], local_time_zone)
        session_data['created_at'] = created_at_utc
        session_data_dict['created_at'] = session_data['created_at']
        session_data_dict['highest_energy_level'] = session_data['highest_energy_level']
        session_data_list.append(session_data_dict)
    return session_data_list


def convert_to_local_time(datetime, timezone):
    created_at_utc = datetime.replace(tzinfo=pytz.utc)
    if timezone:
        created_at_utc = created_at_utc.astimezone(timezone)
    return created_at_utc


def get_local_time_zone(request):
    local_time_zone = None
    for key, value in request.headers.items():
        if key == "Tz" and value:
            local_time_zone = pytz.timezone(value)
    return local_time_zone


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_payment_method(request):
    if request.method == "POST":
        try:
            payment_method_id = request.data.get('payment_method_id')
            user_id = get_member_id(request)
            subscribed = Subscription.objects.filter(user_id=user_id,
                                                     payment_method_id__pk=payment_method_id, status=1).exists()
            if not subscribed:
                payment_method = PaymentMethod.objects.filter(pk=payment_method_id).first()
                stripe_payment_id = payment_method.payment_id
                delete_stripe_payment_method(stripe_payment_id)
                payment_method.delete()
                return Response({"message": "Payment details removed successfully"})
            else:
                return Response({"message": "This payment details is already subscribed"})
        except Exception as e:
            return Response({'Error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_device(request):
    device_serial_no = request.data.get('device_serial_no', None)
    device_value = request.data.get('device_value', None)
    if not device_serial_no:
        return Response({"status": "failure", "error": "Device Serial Number is missing"}, status.HTTP_400_BAD_REQUEST)
    if not device_value:
        return Response({"status": "failure", "error": "Device Value is missing"}, status.HTTP_400_BAD_REQUEST)
    user_id = get_member_id(request)
    subscription = Subscription.objects.filter(device_id__device_serial_no=device_serial_no, user_id=user_id,
                                               status=1).order_by(
        '-created_at').first()
    if not subscription:
        return Response({"status": "failure", "error": "Subscription is not exist/active"}, status.HTTP_400_BAD_REQUEST)
    end_date = subscription.end_date
    difference_in_days = (end_date - timezone.now()).days
    # difference_in_days = (datetime.date.today() - end_date).days
    if difference_in_days >= 0:
        # text_to_replaced = 1.5 * difference_in_days
        # hex_conversion = hex(int(text_to_replaced))[2:]
        # text_to_be_replaced = hex_conversion.zfill(2)
        text_to_be_replaced = "02"
        device_value_list = list(device_value)
        device_value_list[2] = text_to_be_replaced[0]
        device_value_list[3] = text_to_be_replaced[1]
        device_value = "".join(device_value_list)
        # print("Updated device value", device_value)
        hex_value = generate_hex_string(device_value)
        if not hex_value:
            return Response({"status": "failure", "error": "Unable to get the device code"},
                            status.HTTP_400_BAD_REQUEST)
        return Response({"status": "success", "message": "Device Activated", "updated_device_value": device_value,
                         "device_code": hex_value.upper()}, status.HTTP_200_OK)
    return Response(
        {"status": "failure", "error": f"Unable to get the response as subscription days left is {difference_in_days}"},
        status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def user_subscription_period_list(request):
    if request.method == "GET":
        search = request.GET.get('search', None)
        subscription_period = SubscriptionPeriod.objects.order_by('-created_at')
        if search:
            subscription_period = subscription_period.filter(
                Q(subscription_id__user_id__username__icontains=search) |
                Q(subscription_id__device_id__device_serial_no__icontains=search) |
                Q(subscription_id__stripe_subscription_id__icontains=search) |
                Q(subscription_id__stripe_customer_id__icontains=search))
        return Response(subscription_period.values(), status=status.HTTP_200_OK)


# def generate_hex_string(value):
#     sk = SigningKey.generate(curve=NIST256p)
#     sk.from_pem("""
#              -----BEGIN EC PRIVATE KEY-----
#              MHcCAQEEIMaGe/ECPfwLyz1XAodBt3Y9VIAYA+R5zr8anbb79GqBoAoGCCqGSM49
#              AwEHoUQDQgAECwqZsBUJpT1Yua2PKB9+djq+l6iQbiVbnfCPMaEUyyv5GHt3srFp
#              HKhFVov1O8k6mw+2rMdybjfwtBx8NXZbIg==
#              -----END EC PRIVATE KEY-----
#             """)
#     hex_string = value
#     print("Length of Hex String", len(hex_string))
#     if len(hex_string) == 20:
#         msg = bytearray.fromhex(hex_string)
#         sig = sk.sign(msg, hashfunc=hashlib.sha256)
#         value_string = binascii.hexlify(msg)
#         encoded_string = binascii.hexlify(sig)
#         return value_string, encoded_string
#     return None


@api_view(['GET'])
def subscription_list(request):
    if request.method == 'GET':
        search = request.GET.get('search', None)
        subscriptions = Subscription.objects.order_by('-created_at')
        if search:
            subscriptions = subscriptions.filter(
                Q(device_id__device_name__icontains=search) | Q(user_id__username__icontains=search) | Q(
                    status__icontains=search))
        return Response(subscriptions.values(), status=status.HTTP_200_OK)


def generate_hex_string(device_value):
    import os
    import subprocess
    exe_path = "/app/LicenseUnlock"
    os.chmod(exe_path, 0o755)
    result = subprocess.run(["./LicenseUnlock", device_value], cwd=settings.BASE_DIR, capture_output=True, text=True)
    if result.returncode == 0:
        data = str(result.stdout).strip()
    else:
        error = f"'Execution failed with code', {result.returncode}"
        print(result.stderr)
        print("error: " + error)
        data = None
    return data


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_list(request):
    if request.method == 'POST':
        try:
            date_values = []
            user_id = get_member_id(request)
            device_serial_no = request.data.get('device_serial_no', None)
            start_date = request.data.get('start_date', None)
            end_date = request.data.get('end_date', None)
            environment = request.data.get('environment', None)

            if start_date and not end_date:
                return Response("please provide End_date")
            if not start_date and end_date:
                return Response("please provide Start_date")
            if start_date and end_date and device_serial_no:
                date_range(request, start_date, end_date, user_id, device_serial_no, date_values, environment)
            elif start_date and end_date:
                session = session_fn(user_id)
                if session:
                    device_serial_no = session.device_id.device_serial_no
                    date_range(request, start_date, end_date, user_id, device_serial_no, date_values, environment)
            else:
                session = session_fn(user_id)
                if session:
                    device_serial_no = session.device_id.device_serial_no
                    end_date = session.created_at.date().isoformat()
                    start_date = (session.created_at - timedelta(days=7)).date().isoformat()
                    date_range(request, start_date, end_date, user_id, device_serial_no, date_values, environment)

            return Response(date_values, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


def session_fn(user_id):
    session = Session.objects.filter(user_id=user_id, sessiondata__isnull=False).order_by(
        '-created_at').first()
    return session


def date_range(request, start_date, end_date, user_id, device_serial_no, date_values, environment=None):
    from_date_time_obj = timezone.datetime.strptime(start_date, "%Y-%m-%d")
    end_date_time_obj = timezone.datetime.strptime(end_date, "%Y-%m-%d")
    date_range = end_date_time_obj - from_date_time_obj
    dates = list()
    for days in range(0, date_range.days + 1):
        dates.append((from_date_time_obj + datetime.timedelta(days)).strftime('%Y-%m-%d'))
    for date in dates:
        from_date = timezone.datetime.strptime(date, "%Y-%m-%d")
        to_date = from_date + timedelta(hours=23, minutes=59)
        sessions = Session.objects.filter(user_id=user_id, device_id__device_serial_no=device_serial_no,
                                          created_at__range=(from_date, to_date))
        if environment:
            sessions = sessions.filter(environment=environment)

        time_zone = get_local_time_zone(request)
        session_data_retrieve(sessions, date_values, time_zone)
    return date_values


def session_data_retrieve(sessions, date_values, time_zone):
    data = None
    for session in sessions:
        sub_values = {}
        qs = SessionData.objects.filter(session_id=session)
        data = qs.values_list('highest_energy_level', flat=True)
        if data:
            sub_values['session'] = session.pk
            date_time = qs.order_by('-highest_energy_level').first().created_at
            # sub_values['timestamp'] = str(qs.order_by('-highest_energy_level').first().created_at)
            sub_values['timestamp'] = convert_to_local_time(date_time, time_zone)
            sub_values['session_environment'] = session.environment
            sub_values['maximum_value'] = max(data)
            date_values.append(sub_values)
    return date_values


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def get_session_detail_history_for_graph(request):
    if request.method == 'POST':
        try:
            date_values = []
            user_id = get_member_id(request)
            device_serial_no = request.data.get('device_serial_no', None)
            start_date = request.data.get('start_date', None)
            end_date = request.data.get('end_date', None)
            environment = request.data.get('environment', None)

            if start_date and not end_date:
                return Response("please provide End_date")
            if not start_date and end_date:
                return Response("please provide Start_date")
            if start_date and end_date and device_serial_no:
                date_range_graph(request, start_date, end_date, user_id, device_serial_no, date_values, environment)
            elif start_date and end_date:
                session = session_fn(user_id)
                if session:
                    device_serial_no = session.device_id.device_serial_no
                    date_range_graph(request, start_date, end_date, user_id, device_serial_no, date_values, environment)
            else:
                session = session_fn(user_id)
                if session:
                    device_serial_no = session.device_id.device_serial_no
                    end_date = session.created_at.date().isoformat()
                    start_date = (session.created_at - timedelta(days=7)).date().isoformat()
                    date_range_graph(request, start_date, end_date, user_id, device_serial_no, date_values, environment)

            return Response(date_values, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Error Occurred': str(e)}, status=status.HTTP_400_BAD_REQUEST)


def date_range_graph(request, start_date, end_date, user_id, device_serial_no, date_values, environment):
    from_date_time_obj = timezone.datetime.strptime(start_date, "%Y-%m-%d")
    end_date_time_obj = timezone.datetime.strptime(end_date, "%Y-%m-%d")
    date_range = end_date_time_obj - from_date_time_obj
    dates = list()
    for days in range(0, date_range.days + 1):
        dates.append((from_date_time_obj + datetime.timedelta(days)).strftime('%Y-%m-%d'))
    for date in dates:
        from_date = timezone.datetime.strptime(date, "%Y-%m-%d")
        to_date = from_date + timedelta(hours=23, minutes=59)
        sessions = Session.objects.filter(user_id=user_id, device_id__device_serial_no=device_serial_no,
                                          created_at__range=(from_date, to_date))
        if environment:
            sessions = sessions.filter(environment=environment)

        time_zone = get_local_time_zone(request)
        for session in sessions:
            sub_values = {}
            qs = SessionData.objects.filter(session_id=session)
            data = qs.values_list('highest_energy_level', flat=True)
            if data:
                date_time = qs.order_by('-highest_energy_level').first().created_at
                sub_values['created_at'] = convert_to_local_time(date_time, time_zone)
                sub_values['highest_energy_level'] = max(data)
                date_values.append(sub_values)

    return date_values
