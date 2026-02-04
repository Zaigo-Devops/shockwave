from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from sw_admin_app.models import Subscription, SubscriptionPrice
from .serializers import (
    PurchaseVerificationSerializer,
    PurchaseSerializer,
)
from .service import PurchaseProcessor
from .models import InAppPurchase
from django.db import transaction
from .utils import get_member_id, get_paginated_response, generate_user_cards, get_attachment_from_name, \
    get_recuring_periods, \
    unix_timestamp_format, INACTIVE, get_address, ACTIVE
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
import base64
import json

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_and_activate_purchase(request):
    """
    Single API to verify purchase and activate subscription in one call
    
    Flow:
    1. Verify the purchase with Google Play
    2. If successful, create purchase record
    3. Then automatically create/activate subscription
    
    Request body:
    {   
        "token": "token_from_google",
        "platform": "google_play",
        "product_id": "premium_monthly",
        "user_id": "user_identifier"  # optional
    }
    """
    print("api called")
    serializer = PurchaseVerificationSerializer(data=request.data)
    print("Received data for purchase verification:", request.data)
    if not serializer.is_valid():
        return Response(
            {'error': 'Invalid data', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    processor = PurchaseProcessor()
    print("Starting purchase processing...",processor)
    try:
        with transaction.atomic():
            print("comes in s")
            user_id = get_member_id(request)
            print("User ID from token:", user_id)

            # Step 2: Purchase verified successfully, now activate subscription
            subscription_result = processor.process_subscription(
                token=serializer.validated_data['token'],
                platform=serializer.validated_data['platform'],
                product_id=serializer.validated_data['product_id'],
                user_id=user_id
            )
    
            user = User.objects.get(pk=user_id)
            print("User fetched:", user.id)
            if not user:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            if not subscription_result['success']:
                # Purchase was created but subscription failed
                return Response({
                    'success': False,
                    'error': 'Purchase verified but subscription activation failed',
                    'purchase_created': True,
                    'details': subscription_result.get('details')
                }, status=status.HTTP_400_BAD_REQUEST)
            

            status_value = subscription_result.get('status', 'unknown')

            # Step 3: Both purchase and subscription successful
            purchase_serializer = PurchaseSerializer(subscription_result['subscription'])

            response_data = {
                'success': True,
                'data': purchase_serializer.data,
                # 'is_subscribed': subscription_result['subscription'].is_subscribed,
            }

            print("Subscription status value:", status_value)
            if status_value == 'completed':
                response_data['message'] = 'Subscription verified and activated successfully'
                app_price = SubscriptionPrice.objects.get()
                duration_days = '30'
                start_date = timezone.now()
                end_date = start_date + timedelta(days=int(duration_days))

                Subscription.objects.create(status=1,
                                            user_id=user,
                                            app_subscribed=True,
                                            start_date=start_date,
                                            end_date=end_date,
                                            subscription_price=app_price.price
                                            )
                print("Subscription created for user:", user.id)
                return Response(response_data, status=status.HTTP_200_OK)
            
            elif status_value == 'trial':
                # Free trial active
                response_data['message'] = 'Free trial activated successfully'
                return Response(response_data, status=status.HTTP_200_OK)
            
            elif status_value == 'pending':
                response_data['message'] = 'Subscription created but payment is pending'
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
            else:
                response_data['message'] = 'Subscription created but status is unknown'
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        return Response({
            'success': False,
            'error': 'Internal server error',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def google_play_webhook(request):
    """Handle Google Play notifications"""
    try:
        body = json.loads(request.body)
        message_data = body['message']['data']
        decoded = base64.b64decode(message_data).decode('utf-8')
        notification = json.loads(decoded)

        # Handle subscription notification
        if 'subscriptionNotification' in notification:
            sub_notif = notification['subscriptionNotification']
            notification_type = sub_notif['notificationType']
            purchase_token = sub_notif['purchaseToken']
            subscription_id = sub_notif['subscriptionId']
            
            # Find subscription in database
            purchase = InAppPurchase.objects.get(
                purchase_token=purchase_token,
                subscription_id=subscription_id
            )
            
            # Type 3 = SUBSCRIPTION_CANCELED
            if notification_type == 3:
                purchase.status = 'cancelled_by_user'
                purchase.is_subscribed = False
                purchase.auto_renewing = False
                purchase.save()

                subscription = Subscription.objects.filter(user_id=purchase.user_id, app_subscribed=True).first()
                if subscription:
                    subscription.status = 2  # Cancelled
                    subscription.app_subscribed = False
                    subscription.save()
            
            # Type 13 = SUBSCRIPTION_EXPIRED
            elif notification_type == 13:
                purchase.status = 'expired'
                purchase.is_subscribed = False
                purchase.save()
            
            # Type 2 = SUBSCRIPTION_RENEWED
            elif notification_type == 2:
                # Re-verify to get new expiry time
                processor = PurchaseProcessor()
                processor.process_subscription(
                    token=purchase_token,
                    platform='android',
                    product_id=subscription_id,
                    user_id=purchase.user_id
                )
        
        return HttpResponse(status=200)
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return HttpResponse(status=200)
