from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import (
    PurchaseVerificationSerializer,
    PurchaseSerializer,
)
from .service import PurchaseProcessor
from .models import InAppPurchase
from django.db import transaction


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
            # Step 2: Purchase verified successfully, now activate subscription
            subscription_result = processor.process_subscription(
                token=serializer.validated_data['token'],
                platform=serializer.validated_data['platform'],
                product_id=serializer.validated_data['product_id'],
                user_id=serializer.validated_data.get('user_id')
            )

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

            if status_value == 'completed':
                response_data['message'] = 'Subscription verified and activated successfully'
                return Response(response_data, status=status.HTTP_201_CREATED)
            
            elif status_value == 'trial':
                # Free trial active
                response_data['message'] = 'Free trial activated successfully'
                return Response(response_data, status=status.HTTP_201_CREATED)
            
            elif status_value == 'pending':
                response_data['message'] = 'Subscription created but payment is pending'
                return Response(response_data, status=status.HTTP_202_ACCEPTED)
            else:
                response_data['message'] = 'Subscription created but status is unknown'
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        return Response({
            'success': False,
            'error': 'Internal server error',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
