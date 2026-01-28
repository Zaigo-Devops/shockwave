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
            # Step 1: Process and verify the purchase
            purchase_result = processor.process_product_purchase(
                purchase_token=serializer.validated_data['token'],
                platform=serializer.validated_data['platform'],
                product_id=serializer.validated_data['product_id'],
                user_id=serializer.validated_data.get('user_id')
            )
            print("Purchase processing result:", purchase_result)
            
            if not purchase_result['success']:
                return Response({
                    'success': False,
                    'error': purchase_result['error'],
                    'details': purchase_result.get('details')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Step 2: Purchase verified successfully, now activate subscription
            subscription_result = processor.process_subscription(
                user=request.user,
                subscription_id=serializer.validated_data['product_id'],
                purchase_token=serializer.validated_data['token']
            )
            print("Subscription processing result:", subscription_result)
            if not subscription_result['success']:
                # Purchase was created but subscription failed
                return Response({
                    'success': False,
                    'error': 'Purchase verified but subscription activation failed',
                    'purchase_created': True,
                    'details': subscription_result.get('details')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Step 3: Both purchase and subscription successful
            purchase_serializer = PurchaseSerializer(subscription_result['subscription'])
            print("Final purchase and subscription data:", purchase_serializer.data)
            return Response({
                'success': True,
                'message': 'Purchase verified and subscription activated successfully',
                'purchase': purchase_serializer.data,
                'is_subscribed': subscription_result['subscription'].is_subscribed,
                'subscription': purchase_serializer.data,
                'created': subscription_result['created']
            }, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        return Response({
            'success': False,
            'error': 'Internal server error',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
