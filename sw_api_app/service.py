import json

from django.http import HttpResponse
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime, timedelta, timezone
import logging
from django.contrib.auth.models import User
from SHOCK_WAVE import settings
from sw_admin_app.models import Subscription
from sw_api_app.models import InAppPurchase



class GooglePlayService:
    SCOPES = ['https://www.googleapis.com/auth/androidpublisher']
    
    def __init__(self):
        self.package_name = settings.GOOGLE_PACKAGE_NAME
        self.service = self._get_service()
    
    def _get_service(self):
        """Initialize Google Play Developer API service"""
        try:
            credentials = service_account.Credentials.from_service_account_info(
                json.loads(settings.service_account_info),
                scopes=self.SCOPES
            )
            service = build('androidpublisher', 'v3', credentials=credentials)
            return service  # Return service object, not Response
        except Exception as e:
            print(f"Error initializing Google Play service: {e}")
    
    def verify_purchase(self, product_id, token):
        """Verify in-app product purchase"""
        try:
            result = self.service.purchases().products().get(
                packageName=self.package_name,
                productId=product_id,
                token=token
            ).execute()
            # Return dictionary, not Response
            return {
                'valid': True,
                'data': result
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def verify_subscription(self, subscription_id, token):
        """Verify subscription purchase"""
        try:
            result = self.service.purchases().subscriptions().get(
                packageName=self.package_name,
                subscriptionId=subscription_id,
                token=token
            ).execute()
            
            return {
                'valid': True,
                'data': result
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def acknowledge_purchase(self, product_id, purchase_token):
        """Acknowledge in-app product purchase"""
        try:
            self.service.purchases().products().acknowledge(
                packageName=self.package_name,
                productId=product_id,
                token=purchase_token
            ).execute()
            return True
        except Exception as e:
            return False
    
    def acknowledge_subscription(self, product_id, purchase_token):
        """Acknowledge subscription (REQUIRED within 3 days!)"""
        try:
            self.service.purchases().subscriptions().acknowledge(
                packageName=self.package_name,
                subscriptionId=product_id,
                token=purchase_token
            ).execute()
            return True
        except Exception as e:
            return False

    def cancel_subscription(self, subscription_id, token):
        """
        Cancel subscription - stops auto-renewal
        User keeps access until current period ends
        """
        try:
            self.service.purchases().subscriptions().cancel(
                packageName=self.package_name,
                subscriptionId=subscription_id,
                token=token
            ).execute()
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        

class PurchaseProcessor:
    """Process and validate purchases"""
    
    def __init__(self):
        self.play_service = GooglePlayService()
    
    def process_product_purchase(self, token, platform, product_id, user_id=None):
        """Process in-app product purchase"""
        from .models import InAppPurchase
        
        try:
            # Verify with Google
            verification = self.play_service.verify_purchase(product_id, token)
            if not verification['valid']:
                return {
                    'success': False,
                    'error': 'Purchase verification failed',
                    'details': verification.get('error')
                }
            data = verification['data']
            
            # Check if already processed
            if InAppPurchase.objects.filter(purchase_token=token).exists():
                return {
                    'success': False,
                    'error': 'Purchase already processed'
                }
            
            # Create purchase record
            purchase = InAppPurchase.objects.create(
                user_id=user_id,
                product_id=product_id,
                purchase_token=token,
                purchase_time=datetime.fromtimestamp(int(data.get('purchaseTimeMillis', 0)) / 1000),
                purchase_type='subscribed',
                status='completed',
                verified=True,
                is_subscribed=False # Will be updated upon subscription activation
            )
        
            return {
                'success': True,
                'purchase': purchase
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': 'Failed to process purchase',
                'details': str(e)
            }
    
    def process_subscription(self, token, platform, product_id, user_id=None):
        """Process subscription purchase"""
        from .models import InAppPurchase
        
        try:
            # Verify with Google
            # Note: We pass product_id, but Google API calls it 'subscriptionId'
            verification = self.play_service.verify_subscription(product_id, token)

            if not verification['valid']:
                return {
                    'success': False,
                    'error': 'Subscription verification failed',
                    'details': verification.get('error')
                }
            data = verification['data']

            print(f"Google verification data: {data}")  # Debug log to inspect the data structure
            payment_state = data.get('paymentState', 0)
            auto_renewing = data.get('autoRenewing', False)
            price_mode = data.get('priceCurrencyCode', 'USD')
            price =  data.get('priceAmountMicros', 0) # Convert micros to standard currency unit
            order_id = data.get('orderId', None)
            # Create or update subscription record in InAppPurchase

            if payment_state == 0:
                # Payment pending - don't activate yet!
                status = 'pending'
                is_subscribed = False
            
            elif payment_state == 1:
                # Payment received - activate subscription!
                status = 'completed'
                is_subscribed = True
            
            else:
                # Free trial - activate subscription
                status = 'pending'
                is_subscribed = False

            try:
                purchase = InAppPurchase.objects.get(
                    user_id=user_id,
                    purchase_token=token
                )
                
            except InAppPurchase.DoesNotExist:
                # If purchase doesn't exist, create it (shouldn't happen in normal flow)
                user_id = User.objects.get(id=user_id)
                purchase = InAppPurchase.objects.create(
                    user_id = user_id,
                    product_id=product_id,
                    purchase_token=token,
                    purchase_time=datetime.fromtimestamp(int(data.get('startTimeMillis', 0)) / 1000),
                    purchase_price = price,
                    purchase_currency = price_mode,
                    purchase_type='subscribed',
                    status=status,
                    verified=True
                )
            # Update with subscription details
            purchase.is_subscribed = is_subscribed
            purchase.subscription_id = product_id  # Store the subscription product ID
            purchase.order_id = order_id
            purchase.expiry_time = datetime.fromtimestamp(int(data.get('expiryTimeMillis', 0)) / 1000)
            purchase.auto_renewing = auto_renewing
            purchase.status = status
            purchase.save()
            
            if data.get('acknowledgementState', 0) == 0 and payment_state == 1:
                self.play_service.acknowledge_subscription(product_id, token)

            
            return {
                'success': True,
                'subscription': purchase,
                'payment_state': payment_state,
                'is_active': is_subscribed,
                'status': status
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': 'Failed to process subscription',
                'details': str(e)
            }



def handle_renewal(new_token, subscription_id):
    """
    Handle subscription renewal.

    ⚠️ Google issues a NEW token on every renewal, so we:
    1. Find the existing record by subscription_id (NOT by token)
    2. Verify with NEW token to get updated expiry time
    3. Update the existing record (don't create a new one!)
    """

    print("come in hDNLE")
    print(f"Handling renewal for subscription_id: {subscription_id}, new_token: {new_token[:20]}...")  # Debug log to inspect inputs
    try:
        purchase = InAppPurchase.objects.get(
                    purchase_token=new_token,
                ) 
        print(purchase.purchase_token)

        if not purchase:
            return HttpResponse(status=400)  # No record found, nothing to update (could be a renewal before first purchase is processed)

        # Verify with NEW token to get updated data from Google
        play_service = GooglePlayService()
        verification = play_service.verify_subscription(
            subscription_id=subscription_id,
            token=new_token
        )
        print(f"Google verification for renewal: {verification}")  # Debug log to inspect verification result
        if not verification['valid']:
            return

        data = verification['data']
        print(f"Google verification data for renewal: {data}")  # Debug log to inspect the data structure
        payment_state = data.get('paymentState', 0)

        if payment_state != 1:
            return

        purchase.purchase_token = new_token 
        purchase.expiry_time = datetime.fromtimestamp(
            int(data.get('expiryTimeMillis', 0)) / 1000
        )
        purchase.auto_renewing = data.get('autoRenewing', True)
        purchase.status = 'completed'
        purchase.is_subscribed = True
        purchase.save()
        
        extend_subscription_date(purchase.user_id, duration_days=30)


    except Exception as e:
        print(f"Renewal handling failed: {str(e)}")
        return HttpResponse(status=400)


def extend_subscription_date(user, duration_days=30):
    """
    Extend subscription end_date by duration_days.

    IMPORTANT: Always extend from end_date (not from now!)
    This ensures user never loses days they already paid for.

    """
    print(f"Extending subscription for user: {user.pk} by {duration_days} days")  # Debug log to inspect inputs
    subscription = Subscription.objects.filter(user_id=user,app_subscribed=True).first()

    if not subscription:
        print(f" No active subscription found for user: {user.pk}")
        return

    now = timezone.now()

    if subscription.end_date and subscription.end_date > now:
        new_end_date = subscription.end_date + timedelta(days=duration_days)
    else:
        new_end_date = now + timedelta(days=duration_days)

    subscription.end_date = new_end_date
    subscription.status = 1
    subscription.app_subscribed = True
    subscription.save()


    return ""