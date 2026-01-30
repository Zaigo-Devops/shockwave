import json

from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime
import logging

from SHOCK_WAVE import settings



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
    
    def verify_subscription(self, subscription_id, purchase_token):
        """Verify subscription purchase"""
        try:
            result = self.service.purchases().subscriptions().get(
                packageName=self.package_name,
                subscriptionId=subscription_id,
                token=purchase_token
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
            # Create or update subscription record in InAppPurchase
            try:
                print(type(user_id),token,product_id,"========================")

                purchase = InAppPurchase.objects.get(
                    user_id=user_id,
                    purchase_token=token
                )
                
            except InAppPurchase.DoesNotExist:
                # If purchase doesn't exist, create it (shouldn't happen in normal flow)
                purchase = InAppPurchase.objects.create(
                    product_id=product_id,
                    purchase_token=token,
                    purchase_time=datetime.fromtimestamp(int(data.get('startTimeMillis', 0)) / 1000),
                    purchase_type='subscribed',
                    status='completed',
                    verified=True
                )
                print("Created new purchase record for subscription:", purchase)
            # Update with subscription details
            purchase.is_subscribed = True
            purchase.subscription_id = product_id  # Store the subscription product ID
            purchase.expiry_time = datetime.fromtimestamp(int(data.get('expiryTimeMillis', 0)) / 1000)
            purchase.auto_renewing = data.get('autoRenewing', False)
            purchase.status = 'completed' if data.get('paymentState', 0) == 1 else 'pending'
            purchase.save()
            print("Updated purchase record:", purchase)
            return {
                'success': True,
                'subscription': purchase,
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': 'Failed to process subscription',
                'details': str(e)
            }