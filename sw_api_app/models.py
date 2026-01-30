# Create your models here.
from django.db import models
import uuid
from django.contrib.auth.models import User

class InAppPurchase(models.Model):
    PURCHASE_TYPES = [
        ('subscribed', 'subscribed'),
        ('pending', 'Pending'),
    ]
    
    PURCHASE_STATUS = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
        ('expired', 'Expired'),
    ]
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, default=None, null=True, blank=True)
    purchase_type = models.CharField(max_length=20, choices=PURCHASE_TYPES,default='pending')
    product_id = models.CharField(max_length=255,blank=True, null=True,default=None)# subscription or product identifier
    purchase_token = models.TextField(max_length=255,blank=True, null=True,default=None)
    # Purchase details
    purchase_time = models.DateTimeField()
    purchase_price = models.FloatField(default=0, null=True)
    purchase_currency = models.CharField(max_length=3, default='USD')
    # Status
    status = models.CharField(max_length=20, choices=PURCHASE_STATUS, default='pending')
    verified = models.BooleanField(default=False)
    
    # Subscription specific
    expiry_time = models.DateTimeField(null=True, blank=True,default=None)
    auto_renewing = models.BooleanField(default=False)
    subscription_id = models.CharField(max_length=255, blank=True, null=True, default=None)
    is_subscribed = models.BooleanField(default=False)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['product_id']),
        ]
    
    def __str__(self):
        return f"{self.product_id}"

