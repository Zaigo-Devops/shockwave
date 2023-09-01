import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
import stripe
from SHOCK_WAVE.settings import STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SIGNING_SECRET
from django.views.decorators.csrf import csrf_exempt

from sw_admin_app.models import Subscription, SubscriptionPeriod
from sw_api_app.utils import ACTIVE, INACTIVE, unix_timestamp_format
from rest_framework import status
stripe.api_key = STRIPE_SECRET_KEY


@api_view(['POST'])
@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META['HTTP_STRIPE_SIGNATURE']
    endpoint_secret = STRIPE_WEBHOOK_SIGNING_SECRET
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except Exception as e:
        # Invalid payload
        print("except value msg", str(e))
        return Response({'error message': str(e),"endpoint_secret":endpoint_secret,"sig_header": sig_header,"payload":payload}, status=status.HTTP_400_BAD_REQUEST)

    if event.type == 'payment_intent.succeeded':
        payment_intent = event.data.object  # contains a stripe.PaymentIntent
        print('PaymentIntent was successful!')

    if event.type == 'invoice.paid':
        payment_intent = event.data.object
        stripe_Subscription_id = payment_intent.subscription
        stripe_customer_id = payment_intent.customer
        try:
            start_date = unix_timestamp_format(payment_intent.lines.data[0].period.start)
            end_date = unix_timestamp_format(payment_intent.lines.data[0].period.end)
        except:
            start_date = datetime.date.today()
            end_date = start_date + datetime.timedelta(days=30)

        subscription = Subscription.objects.filter(stripe_subscription_id=stripe_Subscription_id,
                                                   stripe_customer_id=stripe_customer_id).first()
        if subscription:
            """After payment successful, Change the subscribed status and app subscribed is active"""
            subscription.status = ACTIVE
            subscription.app_subscribed = True
            subscription.start_date = start_date
            subscription.end_date = end_date
            subscription.save()
            SubscriptionPeriod.objects.create(subscription_id=subscription,
                                              stripe_subscription_id=stripe_Subscription_id,
                                              stripe_customer_id=stripe_customer_id, start_date=start_date,
                                              end_date=end_date)
            
    if event.type == 'invoice.payment_failed':
        """payment Failed, Change the subscribed status and app subscribed is In-active"""
        payment_intent = event.data.object
        stripe_subscription_id = payment_intent.subscription
        stripe_customer_id = payment_intent.customer
        
        subscription = Subscription.objects.filter(stripe_subscription_id=stripe_subscription_id,
                                                stripe_customer_id=stripe_customer_id).first()
        if subscription:
            subscription.status = INACTIVE
            subscription.app_subscribed = False
            subscription.save()
    else:
        print('Unhandled event type {}'.format(event.type))
    return Response(event,status=status.HTTP_200_OK)


def create_payment_customer(name, email, payment_method=None, phone=None):
    customer = stripe.Customer.create(
        name=name,
        email=email,
        phone=phone,
        payment_method=payment_method
    )
    return customer


def retrieve_payment_customer(customer_id):
    return stripe.Customer.retrieve(customer_id)


def create_payment_method(card_type, card_number, card_exp_month, card_exp_year, card_cvc, name, email, address):
    payment_method = stripe.PaymentMethod.create(
        type=card_type,
        card={
            "number": card_number,
            "exp_month": card_exp_month,
            "exp_year": card_exp_year,
            "cvc": card_cvc
        },
        billing_details={
            "name": name,
            "email": email,
            "address": address
        }
    )
    return payment_method


def create_address(line1, line2, city, state, postal_code, country):
    address = {
        "line1": line1,
        "line2": line2,
        "city": city,
        "state": state,
        "postal_code": postal_code,
        "country": country
    }
    return address


def attach_payment_method(customer_id, payment_method_id):
    attach_payment = stripe.PaymentMethod.attach(
        payment_method_id,
        customer=customer_id,
    )
    return attach_payment


def create_product(product_name, description):
    product = stripe.Product.create(name=product_name, description=description)
    return product


def create_price(amount, currency, interval, interval_count, product_id):
    price = stripe.Price.create(
        unit_amount=amount,
        currency=currency,
        recurring={"interval": interval,
                   "interval_count": interval_count},
        product=product_id,
    )
    return price


def create_subscription(customer_id, default_payment_method, price_id):
# def create_subscription(customer_id, price_id):
    subscription = stripe.Subscription.create(
        customer=customer_id,
        items=[
            {
                "price": price_id,
            },
        ],
        # payment_behavior="allow_incomplete",
        collection_method="charge_automatically",
        default_payment_method=default_payment_method,
        # expand=["latest_invoice.payment_intent"],
    )
    return subscription


def delete_subscription(subscription_id):
    delete = stripe.Subscription.delete(subscription_id)
    return delete


def delete_stripe_payment_method(stripe_payment_id):
    delete = stripe.PaymentMethod.detach(stripe_payment_id)
    return delete
