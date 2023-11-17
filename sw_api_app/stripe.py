import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
import stripe
from SHOCK_WAVE.settings import STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SIGNING_SECRET
from django.views.decorators.csrf import csrf_exempt

from sw_admin_app.models import Subscription, SubscriptionPeriod, PaymentMethod
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
    resp = {}
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        resp["event"] = event
    except Exception as e:
        # Invalid payload
        return Response(
            {'error message': str(e), "endpoint_secret": endpoint_secret, "sig_header": sig_header, "payload": payload},
            status=status.HTTP_400_BAD_REQUEST)
    context = {}
    # if event.type ==
    if event.type == 'payment_intent.succeeded':
        payment_intent = event.data.object  # contains a stripe.PaymentIntent
        context['data'] = payment_intent
        payment_intent_id = payment_intent.id
        context['payment_intent_id'] = payment_intent_id
        card_last4_no = None
        customer_id = None
        payment_method_id = None
        subscription = None
        try:
            subscription = Subscription.objects.filter(stripe_intent_id=payment_intent_id).order_by(
                '-created_at').first()
        except Exception as e:
            resp["pi_succeeded_subscription_ex"] = str(e)
        if subscription:
            try:
                customer_id = subscription.stripe_customer_id
                context['customer_id'] = customer_id
            except Exception as e:
                context['customer_id'] = customer_id
                resp["subscription_exception"] = str(e)
            try:
                try:
                    payment_intent, payment_method_id = retrieve_payment_method_id(payment_intent_id)
                    context['payment_method_id'] = payment_method_id

                    # try:
                    #     payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
                    #     if payment_method.customer is None:
                    #         payment_method.attach(customer=customer_id)
                    #     else:
                    #         print("PaymentMethod is already attached to a customer")
                    #     # attach_payment_method(customer_id, payment_method_id)
                    #     context['payment_method_id'] = payment_method_id
                    # except Exception as e:
                    #     context["payment_intent_error_except"] = str(e)
                    #     return Response({'payment_method attach error': str(e), "context": context})
                except Exception as e:
                    context['payment_method_id'] = payment_method_id
                    return Response({'payment_intent,payment_method_id error': str(e),"context":context})

                    # print(str(e))
                try:
                    stripe_subscription = create_subscription_post_payment_intent(customer_id, payment_method_id,
                                                                                  subscription.stripe_price_id)
                    payment_intent_status = stripe.PaymentIntent.retrieve(stripe_subscription.latest_invoice.payment_intent)
                    print("payment_intent status", payment_intent.status)
                except Exception as e:
                    # print(str(e))
                    return Response({'stripe_subscription_error': str(e)})
                try:
                    payment_method = retrieve_payment_method(payment_method_id)
                except Exception as e:
                    return Response({'stripe_payment_method_error': str(e)})
                try:
                    card_last4_no = payment_method["card"]["last4"]
                    user_id = subscription.user_id
                    context['card_last4_no'] = card_last4_no
                    context['user_id'] = user_id
                except Exception as e:
                    context['card_last4_no'] = card_last4_no
                    context['user_id'] = user_id
                    return Response({'card,userid error': str(e),"context":context})
                if not PaymentMethod.objects.filter(payment_id=payment_method_id).first():
                    PaymentMethod.objects.create(payment_id=payment_method_id, card_last4_no=card_last4_no,
                                                 user_id=user_id)
                try:
                    start_date = unix_timestamp_format(stripe_subscription.current_period_start)
                    end_date = unix_timestamp_format(stripe_subscription.current_period_end)
                except Exception as e:
                    start_date = datetime.date.today()
                    end_date = start_date + datetime.timedelta(days=30)
                subscription.status = ACTIVE
                subscription.stripe_subscription_id = stripe_subscription['id']
                subscription.stripe_payment_id = payment_method_id
                subscription.payment_id = None
                subscription.app_subscribed = True
                subscription.start_date = start_date
                subscription.end_date = end_date
                subscription.save()
                sub_per = SubscriptionPeriod.objects.create(subscription_id=subscription,
                                                            stripe_subscription_id=stripe_subscription.id,
                                                            stripe_customer_id=customer_id, start_date=start_date,
                                                            end_date=end_date)
                # create_subscription_post_payment_intent(customer_id, payment_intent_id, subscription.stripe_price_id)
            except Exception as e:
                return Response({'error': str(e),"context":context})

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
        print("subscription", subscription)

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

    if event.type == 'invoice.payment_action_required':
        print("invoice payment action required event", event)

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
    return Response(resp, status=status.HTTP_200_OK)


def create_payment_customer(name, email, payment_method=None, phone=None):
    customer = stripe.Customer.create(
        name=name,
        email=email,
        phone=phone,
        payment_method=payment_method
    )
    return customer


def stripe_ephemeral_key(customer_id):
    try:
        # Create an ephemeral key associated with the customer
        ephemeral_key = stripe.EphemeralKey.create(
            customer=customer_id,
            stripe_version="2023-08-16",  # Replace with the desired API version
        )
        key = ephemeral_key.secret
        return key
    except Exception as e:
        print("Stripe Ephemeral key error exception", str(e))


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


def create_subscription_post_payment_intent(customer_id, payment_method_id, price_id):
    # def create_subscription(customer_id, price_id):
    subscription = stripe.Subscription.create(
        customer=customer_id,
        items=[
            {
                "price": price_id,
            },
        ],
        # payment_behavior='default_incomplete',
        # collection_method="send_invoice",
        default_payment_method=payment_method_id,
        expand=["latest_invoice.payment_intent"]
        # customer_action='use_payment_method',
        # payment_settings={
        #     "payment_method_options": {
        #         "payment_intent": payment_intent_id
        #     }
        # }
    )
    return subscription


def retrieve_payment_method_id(payment_intent_id):
    payment_intent = stripe.PaymentIntent.retrieve(
        payment_intent_id,
    )
    payment_method_id = payment_intent["payment_method"]
    return payment_intent, payment_method_id


def retrieve_payment_method(payment_method_id):
    payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
    return payment_method
