from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import stripe
from django.conf import settings
from SHOCK_WAVE.settings import STRIPE_SECRET_KEY

stripe.api_key = STRIPE_SECRET_KEY


@api_view(['POST'])
def create_customer(request):
    if request.method == 'POST':

        # customer = create_payment_customer('abd', "add@gmail.com")
        # address = create_address("123 Main St", "Apartment 5", "San Francisco", "CA", "94111", "US")
        # payment_method = create_payment_method("card", "4242424242424242", 12, 2024, "314", 'abd', "add@gmail.com", address)
        # attach_payment = attach_payment_method(customer.id, payment_method.id)
        # product = create_product("Shock Wave", "Shock Wave description")
        # price = create_price(1000,"usd","month",product.id)
        # subscription = create_subscription(customer.id,price.id) 
        
        delete_subscription("sub_1Mlus5SJEQdByQx0cVj9uBcy")
        
        return Response({'message': 'Customer created successfully', })



def create_payment_customer(name, email, phone=None):
    customer = stripe.Customer.create(
        name=name,
        email=email,
        phone=phone
    )
    return customer


def retrive_payment_customer(customer_id):
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

def create_product(product_name,description):
    product  = stripe.Product.create(name=product_name, description=description)
    return product

def create_price(amount, currency,intervell,product_id):
    price = stripe.Price.create(
        unit_amount=amount,
        currency=currency,
        recurring={"interval": intervell},
        product=product_id,
    )
    return price


def create_subscription(customer_id, price_id):  
    subscription = stripe.Subscription.create(
    customer=customer_id,
    items=[
        {
            "price": price_id,
        },
    ],
    payment_behavior="default_incomplete",
    # expand=["latest_invoice.payment_intent"],
    )
    return subscription


def delete_subscription(subscription_id):
    delete = stripe.Subscription.delete(subscription_id)
    return delete