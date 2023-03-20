import random
from django.utils import timezone


def generate_otp():
    """Generate a random OTP of 6 digits."""
    return random.randint(100000, 999999)


def get_expire_time():
    return timezone.now() + timezone.timedelta(minutes=15)


