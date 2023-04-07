from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from sw_admin_app.models import UserProfile, BillingAddress, Device
from .stripe import create_payment_customer
from sw_api_app.utils import get_attachment_from_name


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'


class UserDetailSerializer(serializers.ModelSerializer):
    insurance_provider = serializers.CharField(source="user_profile.insurance_provider", read_only=True)
    user_profile_image = serializers.ImageField(source="user_profile.user_profile_image", read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'insurance_provider', 'user_profile_image',)


# Serializer to Register User
class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    insurance_provider = serializers.CharField(source="user_profile.insurance_provider", allow_blank=True,
                                               allow_null=True, required=False, default=None, max_length=256)

    class Meta:
        model = User
        fields = ('email', 'password', 'password2',
                  'first_name', 'last_name', 'insurance_provider',)
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            username=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        # Will get the insurance provider from the user_profile dictionary as in serializer fields it is declared that
        # it is a related field source="user_profile.insurance_provider" hence it needs to be retrieved as mentioned
        # below.
        user_name = f'{user.first_name} {user.last_name}'
        name = user.first_name
        if len(user.last_name) > 0:
            name = user.first_name + ' ' + user.last_name
        stripe_customer_create = create_payment_customer(name=name, email=user.email)
        insurance_provider = validated_data.get('user_profile').get('insurance_provider')
        user_profile = UserProfileSerializer(data={"user_id": user.pk, "insurance_provider": insurance_provider,
                                                   "user_profile_image": get_attachment_from_name(user_name),
                                                   "stripe_customer_id": stripe_customer_create['id']},
                                             many=False,
                                             read_only=False)
        if user_profile.is_valid():
            user_profile.save()
        return user


class BillingAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillingAddress
        fields = "__all__"


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = "__all__"
