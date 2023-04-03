from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from sw_admin_app.models import *


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'


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
        insurance_provider = validated_data.get('user_profile').get('insurance_provider')
        user_profile = UserProfileSerializer(data={"user_id": user.pk, "insurance_provider": insurance_provider},
                                             many=False,
                                             read_only=False)
        if user_profile.is_valid():
            user_profile.save()
        return user


class BillingAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillingAddress
        fields = "__all__"
