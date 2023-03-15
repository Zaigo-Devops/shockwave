from django.contrib.auth.models import User
from rest_framework import serializers, status
from rest_framework_simplejwt.tokens import RefreshToken


class UserSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'first_name', 'last_name', 'tokens']
        extra_kwargs = {'password': {'write_only': True}}

    def get_tokens(self, obj):
        tokens = RefreshToken.for_user(obj)
        return {
            'access': str(tokens.access_token),
            'refresh': str(tokens),
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['email'],
            validated_data['password'],
            validated_data['first_name'],
            validated_data['last_name'],
        )
        return user

    # def post(self, request):
    #     req_data = request.data
    #     email_id = req_data.get('email')
    #     password = req_data.get('password')
    #     first_name = req_data.get('first_name')
    #     last_name = req_data.get('last_name')
    #     obj = User.objects.filter(email=email_id).count()
    #     print('obj', obj)
    #     if obj == 0:
    #         user = User.objects.create(email=email_id, password=password, first_name=first_name, last_name=last_name)
    #         return user
    #     else:
    #         print('invalid')