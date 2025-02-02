from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

from shared.utility import check_email_or_phone, send_email, send_phone_code
# from shared.utility import check_email_or_phone, send_email, send_phone_code, check_user_type
from .models import User, UserConfirmation, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_STEP
from rest_framework import exceptions
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ('id',
                  'auth_type',
                  'auth_status'
                  )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        print(data)
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)
        if input_type == "email":
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL,
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE,
            }
        else:
            data = {
                "success": False,
                "message": "Invalid input",
            }
        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Email already registered",
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Phone number already registered",
            }
            raise ValidationError(data)
        return value

    def to_representation(self, instance):
        print("to_rep", instance)
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserInformationSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    "message": "Passwords must match",
                }
            )
        if password:
            validate_password(password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters",
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric",
                }
            )
        return username

    def validate_firstname(self, firstname):
        if len(firstname) < 5 or len(firstname) > 30:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters",
                }
            )
        if firstname.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric",
                }
            )
        return firstname

    def validate_lastname(self, lastname):
        if len(lastname) < 5 or len(lastname) > 30:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters",
                }
            )
        if lastname.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric",
                }
            )
        return lastname

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password = validated_data.get('password', instance.password)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance