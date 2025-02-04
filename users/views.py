from datetime import timezone
from tokenize import TokenError

from aiohttp.helpers import TOKEN
from django.core.serializers import serialize
from django.shortcuts import render
from django.views.generic import CreateView
from rest_framework import permissions, status
from datetime import datetime
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from shared.utility import send_email
from users.models import User, DONE, CODE_VERIFIED, VIA_EMAIL, VIA_PHONE
from users.serializers import SignUpSerializer, ChangeUserInformationSerializer, ChangeUserPhotoSerializer, \
    LoginSerializer, LoginRefreshSerializer, LogoutSerializer


# Create your views here.

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = SignUpSerializer

class VerifyAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = request.data.get('code')


        self.check_verify(user, code)
        return Response(
            data = {
                'success': True,
                "auth_status": user.auth_status,
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token'],
            }
        )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gt=datetime.now(), code = code, is_confirmed=False)
        if not verifies.exists():
            data = {
                'message': 'Tasdiqlash kodingiz xato yoki eskirgan',
            }
            raise ValidationError(data)
        verifies.update(is_confirmed = True)
        if user.auth_status not in DONE:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerification(APIView):

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        else:
            data = {
                "message": "email yoki telefon raqami xato"
            }
            raise ValidationError(data)
        return Response(
            data={
                'success': True,
                "message": "Tasdiqlash kodingiz qaytadan jo'natildi",
            }
        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gt=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "Kodingiz hali ishlatish uchun yaroqli. Biroz kutib turing"
            }

class ChangeUserInformationView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangeUserInformationSerializer
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User was updated",
            "auth_status": self.request.user.auth_status,
        }
        return Response(
            data=data,
            status=status.HTTP_200_OK
        )

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User was updated",
            "auth_status": self.request.user.auth_status,
        }
        return Response(
            data=data,
            status=status.HTTP_200_OK
        )

class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response(
                {
                    'message': "Rasm muvaffaqiyatli o'zgartirildi"
                }, status=status.HTTP_200_OK
            )
        return Response(
            serializer.errors, 400
        )

class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

class  LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': "You are logged out",
            }
            return Response(data=data, status=status.HTTP_200_OK)
        except TokenError:
            return Response(status=400)