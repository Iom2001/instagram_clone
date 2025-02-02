from django.contrib import admin
from django.urls import path, include
from .serializers import SignUpSerializer
from .models import User
from .views import CreateUserView, VerifyAPIView, GetNewVerification, ChangeUserInformationView

urlpatterns = [
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyAPIView.as_view()),
    path('new-verify/', GetNewVerification.as_view()),
    path('change-user/', ChangeUserInformationView.as_view()),
]
