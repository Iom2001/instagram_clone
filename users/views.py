from django.shortcuts import render
from django.views.generic import CreateView
from rest_framework import permissions
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated

from users.models import User
from users.serializers import SignUpSerializer


# Create your views here.

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = SignUpSerializer
