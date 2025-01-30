from django.contrib import admin
from django.urls import path, include
from .serializers import SignUpSerializer
from .models import User
from .views import CreateUserView

urlpatterns = [
    path('signup/', CreateUserView.as_view()),
]