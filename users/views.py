from django.shortcuts import render
from rest_framework.generics import CreateAPIView
from rest_framework import permissions

from users.models import User
from users.serializers import SignUpSerializer


# Create your views here.


class UserCreateView(CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = SignUpSerializer
    queryset = User.objects.all()
