import datetime

from django.shortcuts import render
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from shared.utils import send_email
from users.models import User, NEW, CODE_VERIFIED, VIA_EMAIL, VIA_PHONE
from users.serializers import SignUpSerializer, ChangeUserInformation, ChangeUserPhotoSerializer


# Create your views here.


class UserCreateView(CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = SignUpSerializer
    queryset = User.objects.all()


class VerifyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        user = request.user
        code = request.data.get('code')

        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "auth_status": user.auth_status,
                "access": user.token()['access'],
                "refresh_token": user.token()['refresh_token']
            }
        )

    def check_verify(self, user, code):
        verifyes = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        print(verifyes)
        if not verifyes.exists():
            data = {
                "message": "Tasdiqlash kodingiz xato yoki eskirgan!"
            }
            raise ValidationError(data)
        else:
            verifyes.update(is_confirmed=True)
            if user.auth_status == NEW:
                user.auth_status = CODE_VERIFIED
                user.save()
            return True


class GetNewVerification(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        else:
            data = {
                "message": "Email yoki telefon raqami no to'g'ri!"
            }
            raise ValidationError(data)
        return Response(
            data={
                "success": True,
                "messages": "Tasdiqlash kodingiz qaytadan jo'natildi!"
            }
        )

    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "Tasdiqlash kodingiz ishlatish uchun yaroqli!"
            }
            raise ValidationError(data)


class ChangeUserInformationView(UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, )
        data = {
            "success": True,
            "message": "Ma'lumotlar o'zgartirildi!",
            "auth_status": self.request.user.auth_status
        }
        return Response(data, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, )
        data = {
            "success": True,
            "message": "Ma'lumotlar o'zgartirildi!",
            "auth_status": self.request.user.auth_status
        }
        return Response(data, status=status.HTTP_200_OK)


class ChangeUserPhotoView(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user

            serializer.update(user, serializer.validated_data)
            return Response({
                "message": "Rasm o'zgartirildi!"
            }, status=status.HTTP_200_OK)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserVerification(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        data = request.data
        try:
            validated_username = self.validate_username(data.get("username"))
        except ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        try:
            validated_first_name = self.validate_first_name(data.get("first_name"))
        except ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        try:
            validated_last_name = self.validate_last_name(data.get("last_name"))
        except ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(username=validated_username, first_name=validated_first_name,
                                   last_name=validated_last_name)
        serializer = SignUpSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
