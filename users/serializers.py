import re
from re import fullmatch

from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator

from shared.utils import send_email, check_user_type, check_email_or_phone, regex_firs_and_last_name, regex_username
from .models import User, UserConfirmation, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status'
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False}
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
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "You must send email or phone number"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data

    def validate_username(self, username):
        username = username.lower()
        if username and User.objects.filter(username=username).exists():
            data = {
                "success": False,
                "message": "Bu username allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        return re.fullmatch(regex_username, username)

    def validate_first_name(self, first_name):
        if not first_name:
            data = {
                "success": False,
                "message": "Ismingizni kiritishingiz shart"
            }
            raise ValidationError(data)
        return re.fullmatch(regex_firs_and_last_name, first_name.capitalize())

    def validate_last_name(self, last_name):
        if not last_name:
            data = {
                "success": False,
                "message": "Familiyangizni kiritishingiz shart"
            }
            raise ValidationError(data)
        return re.fullmatch(regex_firs_and_last_name, last_name.capitalize())


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    password_confirmation = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        password_confirmation = data.get('password_confirmation', None)
        if password != password_confirmation:
            raise ValidationError(
                {
                    "message": "Parolingiz va tastiqlash parolingiz  mos kelmadi!"
                }
            )
        if password:
            validate_password(password)
            validate_password(password_confirmation)
        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError({
                "message": "Username 5 tadan 30 tagacha belgidan iborat bo'lishi kerak"
            }
            )
        if username.isdigit():
            raise ValidationError({
                "message": "usernameda harflar ham bo'lishi shart"
            }
            )
        return username


class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=
                                                                      ['.jpg', 'png', 'jpeg', 'heic', 'heif']
                                                                      )])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo', None)
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        return instance
