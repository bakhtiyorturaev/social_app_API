from rest_framework import serializers

from shared.utils import check_email_phone
from .models import User, VIA_EMAIL, VIA_PHONE


class UserSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=20, unique=True, required=False)
    phone = serializers.CharField(max_length=20, unique=True, required=False)

    def __init__(self, *args, **kwargs):
        super(UserSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'].required = serializers.CharField(max_length=500)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'auth_type', 'status_type', 'user_role']

    def validators(self):
        return [
            self.auth_validate,
        ]

    def auth_validate(self, data):
        user_input = self.data.get('email_phone_number')
        input_type = check_email_phone(user_input)
        if not user_input:
            raise serializers.ValidationError({'email_phone_number': ['This field is required.']})
        elif input_type == VIA_EMAIL:
            pass
            #send_email_code
        elif input_type == VIA_PHONE:
            pass
            #send_sms_code
        return data

