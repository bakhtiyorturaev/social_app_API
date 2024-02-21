import random
import uuid
import datetime
from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken

from shared.models import BaseModel

ORDINARY_USER, ADMIN, SUPER_ADMIN = ('ordinary user', 'admin', 'super admin')
VIA_EMAIL, VIA_PHONE = ('email', 'phone')
NEW, VERIFIED, DONE, IMAGE = ('new', 'verified', 'done', 'image')


class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (ADMIN, ADMIN),
        (SUPER_ADMIN, SUPER_ADMIN),
    )
    AUTH_TYPE = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )
    STATUS_TYPE = (
        (NEW, NEW),
        (VERIFIED, VERIFIED),
        (DONE, DONE),
        (IMAGE, IMAGE),
    )

    user_role = models.CharField(max_length=20, choices=USER_ROLES, default=ORDINARY_USER)
    verify_type = models.CharField(max_length=20, choices=AUTH_TYPE)
    status = models.CharField(max_length=20, choices=STATUS_TYPE, default=NEW)
    email = models.EmailField(max_length=500, blank=True, null=True)
    phone = models.CharField(max_length=500, blank=True, null=True)

    def __str__(self):
        return self.username

    def generate_code(self, verify_type):
        code = ''.join(str(random.randint(0, 100)) for _ in range(4))
        UserConfirmCode.objects.create(
            user_id=self.id,
            code=code,
            verify_type=verify_type
        )

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def check_username(self):
        if not self.username:
            temp_username = f"username-{uuid.uuid4().__str__.split('-')[-1]}"
            while User.objects.filter(username=temp_username).exists():
                temp_username = f"username-{uuid.uuid4().__str__.split('-')[0]}"
            self.username = temp_username

    def check_email(self):
        if self.email:
            normalized_email = self.email.lower()
            self.email = normalized_email

    def check_password(self, *args, **kwargs):
        if not self.password:
            temp_password = f"password-{uuid.uuid4().__str__.split('-')[-1]}"
            self.password = temp_password

    def has_password(self):
        if self.password.startswith('pbkdf2'):
            self.password = self.set_password(self.password)

    def token(self):
        refresh_token = RefreshToken.for_user(self.user)
        data = {
            'access_token': str(refresh_token.access_token),
            'refresh_token': str(refresh_token),
        }
        return data

    def clean(self):
        self.check_username()
        self.check_email()
        self.check_password()
        self.has_password()
        self.token()

    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)


class UserConfirmCode(BaseModel):
    AUTH_TYPE = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )
    code = models.CharField(max_length=20)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user')
    auth_type = models.CharField(max_length=20, choices=AUTH_TYPE)

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.auth_type == VIA_EMAIL:
                self.exp_time = datetime.now() + datetime.timedelta(minutes=2)
                self.code = self.user.create_verify_code(VIA_EMAIL)
            else:
                self.exp_time = datetime.now() + datetime.timedelta(minutes=3)
                self.code = self.user.create_verify_code(VIA_PHONE)
            self.user.save(*args, **kwargs)
