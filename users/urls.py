from .views import (
                    UserCreateView, VerifyAPIView, GetNewVerification, ChangeUserInformationView,
                    UserVerification, ChangeUserPhotoView, LoginView, LoginRefreshView, LogOutView, ForgotPasswordView,
                    ResetPasswordView,
                    )

from django.urls import path
urlpatterns = [
    path('user-create', UserCreateView.as_view()),
    path('verify', VerifyAPIView.as_view()),
    path('new-verify', GetNewVerification.as_view()),
    path('change-info', ChangeUserInformationView.as_view()),
    path('add-photo', ChangeUserPhotoView.as_view()),
    path('user-verify', UserVerification.as_view()),
    path("login", LoginView.as_view()),
    path("logout", LogOutView.as_view()),
    path("login-refresh", LoginRefreshView.as_view()),
    path("forgot-password", ForgotPasswordView.as_view()),
    path("reset-password", ResetPasswordView.as_view()),
]
