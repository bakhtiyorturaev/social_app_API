from .views import UserCreateView
from django.urls import path
urlpatterns = [
    path('user-create/', UserCreateView.as_view())

    ]
