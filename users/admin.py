from django.contrib import admin
from .models import User, UserConfirmation
# Register your models here.


class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'first_name', 'email', 'id', 'is_staff']


admin.site.register(User, UserAdmin)
admin.site.register(UserConfirmation)
