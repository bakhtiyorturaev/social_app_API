import re
from rest_framework.exceptions import ValidationError

regex_phone = r"/^9989[0123456789][0-9]{7}$/"
regex_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'


def check_email_phone(email_phone_number):
    if re.fullmatch(regex_phone, email_phone_number):
        return "phone"
    elif re.fullmatch(regex_email, email_phone_number):
        return "email"
    else:
        context = {
            "status": False,
            "message": "Invalid email or phone number"
        }
        raise ValidationError(context)
