from __future__ import unicode_literals
import re, bcrypt
from django.core.exceptions import ObjectDoesNotExist
from django.db import models

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    def validation_errors(self, request):
        errors = []
        if len(request.POST['first_name']) < 3 or len(request.POST['last_name']) < 3:
            errors.append("First and Last name are too short")
        if not EMAIL_REGEX.match(request.POST['email']):
            errors.append("Must use a valid email")
        if len(request.POST['password']) < 8 or request.POST['password'] != request.POST['pwconfirm']:
            errors.append("Passwords must match and be at least 8 characters")
        return errors

    def reg_validation(self, request):
        errors = self.validation_errors(request)
        if len(errors) > 0:
            return (False, errors)
        pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = self.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], pw_hash=pw_hash)
        return (True, user)

    def login_validation(self, request):
        try:
            user = User.objects.get(email=request.POST['email'])
            password = request.POST['password'].encode()
            if bcrypt.hashpw(password, user.pw_hash.encode()):
                return (True, user)
        except ObjectDoesNotExist:
            pass
        return (False, ["Login information does not match existing information"])

class User(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=60)
    pw_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
