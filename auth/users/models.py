from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import datetime

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    number_plate = models.CharField(max_length=20, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    reset_token = models.CharField(max_length=6, blank=True, null=True)
    reset_token_expires_at = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

def default_expires_at():
    return timezone.now() + datetime.timedelta(hours=1)

class Reservation(models.Model):
    user = models.ForeignKey(User, related_name='reservations', on_delete=models.CASCADE)
    reservation_code = models.CharField(max_length=4, unique=True)
    reserved_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(blank=True, null=True)
    exited_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField(default=default_expires_at, blank=True, null=True)  # Allow NULL values

    def __str__(self):
        return self.reservation_code

    def calculate_duration(self):
        if self.activated_at and self.exited_at:
            return (self.exited_at - self.activated_at).total_seconds() / 60
        elif self.activated_at:
            return (timezone.now() - self.activated_at).total_seconds() / 60
        return None
