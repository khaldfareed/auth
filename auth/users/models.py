from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.db import models
from django.utils import timezone
import random


class UserManager(BaseUserManager):
    use_in_migrations = True

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

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)
class User(AbstractUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    number_plate = models.CharField(max_length=50, unique=True)
    reset_token = models.CharField(max_length=4, null=True, blank=True)
    reset_token_expires_at = models.DateTimeField(null=True, blank=True)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

class Reservation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reservations')
    reservation_code = models.CharField(max_length=4, unique=True)
    reserved_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    exited_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)  # Added expires_at field
    duration = models.FloatField(null=True, blank=True)
    def __str__(self):
        return f"Reservation {self.reservation_code} by {self.user.email}"

    def calculate_duration(self):
        if self.exited_at and self.activated_at:
            activated_at = self.activated_at.astimezone(timezone.utc) if self.activated_at.tzinfo else self.activated_at
            exited_at = self.exited_at.astimezone(timezone.utc) if self.exited_at.tzinfo else self.exited_at
            duration = (exited_at - activated_at).total_seconds() / 60  # Duration in minutes
            return duration
        else:
            return None

    def generate_reservation_code():
        while True:
            code = str(random.randint(1000, 9999))
            if not Reservation.objects.filter(reservation_code=code).exists():
                return code

    def save(self, *args, **kwargs):
        if not self.reservation_code:
            self.reservation_code = Reservation.generate_reservation_code()
        super().save(*args, **kwargs)
