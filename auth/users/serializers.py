from rest_framework import serializers
from .models import User, Reservation
from django.core.validators import MinLengthValidator

class ReservationSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    duration = serializers.SerializerMethodField()

    class Meta:
        model = Reservation
        fields = ['id', 'reservation_code', 'expires_at', 'reserved_at', 'activated_at', 'exited_at', 'duration', 'user']
        read_only_fields = ['id', 'reservation_code', 'reserved_at', 'user']

    def get_duration(self, obj):
        return obj.calculate_duration()

class UserSerializer(serializers.ModelSerializer):
    reservations = ReservationSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'number_plate', 'reservations']
        extra_kwargs = {
            'password': {'write_only': True, 'validators': [MinLengthValidator(8)]}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(validators=[MinLengthValidator(8)])