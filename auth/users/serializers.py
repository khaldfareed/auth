from rest_framework import serializers
from .models import User, Reservation

class ReservationSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()

    class Meta:
        model = Reservation
        fields = ['id', 'reservation_code', 'reserved_at', 'activated_at', 'exited_at', 'user']
        read_only_fields = ['id', 'reservation_code', 'reserved_at', 'user']

class UserSerializer(serializers.ModelSerializer):
    reservations = ReservationSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'number_plate', 'reservations']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
