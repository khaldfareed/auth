from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User, Reservation
from .serializers import UserSerializer, ReservationSerializer
from rest_framework.exceptions import AuthenticationFailed
import jwt
import datetime
from django.utils import timezone
import random


import logging
from .serializers import PasswordResetRequestSerializer, PasswordResetSerializer
import secrets
from django.core.mail import send_mail  # Ensure you have Django's email settings configured

logger = logging.getLogger(__name__)

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.filter(email=email).first()
        if user is None or not user.check_password(password):
            raise AuthenticationFailed('Invalid credentials')
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {'jwt': token}
        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {'message': 'success'}
        return response


class ReserveSlotAPIView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")
        user = User.objects.get(id=payload['id'])

        # Check if the user already has an active or non-exited reservation
        existing_reservation = Reservation.objects.filter(
            user=user,
            exited_at__isnull=True,
            activated_at__isnull=False
        ).first()

        if existing_reservation:
            return Response({
                'message': 'You already have an active reservation. You cannot reserve another slot until it is exited or expired.'},
                status=status.HTTP_400_BAD_REQUEST)

        # Check for available slots
        active_reservations = Reservation.objects.filter(exited_at__isnull=True, activated_at__isnull=False).count()
        if active_reservations >= 4:
            return Response({'message': 'All slots are reserved'}, status=status.HTTP_400_BAD_REQUEST)

        expires_at = timezone.now() + datetime.timedelta(hours=1)

        # Generate a 4-digit reservation code
        reservation_code = '{:04d}'.format(random.randint(0, 9999))

        reservation = Reservation.objects.create(user=user, reservation_code=reservation_code, expires_at=expires_at)
        serializer = ReservationSerializer(reservation)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ActivateSlotAPIView(APIView):
    def post(self, request, code):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.get(id=payload['id'])

        try:
            reservation = Reservation.objects.get(reservation_code=code, user=user)
            if reservation.activated_at:
                return Response({'message': 'Already activated'}, status=status.HTTP_400_BAD_REQUEST)
            if reservation.expires_at < timezone.now():
                return Response({'message': 'Reservation code expired'}, status=status.HTTP_400_BAD_REQUEST)

            reservation.activated_at = timezone.now()
            reservation.expires_at = None  # Clear the expiration time once activated
            reservation.save()

            return Response({'message': 'Activated'}, status=status.HTTP_200_OK)

        except Reservation.DoesNotExist:
            return Response({'message': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)


class ExitSlotAPIView(APIView):
    def post(self, request, code):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.get(id=payload['id'])

        try:
            reservation = Reservation.objects.get(reservation_code=code, user=user)
            if reservation.exited_at:
                return Response({'message': 'Already exited'}, status=status.HTTP_400_BAD_REQUEST)

            reservation.exited_at = timezone.now()
            reservation.save()

            duration = reservation.calculate_duration()

            return Response({'message': 'Exited', 'duration': duration}, status=status.HTTP_200_OK)

        except Reservation.DoesNotExist:
            return Response({'message': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)


class ReservationHistoryAPIView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.get(id=payload['id'])
        reservations = Reservation.objects.filter(user=user).order_by('-reserved_at')
        serializer = ReservationSerializer(reservations, many=True)
        return Response(serializer.data)


class FreeSlotsAPIView(APIView):
    def get(self, request):
        active_reservations = Reservation.objects.filter(exited_at__isnull=True, activated_at__isnull=False).count()
        free_slots = 4 - active_reservations
        return Response({'free_slots': free_slots}, status=status.HTTP_200_OK)


class ActiveSlotsAPIView(APIView):
    def get(self, request):
        active_reservations = Reservation.objects.filter(activated_at__isnull=False, exited_at__isnull=True)
        serializer = ReservationSerializer(active_reservations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class PasswordResetRequestAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if user:
            reset_token = secrets.token_urlsafe(20)
            reset_token_expires_at = timezone.now() + datetime.timedelta(hours=1)
            user.reset_token = reset_token
            user.reset_token_expires_at = reset_token_expires_at
            user.save()
            reset_link = f"http://yourfrontend.com/reset-password/{reset_token}"
            send_mail(
                'Password Reset Request',
                f'Click the link to reset your password: {reset_link}',
                'KhaledCse2024@outlook.com',
                [user.email],
                fail_silently=False,
            )
            logger.info(f'Password reset email sent to {user.email}')
        return Response({'message': 'If your email is registered, you will receive a password reset link.'}, status=status.HTTP_200_OK)

class PasswordResetAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reset_token = serializer.validated_data['reset_token']
        new_password = serializer.validated_data['new_password']
        user = User.objects.filter(reset_token=reset_token, reset_token_expires_at__gt=timezone.now()).first()
        if not user:
            logger.error('Invalid or expired reset token')
            return Response({'message': 'Invalid or expired reset token.'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expires_at = None
        user.save()
        logger.info(f'Password has been reset for {user.email}')
        return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)