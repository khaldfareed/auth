from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User, Reservation
from .serializers import UserSerializer, ReservationSerializer, PasswordResetRequestSerializer, PasswordResetSerializer
from rest_framework.exceptions import AuthenticationFailed
import jwt
import datetime
from django.utils import timezone
import random
import logging
from django.core.mail import send_mail

logger = logging.getLogger(__name__)

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f'User registered with email: {serializer.data["email"]}')
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error('User registration failed')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()
        if user is None or not user.check_password(password):
            logger.warning(f'Invalid login attempt for email: {email}')
            raise AuthenticationFailed('Invalid credentials')
        payload = {
            'id': user.id,
            'exp': timezone.now() + datetime.timedelta(minutes=60),
            'iat': timezone.now()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {'jwt': token}
        logger.info(f'User logged in: {email}')
        return response

class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            logger.warning('Unauthenticated access attempt')
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            logger.warning('Expired JWT token')
            raise AuthenticationFailed("Unauthenticated")
        user = User.objects.filter(id=payload['id']).first()
        if user:
            serializer = UserSerializer(user)
            logger.info(f'User data retrieved: {user.email}')
            return Response(serializer.data)
        logger.error('User not found')
        raise AuthenticationFailed("Unauthenticated")

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {'message': 'success'}
        logger.info('User logged out')
        return response

#
class ReserveSlotAPIView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            logger.warning('Unauthenticated access attempt')
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            logger.warning('Expired JWT token')
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.get(id=payload['id'])

        # Check if there is an active reservation code that has not been exited
        active_reservation = Reservation.objects.filter(
            user=user,
            exited_at__isnull=True
        ).order_by('-reserved_at').first()

        if active_reservation:
            if active_reservation.activated_at:
                logger.info(f'User {user.email} tried to generate another reservation code without exiting the last one')
                return Response({
                    'message': 'You cannot get another reservation code until you exit.'
                }, status=status.HTTP_400_BAD_REQUEST)

            if active_reservation.expires_at and active_reservation.expires_at > timezone.now():
                
                reservation_code = active_reservation.reservation_code
                
                # Convert the expiration time to Egypt Standard Time (UTC+2)
                egypt_timezone = pytz.timezone('Africa/Cairo')
                expires_at_utc = active_reservation.expires_at
                expires_at_egypt = expires_at_utc.astimezone(egypt_timezone)
                expires_at_formatted = expires_at_egypt.strftime('%H:%M at %d-%b-%Y')  # Format datetime with month abbreviation
                
                logger.info(f'User {user.email} tried to generate another reservation code without activating the last one')
                return Response({
                    'message': 'You already have a reservation code: {' + f' {reservation_code} ' + '} and it expires at:' + f'{expires_at}'
                }, status=status.HTTP_400_BAD_REQUEST)

        # Check if there are already 4 active reservations globally
        active_reservations_count = Reservation.objects.filter(exited_at__isnull=True, activated_at__isnull=False).count()
        if active_reservations_count >= 4:
            logger.info('All slots are reserved')
            return Response({'message': 'All slots are reserved'}, status=status.HTTP_400_BAD_REQUEST)

        # Create new reservation
        expires_at = timezone.now() + datetime.timedelta(hours=1)
        reservation_code = '{:04d}'.format(random.randint(0, 9999))
        reservation = Reservation.objects.create(
            user=user,
            reservation_code=reservation_code,
            expires_at=expires_at,
            reserved_at=timezone.now()
        )
        serializer = ReservationSerializer(reservation)
        logger.info(f'Reservation created for user {user.email} with code {reservation_code}')
        return Response(serializer.data, status=status.HTTP_201_CREATED)



class ActivateSlotOuterAPIView(APIView):
    """
    API endpoint to activate a reserved code at the outer screen.
    """
    def post(self, request, code):
        logger.debug("Received request to activate slot with code: %s at the outer screen", code)

        try:
            reservation = Reservation.objects.get(reservation_code=code)
            logger.debug("Reservation found with code: %s", code)

            if reservation.activated_at:
                logger.info("Reservation already activated: %s", code)
                return Response({'message': 'Already activated'}, status=status.HTTP_400_BAD_REQUEST)

            if reservation.expires_at and reservation.expires_at < timezone.now():
                logger.info("Reservation code expired: %s", code)
                return Response({'message': 'Reservation code expired'}, status=status.HTTP_400_BAD_REQUEST)

            reservation.activated_at = timezone.now()
            reservation.expires_at = None  # Clear the expiration time once activated
            reservation.save()
            logger.info("Reservation activated successfully: %s at the outer screen", code)

            return Response({'message': 'Welcome to the parking'}, status=status.HTTP_200_OK)

        except Reservation.DoesNotExist:
            logger.warning("Invalid reservation code: %s", code)
            return Response({'message': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)


class ExitSlotInnerAPIView(APIView):
    """
    API endpoint to exit a reserved code at the inner screen.
    """
    def post(self, request, code):
        logger.debug("Received request to exit slot with code: %s at the inner screen", code)

        try:
            reservation = Reservation.objects.get(reservation_code=code)
            logger.debug("Reservation found with code: %s", code)

            if reservation.exited_at:
                logger.info("Reservation already exited: %s", code)
                return Response({'message': 'Already exited'}, status=status.HTTP_400_BAD_REQUEST)

            reservation.exited_at = timezone.now()
            reservation.save()
            logger.info("Reservation exited successfully: %s at the inner screen", code)

            duration = reservation.calculate_duration()
            logger.debug("Reservation duration calculated: %s", duration)

            return Response({'message': 'Exited', 'duration': duration}, status=status.HTTP_200_OK)

        except Reservation.DoesNotExist:
            logger.warning("Invalid reservation code: %s", code)
            return Response({'message': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)

class ReservationHistoryAPIView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            logger.warning('Unauthenticated access attempt')
            raise AuthenticationFailed("Unauthenticated")
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            logger.warning('Expired JWT token')
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.get(id=payload['id'])
        reservations = Reservation.objects.filter(user=user).order_by('-reserved_at')
        serializer = ReservationSerializer(reservations, many=True)
        logger.info(f'Reservation history retrieved for user: {user.email}')
        return Response(serializer.data)

class FreeSlotsAPIView(APIView):
    def get(self, request):
        active_reservations = Reservation.objects.filter(exited_at__isnull=True, activated_at__isnull=False).count()
        free_slots = 4 - active_reservations
        logger.info(f'Free slots count: {free_slots}')
        return Response({'free_slots': free_slots}, status=status.HTTP_200_OK)

class ActiveSlotsAPIView(APIView):
    def get(self, request):
        active_reservations = Reservation.objects.filter(activated_at__isnull=False, exited_at__isnull=True)
        serializer = ReservationSerializer(active_reservations, many=True)
        logger.info('Active slots retrieved')
        return Response(serializer.data, status=status.HTTP_200_OK)

class PasswordResetRequestAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if user:
                reset_token = '{:04d}'.format(random.randint(0, 9999))  # Generate 4-digit token
                reset_token_expires_at = timezone.now() + datetime.timedelta(hours=1)
                user.reset_token = reset_token
                user.reset_token_expires_at = reset_token_expires_at
                user.save()
                send_mail(
                    'Password Reset Request',
                    f'Your password reset code is: {reset_token}',
                    'KhaldCse@outlook.com',
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f'Password reset email sent to {user.email}')
            return Response({'message': 'If your email is registered, you will receive a password reset code.'}, status=status.HTTP_200_OK)
        logger.error('Password reset request validation failed')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
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
        logger.error('Password reset validation failed')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#3###
