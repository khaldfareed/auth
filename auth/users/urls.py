from django.urls import path
from .views import RegisterAPIView, LoginAPIView, UserView, LogoutView, ReserveSlotAPIView, ActivateSlotAPIView, ExitSlotAPIView, ReservationHistoryAPIView, FreeSlotsAPIView, ActiveSlotsAPIView, PasswordResetRequestAPIView, PasswordResetAPIView


urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('user/', UserView.as_view(), name='user'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('reserve/', ReserveSlotAPIView.as_view(), name='reserve'),
    path('activate/<str:code>/', ActivateSlotAPIView.as_view(), name='activate'),
    path('exit/<str:code>/', ExitSlotAPIView.as_view(), name='exit'),
    path('history/', ReservationHistoryAPIView.as_view(), name='history'),
    path('freeslots/', FreeSlotsAPIView.as_view(), name='freeslots'),
    path('active/', ActiveSlotsAPIView.as_view(), name='active'),
    path('password-reset-request/', PasswordResetRequestAPIView.as_view(), name='password-reset-request'),
    path('password-reset/', PasswordResetAPIView.as_view(), name='password-reset'),
]
