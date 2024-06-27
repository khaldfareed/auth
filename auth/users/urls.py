from django.urls import path
from .views import RegisterAPIView, LoginAPIView, UserView, LogoutView, ReserveSlotAPIView, ActivateSlotAPIView, ExitSlotAPIView, ReservationHistoryAPIView, FreeSlotsAPIView, ActiveSlotsAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view()),
    path('login/', LoginAPIView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('reserve/', ReserveSlotAPIView.as_view()),
    path('activate/<str:code>/', ActivateSlotAPIView.as_view()),
    path('exit/<str:code>/', ExitSlotAPIView.as_view()),
    path('history/', ReservationHistoryAPIView.as_view()),
    path('freeslots/', FreeSlotsAPIView.as_view()),
    path('active/', ActiveSlotsAPIView.as_view()),  # Added the new endpoint
]
