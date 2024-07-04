from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Reservation
from django.utils import timezone

class ReservationInline(admin.TabularInline):
    model = Reservation
    extra = 0
    readonly_fields = ('reservation_code', 'reserved_at', 'activated_at', 'exited_at', 'expires_at', 'duration', 'user_number_plate')

    def duration(self, obj):
        if obj.activated_at and obj.exited_at:
            return (obj.exited_at - obj.activated_at).total_seconds() / 60
        elif obj.activated_at:
            return (timezone.now() - obj.activated_at).total_seconds() / 60
        else:
            return None
    duration.short_description = 'Duration (minutes)'

    def user_number_plate(self, obj):
        return obj.user.number_plate
    user_number_plate.short_description = 'Number Plate'

class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('number_plate',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Password reset info', {'fields': ('reset_token', 'reset_token_expires_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'number_plate'),
        }),
    )
    list_display = ('email', 'number_plate', 'is_staff', 'is_superuser')
    search_fields = ('email', 'number_plate')
    ordering = ('email',)
    inlines = [ReservationInline]
    filter_horizontal = ('groups', 'user_permissions')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')

class ReservationAdmin(admin.ModelAdmin):
    list_display = ('reservation_code', 'user', 'user_number_plate', 'reserved_at', 'activated_at', 'exited_at', 'is_active', 'duration')
    search_fields = ('reservation_code', 'user__email', 'user__number_plate')
    list_filter = ('activated_at', 'exited_at')
    ordering = ('-reserved_at',)

    def is_active(self, obj):
        return obj.activated_at is not None and obj.exited_at is None
    is_active.boolean = True
    is_active.short_description = 'Is Active'

    def duration(self, obj):
        if obj.activated_at and obj.exited_at:
            return (obj.exited_at - obj.activated_at).total_seconds() / 60
        elif obj.activated_at:
            return (timezone.now() - obj.activated_at).total_seconds() / 60
        else:
            return None
    duration.short_description = 'Duration (minutes)'

    def user_number_plate(self, obj):
        return obj.user.number_plate
    user_number_plate.short_description = 'Number Plate'

admin.site.register(User, UserAdmin)
admin.site.register(Reservation, ReservationAdmin)
