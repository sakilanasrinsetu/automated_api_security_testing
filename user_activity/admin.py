from django.contrib import admin
from .models import *

# Register your models here. 
@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('actor','ip_address', 'action_type','action_time')
    search_fields = ('actor','action_type')
    list_filter = ('actor','action_time', 'action_type')
    readonly_fields = ('action_time',)
    