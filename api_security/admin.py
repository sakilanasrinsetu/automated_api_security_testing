from django.contrib import admin
from .models import *

# Register your models here. 
@admin.register(MITREAttackTactic)
class MITREAttackTacticAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug','created_at')
    search_fields = ('name',)
    list_filter = ('name','created_at')
    readonly_fields = ('created_at',)
    
@admin.register(MITREAttackTechnique)
class MITREAttackTechniqueAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'tactic','created_at')
    search_fields = ('name',)
    list_filter = ('name','created_at')
    readonly_fields = ('created_at',)
    
@admin.register(APITest)
class APITestAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug','endpoint', 'http_method', 'auth_type', 'created_by', 'created_at')
    search_fields = ('name', 'endpoint', 'auth_type')
    list_filter = ('http_method', 'auth_type', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(SecurityTestCase)
class SecurityTestCaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'created_at')
    search_fields = ('name','severity')
    list_filter = ('severity', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(TestExecution)
class TestExecutionAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'security_test_case', 'executed_by', 'executed_at', 'status_code', 'success')
    search_fields = ('api_test__name', 'security_test_case__name')
    list_filter = ('status_code', 'success', 'executed_at')
    readonly_fields = ('executed_at',)

@admin.register(LLMAnalysis)
class LLMAnalysisAdmin(admin.ModelAdmin):
    list_display = ('test_execution', 'risk_score', 'created_at')
    search_fields = ('test_execution__api_test__name',)
    list_filter = ('risk_score', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('test_execution', 'generated_by', 'generated_at')
    search_fields = ('test_execution__api_test__name',)
    list_filter = ('generated_at',)
    readonly_fields = ('generated_at',)

@admin.register(AttackSimulation)
class AttackSimulationAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'security_test_case', 'executed_by', 'executed_at', 'success')
    search_fields = ('api_test__name', 'security_test_case__name')
    list_filter = ('executed_at', 'success')
    readonly_fields = ('executed_at',)

@admin.register(APILog)
class APILogAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'attempted_by', 'ip_address', 'status', 'response_code', 'timestamp')
    search_fields = ('api_test__name', 'attempted_by__username', 'ip_address')
    list_filter = ('status', 'response_code', 'timestamp')
    readonly_fields = ('timestamp',)

@admin.register(TestSchedule)
class TestScheduleAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'security_test_case', 'scheduled_by', 'schedule_time', 'status')
    search_fields = ('api_test__name', 'security_test_case__name', 'scheduled_by__username')
    list_filter = ('status', 'schedule_time')

