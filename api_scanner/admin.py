# admin.py
from django.contrib import admin
from api_scanner.models import (
    MITREAttackTactic, MITREAttackTechnique, APITest, SecurityTestCase,
    TestExecution, LLMAnalysis, Report, AttackSimulation, APILog, TestSchedule
)

@admin.register(MITREAttackTactic)
class MITREAttackTacticAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'created_at')
    search_fields = ('name',)
    list_filter = ('created_at',)
    readonly_fields = ('created_at',)

@admin.register(MITREAttackTechnique)
class MITREAttackTechniqueAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'tactic', 'created_at')
    search_fields = ('name', 'slug', 'tactic__name')
    list_filter = ('tactic', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(APITest)
class APITestAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'http_method', 'auth_type', 'created_by', 'created_at')
    search_fields = ('name', 'slug', 'endpoint', 'created_by__email')
    list_filter = ('http_method', 'auth_type', 'created_at')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(SecurityTestCase)
class SecurityTestCaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'mitre_attack_technique', 'severity', 'created_at')
    search_fields = ('name', 'slug', 'mitre_attack_technique__name')
    list_filter = ('severity', 'created_at')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(TestExecution)
class TestExecutionAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'slug', 'security_test_case', 'executed_by', 'executed_at', 'success')
    search_fields = ('slug', 'api_test__name', 'security_test_case__name', 'executed_by__email')
    list_filter = ('success', 'executed_at')
    readonly_fields = ('executed_at', 'created_at', 'updated_at')

@admin.register(LLMAnalysis)
class LLMAnalysisAdmin(admin.ModelAdmin):
    list_display = ('test_execution', 'slug', 'risk_score', 'created_at')
    search_fields = ('slug', 'test_execution__slug')
    list_filter = ('risk_score', 'created_at')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('test_execution', 'slug', 'generated_by', 'generated_at')
    search_fields = ('slug', 'test_execution__slug', 'generated_by__email')
    list_filter = ('generated_at',)
    readonly_fields = ('generated_at',)

@admin.register(AttackSimulation)
class AttackSimulationAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'slug', 'security_test_case', 'executed_by', 'executed_at', 'success')
    search_fields = ('slug', 'api_test__name', 'security_test_case__name', 'executed_by__email')
    list_filter = ('success', 'executed_at')
    readonly_fields = ('executed_at', 'created_at', 'updated_at')

@admin.register(APILog)
class APILogAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'slug', 'attempted_by', 'ip_address', 'timestamp', 'status')
    search_fields = ('slug', 'api_test__name', 'attempted_by__email', 'ip_address')
    list_filter = ('status', 'timestamp')
    readonly_fields = ('timestamp', 'created_at', 'updated_at')

@admin.register(TestSchedule)
class TestScheduleAdmin(admin.ModelAdmin):
    list_display = ('api_test', 'slug', 'security_test_case', 'scheduled_by', 'schedule_time', 'status')
    search_fields = ('slug', 'api_test__name', 'security_test_case__name', 'scheduled_by__email')
    list_filter = ('status', 'schedule_time')
    readonly_fields = ('created_at', 'updated_at')
