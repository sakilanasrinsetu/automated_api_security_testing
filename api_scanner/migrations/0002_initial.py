# Generated by Django 5.1.6 on 2025-05-07 18:38

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('api_scanner', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='apilog',
            name='attempted_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='attempted_api_logs', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='apitest',
            name='created_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_api_tests', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='apilog',
            name='api_test',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='api_logs', to='api_scanner.apitest'),
        ),
        migrations.AddField(
            model_name='attacksimulation',
            name='api_test',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attack_simulations', to='api_scanner.apitest'),
        ),
        migrations.AddField(
            model_name='attacksimulation',
            name='executed_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='executed_attack_simulations', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='mitreattacktechnique',
            name='tactic',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='techniques', to='api_scanner.mitreattacktactic'),
        ),
        migrations.AddField(
            model_name='report',
            name='generated_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='generated_reports', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='securitytestcase',
            name='api_test',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='security_test_cases', to='api_scanner.apitest'),
        ),
        migrations.AddField(
            model_name='securitytestcase',
            name='mitre_attack_technique',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='security_test_cases', to='api_scanner.mitreattacktechnique'),
        ),
        migrations.AddField(
            model_name='attacksimulation',
            name='security_test_case',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attack_simulations', to='api_scanner.securitytestcase'),
        ),
        migrations.AddField(
            model_name='testexecution',
            name='api_test',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_executions', to='api_scanner.apitest'),
        ),
        migrations.AddField(
            model_name='testexecution',
            name='executed_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='executed_test_executions', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='testexecution',
            name='security_test_case',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_executions', to='api_scanner.securitytestcase'),
        ),
        migrations.AddField(
            model_name='report',
            name='test_execution',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='api_scanner.testexecution'),
        ),
        migrations.AddField(
            model_name='llmanalysis',
            name='test_execution',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='llm_analyses', to='api_scanner.testexecution'),
        ),
        migrations.AddField(
            model_name='testschedule',
            name='api_test',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_schedules', to='api_scanner.apitest'),
        ),
        migrations.AddField(
            model_name='testschedule',
            name='scheduled_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scheduled_test_schedules', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='testschedule',
            name='security_test_case',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_schedules', to='api_scanner.securitytestcase'),
        ),
    ]
