from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

# Schema/Swagger/Redoc URLs
schema_urlpatterns = [
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# App-specific URLs
app_urlpatterns = [
    path('user_account/', include('user.urls')),
    path('api/', include('api_scanner.urls')),
    path('evaluation/', include('evaluation.urls')),
]

# Main URL configuration
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),  # DRF login/logout views
    path('', include(app_urlpatterns)),
] + schema_urlpatterns

# Debug toolbar and static/media files in development
if settings.DEBUG:
    urlpatterns = urlpatterns + \
        static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns = urlpatterns + \
        static(settings.MEDIA_URL, document_root= settings.MEDIA_ROOT)