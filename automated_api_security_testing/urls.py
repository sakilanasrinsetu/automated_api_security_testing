from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)


schema_urlpatterns = [
    path("spectacular/", SpectacularAPIView.as_view(), name="schema"),
    path("", SpectacularSwaggerView.as_view(url_name="schema"), name="doc"),
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]


app_url_patterns = [
    path('user_account/', include('user.urls')),
    # path('api_scanner/', include('api_scanner.urls')),
    path('evaluation/', include('evaluation.urls')),
]


urlpatterns = [
    path('admin/', admin.site.urls),
    path('admin/', include('rest_framework.urls')),
    path('', include(app_url_patterns)),
] + schema_urlpatterns


if settings.DEBUG:
    urlpatterns.append(path("__debug__/", include("debug_toolbar.urls")))


if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, 
                          document_root=settings.MEDIA_ROOT)
