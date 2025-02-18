from django.urls import path
from . import views
from django.urls import path, re_path
from rest_framework.schemas import get_schema_view
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(   
        title="Your API",
        default_version='v1',
        description="API Documentation",
    ),
    public=True,
)

urlpatterns = [
    path('register/', views.register_user, name='register_user'),
    path('register/verify/', views.verify_registration, name='verify_registration'),
    path('login/', views.login_user, name='login_user'),
    path('me/', views.user_details, name='user_details'),
    path('logout/', views.logout_user, name='logout_user'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]
