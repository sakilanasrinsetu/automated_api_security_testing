from django.shortcuts import render

from api_security.models import *
from rest_framework import permissions

from utils.generates import unique_slug_generator
from utils.response_wrapper import ResponseWrapper
from .serializers import *
from utils.custom_veinlet import CustomViewSet

# Create your views here.

class MITREAttackTacticViewSet(CustomViewSet):
    queryset = MITREAttackTactic.objects.all().order_by('-created_at')
    lookup_field = 'slug'
    serializer_class = MITREAttackTacticSerializer
    permission_classes = [permissions.AllowAny]
    
class MITREAttackTechniqueViewSet(CustomViewSet):
    queryset = MITREAttackTechnique.objects.all().order_by('-created_at')
    lookup_field = 'slug'
    serializer_class = MITREAttackTechniqueSerializer
    permission_classes = [permissions.AllowAny]
    
class APITestViewSet(CustomViewSet):
    queryset = APITest.objects.all().order_by('-created_at')
    lookup_field = 'slug'
    serializer_class = APITestSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        data = request.data
        name = data.get('name')

        # Validate required fields
        if not name:
            return ResponseWrapper(
                {"error": "Name is required."},
                status=400
            )

        # Check for duplicate names
        if APITest.objects.filter(name=name).exists():
            return ResponseWrapper(
                {"error": "An APITest with this name already exists."},
                status=400
            )

        # Generate a unique slug
        slug = unique_slug_generator(name=name)

        # Prepare data for the serializer
        serializer_data = data.copy()
        serializer_data['slug'] = slug

        # Dynamically set http_method from request.method (if valid)
        http_method = request.method.upper()
        if http_method not in dict(HTTP_METHOD).keys():
            return ResponseWrapper(
                {"error": f"Invalid HTTP method: {http_method}"},
                status=400
            )
        serializer_data['http_method'] = http_method

        if hasattr(request.auth, 'type'):
            serializer_data['auth_type'] = request.auth.type
        else:
            serializer_data['auth_type'] = 'None'  # Default value

        # Set created_by to the current user
        serializer_data['created_by'] = request.user.id

        # Validate and save the APITest instance
        serializer = self.get_serializer(data=serializer_data)
        if not serializer.is_valid():
            return ResponseWrapper(
                {"error": serializer.errors},
                status=400
            )

        try:
            # Save the APITest instance
            serializer.save(created_by=request.user, slug = slug)
        except Exception as e:
            return ResponseWrapper(
                {"error": f"An error occurred while saving the APITest instance: {str(e)}"},
                status=500
            )

        # Return the created APITest instance
        return ResponseWrapper(
            {"data": serializer.data, "message": "APITest created successfully."},
            status=201
        )