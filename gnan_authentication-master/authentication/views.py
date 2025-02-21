import random
import string
import jwt
import datetime
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.contrib.auth import logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import logout
from django.http import JsonResponse

from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

SECRET_KEY = settings.SECRET_KEY  # Use Django's SECRET_KEY for JWT

# Helper function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# User Registration API (POST /api/register/)
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """
    Handles user registration and sends an OTP to the provided email.
    """
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=email).exists():
        return Response({"error": "User already exists."}, status=status.HTTP_400_BAD_REQUEST)

    otp = generate_otp()
    cache.set(email, otp, timeout=300)  # Store OTP in cache for 5 minutes

    # Send OTP via email
    send_mail(
        subject="Your OTP for Registration",
        message=f"Your OTP for registration is {otp}. It expires in 5 minutes.",
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[email],
        fail_silently=False,
    )

    return Response({"message": "OTP sent to email. Verify within 5 minutes."}, status=status.HTTP_201_CREATED)

# OTP Verification API (POST /api/register/verify)
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_registration(request):
    """
    Verifies the OTP and creates a new user upon successful validation.
    """
    email = request.data.get('email')
    otp = request.data.get('otp')
    password = request.data.get('password')

    if not email or not otp or not password:
        return Response({"error": "Email, OTP, and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    stored_otp = cache.get(email)
    if not stored_otp:
        return Response({"error": "OTP expired or invalid."}, status=status.HTTP_400_BAD_REQUEST)

    if stored_otp != otp:
        return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

    # Create user after OTP verification
    user = User.objects.create_user(username=email, email=email, password=password)
    user.save()

    # Clear OTP after successful verification
    cache.delete(email)

    return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)

# User Login API (POST /api/login/)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    """
    Handles user login, authenticates credentials, and sets an auth token in an HTTP-only cookie.
    """
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=email, password=password)
    if user is None:
        return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

    login(request, user)  # Django login

    # Generate JWT token
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),  # Token valid for 1 day
        'iat': datetime.datetime.utcnow()
    }
    auth_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    response = JsonResponse({"message": "Login successful."}, status=status.HTTP_200_OK)
    response.set_cookie(
        key="auth_token",
        value=auth_token,
        httponly=True,  # Prevent client-side JavaScript access
        secure=True,  # Secure flag for HTTPS
        samesite="Lax",
    )
    return response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_details(request):
    # Get token from cookies
    auth_token = request.COOKIES.get('auth_token')

    if not auth_token:
        return Response({"error": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Decode the JWT token
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
        user = User.objects.get(id=payload['user_id'])
    except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_401_UNAUTHORIZED)

    return Response({"email": user.email, "username": user.username}, status=status.HTTP_200_OK)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def user_details(request):
#     user = request.user
#     return Response({'email': user.email, 'username': user.username})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    logout(request)
    response = Response({"message": "Logged out successfully"}, status=200)
    response.delete_cookie("auth_token")  # Ensure the correct token name
    return response