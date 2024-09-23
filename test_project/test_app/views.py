# Standard Library Imports
from datetime import datetime

# Django Imports
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import smart_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
from django.core.mail import EmailMessage

# Third-party Imports
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# Local Application Imports
from .models import User
from .serializers import (
    UserRegistrationSerializer,
    CustomerLoginSerializer
)
from Utilities.utils import generate_otp, send_email_otp

class CustomerRegistrationView(APIView):
    def post(self, request):
        data = request.data
        
        # Check if a user with the same email already exists
        if User.objects.filter(email=data.get('email')).exists():
            return Response({'status': "error", 'message': 'User with this email already exists. Please try a new one.'},
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Generate OTP
        data["email_otp"] = generate_otp(6)
        data["phone_otp"] = data["email_otp"]

        serializer = UserRegistrationSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            otp_sent = send_email_otp(user, user.email_otp)
            
            if otp_sent:
                return Response({'status': 'success', 'message': 'User registered successfully. Kindly check your email.'},
                                status=status.HTTP_201_CREATED)
            else:
                user.delete()
                return Response({'status': 'error', 'message': 'Email could not be sent'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'status': 'error', 'message': 'User registration failed.', 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)
    

class CustomerEmailOTPVerificationView(APIView):

    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = data.get('otp')

        # Check if email and OTP are provided
        # if not email or not otp:
        if email is None or otp is None:
            return Response({'status': 'error', 'message': 'Email and OTP are required.'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the user with the provided email
            user = User.objects.get(email=email)

            # Check if the OTP matches
            if user.email_otp == int(otp):
                # Mark email as verified
                user.is_email_verified = True
                user.email_otp_verified_at = timezone.now()
                user.save()

                return Response({'status': 'success', 'message': 'Email OTP verified successfully.'}, 
                                status=status.HTTP_200_OK)
            else:
                return Response({'status': 'error', 'message': 'Invalid OTP.'}, 
                                status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({'status': 'error', 'message': 'User not found.'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
class CustomerLoginView(APIView):
    def post(self, request):
        serializer = CustomerLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data['email']
            password = serializer.validated_data['password']
            if not User.objects.filter(email=email).exists():
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "User doesn't exist."}, 
                                status=status.HTTP_400_BAD_REQUEST)
                        
            # Authenticate user
            user = authenticate(email=email, password=password)
            print(user)
            
            if user is not None:
                
                # Check if email is verified
                if not user.is_email_verified:
                    return Response({'status': 'error', 'message': 'Email not verified. Please verify your email first.'}, 
                                    status=status.HTTP_403_FORBIDDEN)
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                return Response({'status': 'success', 'message': 'Login successful',
                                 'data': {'user_role': user.user_role.id, 'access': str(refresh.access_token),
                                          'refresh': str(refresh)}}, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'error', 'message': 'Invalid credentials'}, 
                                status=status.HTTP_401_UNAUTHORIZED)
            
        return Response({'status': 'error', 'message': 'Invalid data', 'errors': serializer.errors}, 
                        status=status.HTTP_400_BAD_REQUEST)


class CustomerForgetPasswordSendMail(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            if not email:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': 'Email is required.'}, 
                            status=status.HTTP_400_BAD_REQUEST)
            
            # Check if the user with the provided email exists
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                
                # Generate the password reset token and URL
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                reset_url = "http://localhost:3000/resetpassword/{0}/{1}".format(uidb64,token)
                
                # Prepare the email context
                ctx = {
                    'user': user.full_name,
                    'email': f"Email : {user.email.lower()}",
                    'url': reset_url,
                    'data1': 'We received a request to reset your password within Quickprop!',
                    'data2': 'If you did not request a password reset, you can safely ignore this email.',
                    'data3': 'To reset your password,',
                    'url_data': 'Reset New Password',
                    'year': datetime.now().year
                }
                
                # Send the email
                subject = 'Forgot Password'
                message = render_to_string('forgot_password_email.html', ctx)
                email_message = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [email])
                email_message.content_subtype = 'html'
                email_message.send()
                
                return Response({'status': status.HTTP_200_OK, 'message': 'Please check your email for the password reset link.'}, 
                                status=status.HTTP_200_OK)
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': 'Invalid Email'}, 
                                status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': str(e)}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
class CustomerForgetPassword(APIView):
    def post(self,request):
        try:
            data=request.data
            uid=request.data['uid']
            token=request.data['token']
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            # Check if new_password and confirm_password are provided
            if not new_password or not confirm_password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': 'New password and confirm password are required.'}, 
                                status=status.HTTP_400_BAD_REQUEST)

            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if user:
                # Validate the token
                if not PasswordResetTokenGenerator().check_token(user, token):
                    return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'Invalid Token.'},
                                    status=status.HTTP_400_BAD_REQUEST)
                else:
                    # Set the new password
                    if new_password==confirm_password:
                        user.set_password(new_password)
                        user.save()
                        return Response({'status': status.HTTP_200_OK,'message': 'Password changed successfully!'},
                                        status=status.HTTP_200_OK)
                    elif new_password != confirm_password:
                        return Response({'status': status.HTTP_400_BAD_REQUEST,'message': "Those password don't match"}, 
                                        status=status.HTTP_400_BAD_REQUEST)                        
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST,'message': "User not found."}, 
                                status=status.HTTP_400_BAD_REQUEST)                        
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST,'message': str(e)}, 
                            status=status.HTTP_400_BAD_REQUEST)