from django.shortcuts import get_object_or_404, render

from users.models import CustomUser
from .serializers import CustomUserSerializer
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from django.core.mail import send_mail
import secrets

class SignUpView(generics.CreateAPIView):
    serializer_class = CustomUserSerializer
    authentication_classes = []  # Desactiva la autenticación para esta vista
    permission_classes = [AllowAny]  # Permite todas las solicitudes sin autenticación

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save(is_active=False)

        # Genera token de confirmación y envia email
        user.confirmation_token = secrets.token_urlsafe(32)
        user.username = user.email
        user.save()

        subject = 'Confirma tu cuenta'
        message = f'Por favor, sigue este enlace para confirmar tu cuenta: http://127.0.0.1:8000/api/confirm/{user.confirmation_token}'

        try:
            send_mail(subject, message, 'hitzseb.test@gmail.com', [user.email], fail_silently=False)
        except Exception as e:
            return Response({'error': 'Error al enviar el correo electrónico de confirmación'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Hemos enviado un email de confirmación a tu correo. Por favor confirma para usar tu cuenta.'}, status=status.HTTP_201_CREATED)
    
class ConfirmEmailView(APIView):
    permission_classes = [AllowAny]  # Permite todas las solicitudes sin autenticación

    def get(self, request, *args, **kwargs):
        try:
            token = kwargs.get('token')  # Obtiene el token de los parámetros de la URL
            user = get_object_or_404(CustomUser, confirmation_token=token)

            # Activa la cuenta del usuario
            user.is_active = True
            user.confirmation_token = ''  # Borra el token
            user.save()
            
            # Usa SimpleJWT para crear tokens refresh y access
            refresh = RefreshToken.for_user(user)
            tokens = {'refresh': str(refresh), 'access': str(refresh.access_token)}

            response_data = {'message': 'Cuenta confirmada exitosamente', 'tokens': tokens}
            return Response(response_data, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Token inválido'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Error al confirmar la cuenta'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)