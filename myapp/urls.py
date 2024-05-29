from django.urls import path
from myapp.views import RegistrationView, ActivateView, ActivationConfirm, GetCSRFToken, LoginView, LogoutView, UserDetailView, ChangePassword, DeleteAccountView, ResetPassword, ResetPasswordView, ResetPasswordConfirmView, CheckAuthenticatedView

urlpatterns = [
    path('myapp/csrf_cookie/', GetCSRFToken.as_view(), name='csrf_cookie'),
    path('myapp/registration/', RegistrationView.as_view(), name='register'),
    path('myapp/activate/<str:uid>/<str:token>/', ActivateView.as_view(), name='activate'),
    path('myapp/activate/', ActivationConfirm.as_view(), name='activation_confirm'),
    path('myapp/login/', LoginView.as_view(), name='login'),
    path('myapp/user/', UserDetailView.as_view(), name='user_detail'),
    path('myapp/change_password/', ChangePassword.as_view(), name='changepw'),
    path('myapp/delete_user/', DeleteAccountView.as_view(), name='delete'),
    path('myapp/logout/', LogoutView.as_view(), name='logout'),
    path('myapp/reset_password/', ResetPassword.as_view(), name='reset_password_email'),
    path('myapp/resetpassword/<str:uid>/<str:token>/', ResetPasswordView.as_view(), name='reset_password'),
    path('myapp/reset_password_confirm/', ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    path('myapp/checkauth/', CheckAuthenticatedView.as_view(), name='check_auth'),
]