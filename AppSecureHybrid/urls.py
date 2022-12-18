from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('User_login/', views.User_login, name='User_login'),
    path('Register/', views.Register, name='Register'),
    path('logout/', views.logout, name='logout'),
    path('FileUpload/', views.FileUpload, name='FileUpload'), 
    path('ViewFiles/', views.ViewFiles, name='ViewFiles'),
    path('decrypt/', views.decrypt, name='decrypt'),  
    path('FileDetail/<int:id>', views.FileDetail, name='FileDetail'),       
]
  