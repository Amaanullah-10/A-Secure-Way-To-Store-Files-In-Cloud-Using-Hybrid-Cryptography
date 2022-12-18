from django.db import models

class Admin_Details(models.Model):
    Username = models.CharField(max_length=100)
    Password = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'Admin_Details'  

class User_Details(models.Model):
    First_name = models.CharField(max_length=50)
    Last_name = models.CharField(max_length=50)
    Dob = models.CharField(max_length=50,default=None)
    Gender = models.CharField(max_length=10)
    Phone = models.IntegerField(default=None)
    Email = models.EmailField()
    Username = models.CharField(max_length=100)
    Password = models.CharField(max_length=100)
    Address = models.CharField(max_length=100)
    City = models.CharField(max_length=100)
    State = models.CharField(max_length=100)

        
    class Meta:
        db_table = 'User_Details'


class FileDetails(models.Model):
    SenderId = models.CharField(max_length=255, blank=True)
    ReceiverId = models.CharField(max_length=255, blank=True)
    Filename = models.CharField(max_length=500, blank=True)
    AES = models.TextField(default=None)
    DES = models.TextField(default=None)
    #FERNET = models.TextField(default=None)
    Image = models.ImageField(upload_to='media/img/images/Encrypted/',default=None)
    ARC2 = models.TextField(default=None)
    Password = models.CharField(max_length=500, blank=True)
    ARC2key = models.BinaryField()
    ARC2IV = models.BinaryField() 

    class Meta:
        db_table = 'FileDetails'
