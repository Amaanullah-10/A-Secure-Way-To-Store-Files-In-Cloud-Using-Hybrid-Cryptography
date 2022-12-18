from django.shortcuts import render,redirect
from django.contrib import messages
from .models import *
from django.contrib.sessions.models import Session
import datetime
from datetime import datetime
import sys
import numpy as np
from PIL import Image
from django.db.models import Avg, Max, Min, Sum, Count
import requests 
from cryptography.fernet import Fernet
import base64
import os
from django.conf import settings
from django.http import HttpResponse, Http404
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.core.files.storage import FileSystemStorage
from datetime import date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from Crypto.Cipher import ARC2
from Crypto import Random
import pyaes, pbkdf2, binascii, os, secrets

from Crypto.Cipher import DES
import hashlib
# https://asecuritysite.com/encryption/padding_des_salt
import sys
import binascii
import Padding
import base64

import docx
import math
import ftplib
import smtplib
import mimetypes
from email.message import EmailMessage
from django.core.mail import send_mail
import smtplib
import imghdr
from email.message import EmailMessage

# Fill Required Information
FTP_URL = "182.50.132.7"
FTP_User = "adocshare"
Password = "wu026Ek*"

# Connect FTP Server
ftp_server = ftplib.FTP(FTP_URL, FTP_User, Password)
 
# force UTF-8 encoding
ftp_server.encoding = "utf-8"


# Create your views here.
def home(request):
    if request.method == 'POST':
        pass
    else:
        return render(request, 'home.html', {})


def User_login(request):
    if request.method == 'POST':
        Username = request.POST['Username']
        password = request.POST['password']
        
        if User_Details.objects.filter(Username=Username, Password=password).exists():
            user = User_Details.objects.get(Username=Username, Password=password)
            request.session['User_id'] = str(user.id)
            request.session['type_id'] = 'User'
            request.session['username'] = Username
            request.session['login'] = 'Yes'
            return redirect('/FileUpload/')
        else:
            messages.info(request,'Invalid Credentials')
            return redirect('/User_login/')

    else:
        return render(request, 'User_login.html', {})




def Register(request):
    if request.method == 'POST':           
        First_name = request.POST['First_name']
        Last_name = request.POST['Last_name']
        Username = request.POST['Username']
        Dob = request.POST['Dob']
        Gender = request.POST['Gender']
        Phone = request.POST['Phone']
        Email = request.POST['Email']
        Password = request.POST['Password']
        final_address = request.POST['Address1']
        City = request.POST['City']
        State = request.POST['State']
        register = User_Details( First_name=First_name, Last_name=Last_name, Dob=Dob, Gender=Gender ,Phone= Phone,Email= Email,Username= Username,Password=Password,Address=final_address,City=City,State=State)
        register.save()
        messages.info(request,'User Register Successfully')
        return redirect('/User_login/')
    else:
        return render(request, 'Register.html', {})


def logout(request):
    Session.objects.all().delete()
    messages.info(request,'Account logout')
    return redirect('/')


def FileUpload(request):
    if request.method == 'POST':
        Username = request.POST['Users']
        filename = request.FILES['fileupload']
        name = filename.name
        print(name)
        Password1 = request.POST['password']
        image = request.FILES['image']
        name1 = image.name
        print(name1)
        password1 = Password1
        FileString = ""

        #today = date.today()
        #encDate = today.strftime("%d-%m-%Y")

        
        now = datetime.now()
        encDate = now.strftime("%d-%m-%Y-%H-%M-%S")
        print("date and time:",encDate)

        UserID=request.session['User_id']

        fs = FileSystemStorage()
        #save file
        filename = fs.save("document/"+filename.name, filename)
        input_file = "media/document/"+name
        extesion = os.path.splitext(str(request.FILES['fileupload']))[1]
        #print('ext',extesion)

        if extesion == ".txt":
            f = open(input_file,'rb')
            FileString = f.read()
            
        elif extesion == ".docx":
            doc = docx.Document(input_file)  # Creating word reader object.
            fullText = []
            for para in doc.paragraphs:
                fullText.append(para.text)
                FileString = '\n'.join(fullText)
     
        #print('FileString',FileString)
        lengths = len(FileString)
        leng = lengths / 3
        NaturalNumber = math.floor(leng)

        #Devide Sting into 3 parts
        some_string=FileString
        x=int(NaturalNumber)+1
        res=[some_string[y-x:y] for y in range(x, len(some_string)+x,x)]

        print("res[0]",res[0])
        print("res[1]",res[1])
        print("res[2]",res[2])

        print('Type of Res',type(res))


        #AES Encryption

        aesstring = res[0]
        enckey = b'\xc9z*a\xd3Q[\rQ\x06oA\xb5\x0bZ\x8c\x94\x10<g\xa8\x1a\x86\x1f\xe8h\xd3\xddo\x0f.\xe9'
        iv = 55370894526525431444462074447914484483528008490751812436704349847140773044585



        plaintext = aesstring
        aes = pyaes.AESModeOfOperationCTR(enckey, pyaes.Counter(iv))
        AesCiphertext = aes.encrypt(plaintext)
        print('AesCiphertext:', AesCiphertext)

        print('Type of AES Encrypted:', type(AesCiphertext))
        print('AES Encrypted:', binascii.hexlify(AesCiphertext))

        AesoutFilename = "AESenc_"+encDate+'_'+UserID+'_'+name 
        print('AesoutFilename',AesoutFilename)
        #Aesoutput_file = "G:/priya_backup/Surya Projects/Surya Backup/Django_MySql/SecureFileStorage_Hybrid/AppSecureHybrid/"+AesoutFilename
        Aesoutput_file = "media/document/encrypted/Aes/"+ AesoutFilename
        print(Aesoutput_file)
        with open(Aesoutput_file, 'wb') as f:
            f.write(AesCiphertext)

        ftp_server = ftplib.FTP(FTP_URL, FTP_User, Password)
        ftp_server.cwd("Documents/Encrypted/AES")
        #fnames = ftp_server.nlst()
        #print(fnames)
        # Enter File Name with Extension
        #root = "G:/priya_backup/Surya Projects/Surya Backup/Django_MySql/SecureFileStorage_Hybrid/AppSecureHybrid/"
        # Read file in binary mode
        with open(Aesoutput_file, "rb") as file:
        # Command for Uploading the file "STOR filename"
            ftp_server.storbinary(f"STOR {AesoutFilename}",file)
            ftp_server.cwd("../")
            #ftp_server.quit()
        #DES Encryption     
        
        val=res[1]
        password=password1
        salt='12345678'
        plaintext=val
        
        if type(plaintext) is bytes:
            Finalplaintext = plaintext.decode("utf-8")
        else:
            Finalplaintext = plaintext



        def encrypt(Finalplaintext,key, mode,salt):
            encobj = DES.new(deskey,mode,salt)
            return(encobj.encrypt(Finalplaintext))

        print("\nDES")
        deskey = hashlib.sha256(password.encode()).digest()[:8]
        print('deskey' ,deskey)
        Finalplaintext = Padding.appendPadding(Finalplaintext,blocksize=Padding.DES_blocksize,mode='CMS')
        DesCiphertext = encrypt(Finalplaintext.encode(),deskey,DES.MODE_CBC,salt.encode())
        DesoutFilename = "DESenc_"+encDate+'_'+UserID+'_'+name 
        Desoutput_file = "media/document/encrypted/Des/"+DesoutFilename

        with open(Desoutput_file, 'wb') as f:
            f.write(DesCiphertext)
        ftp_server.cwd("DES")
        with open(Desoutput_file, "rb") as file:
            # Command for Uploading the file "STOR filename"
            ftp_server.storbinary(f"STOR {DesoutFilename}",file)
            ftp_server.cwd("../")
            #ftp_server.quit()

        #ARC2 Encryption
        strdata = res[2]
        print(strdata)
        '''if type(strdata) is str:
            data = str.encode(strdata)
        else:
            data = strdata'''
        key = os.urandom(32)
        print(key)
        A_iv = Random.new().read(ARC2.block_size)
        print(A_iv)
        cipher = ARC2.new(key, ARC2.MODE_CFB, A_iv)
        ciphertext = A_iv + cipher.encrypt(strdata)
        print(ciphertext)
        print("ARC2 Encrypted",ciphertext)
        print('Type of ARC2 Encrypted:', type(ciphertext))

        ARC2soutFilename = "ARC2enc_"+encDate+'_'+UserID+'_'+name 
        #ARC2output_file = "G:/priya_backup/Surya Projects/Surya Backup/Django_MySql/SecureFileStorage_Hybrid/AppSecureHybrid/"+ARC2soutFilename
        ARC2output_file = "media/document/encrypted/ARC2/"+ ARC2soutFilename

        with open(ARC2output_file, 'wb') as f:
            f.write(ciphertext)

        ftp_server.cwd("ARC2")
        with open(ARC2output_file, "rb") as file:
        # Command for Uploading the file "STOR filename"
            ftp_server.storbinary(f"STOR {ARC2soutFilename}",file)
            #ftp_server.cwd("../")
            #ftp_server.quit()


        #IMAGE STEGNOGRAPHY
        fs = FileSystemStorage()
        filename = fs.save("img/images/"+image.name, image)
        src = "media/img/images/" + name1
        ENC_img = "ENC_"+encDate+'_'+UserID+'_'+name1
        dest ="media/img/images/Encrypted/" + ENC_img

        print(dest)
        img = Image.open(src, 'r')
        print(img)
        width, height = img.size
        array = np.array(list(img.getdata()))

        if img.mode == 'RGB':
            n = 3
        elif img.mode == 'RGBA':
            n = 4

        total_pixels = array.size//n

        password1 += "$t3g0"
        b_message = ''.join([format(ord(i), "08b") for i in password1])
        print(b_message)
        req_pixels = len(b_message)
        print(req_pixels)

        if req_pixels > total_pixels:
            print("ERROR: Need larger file size")

        else:
            index=0
            for p in range(total_pixels):
                for q in range(0, 3):
                    if index < req_pixels:
                        array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
                        index += 1

            array=array.reshape(height, width, n)
            enc_img = Image.fromarray(array.astype('uint8'), img.mode)
            enc_img.save(dest)
            print("Image Encoded Successfully")
        ToUser = User_Details.objects.all().filter(First_name=Username)  
        fid = ToUser[0].id
        f_email = ToUser[0].Email
        print(f_email)
        Sender_Email = "python2projects@gmail.com"
        Passwords = "python@21@"
        Reciever_Email = f_email
        print(Reciever_Email)
        newMessage = EmailMessage()                         
        newMessage['Subject'] = "Check out the Key" 
        newMessage['From'] = Sender_Email                   
        newMessage['To'] = Reciever_Email                   
        newMessage.set_content('This is the encrypted image.') 
        with open(dest, 'rb') as f:
            image_data = f.read()
            image_type = imghdr.what(f.name)
            image_name = f.name
            image_name = image_name.split('/')
            image_name = image_name[4]
            print(image_name)

        newMessage.add_attachment(image_data, maintype='image', subtype=image_type, filename=image_name)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
    
            smtp.login(Sender_Email, Passwords)              
            smtp.send_message(newMessage)
       





        today = date.today()
        encDate = today.strftime("%d/%m/%Y")


        
        ToUser = User_Details.objects.all().filter(First_name=Username)  
        fid = ToUser[0].id
        f_email = ToUser[0].Email
        register = FileDetails( SenderId = UserID,ReceiverId = fid,Filename = name,Image = ENC_img,AES = AesoutFilename,DES = DesoutFilename,ARC2 = ARC2soutFilename,Password = Password1,ARC2key = key,ARC2IV = A_iv )
        register.save()
        messages.info(request,'File Encrypted')
        return redirect('/FileUpload/')
    else:
        u_id = request.session['User_id'] 
        Users = User_Details.objects.all().exclude(id=u_id)
        return render(request, "FileUpload.html",{'Users':Users})




def decrypt(request):
    if request.method == 'POST': 
        Id = request.POST['hfId']
        print('Id',Id)
        filename = request.POST['hffilename']
        print('filename',filename)
        hfpassword = request.POST['hfpassword']
        print('hfpassword',hfpassword)
        Encode_img = request.FILES['encimg']
        print(Encode_img)


        #password1 = request.FILES['encimg']
        name2 = Encode_img.name
        name3 = name2.split('_')
        print(name3)
        print('Encode_img',name2)

        #img = password1
        src = "media/img/images/Encrypted/" + name2
        print(src)
        img = Image.open(src, 'r')
        array = np.array(list(img.getdata()))

        if img.mode == 'RGB':
            n = 3
        elif img.mode == 'RGBA':
            n = 4

        total_pixels = array.size//n

        hidden_bits = ""
        for p in range(total_pixels):
            for q in range(0, 3):
                hidden_bits += (bin(array[p][q])[2:][-1])

        hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]
        #print(hidden_bits)
        message = ""
        print(message)
        for i in range(len(hidden_bits)):
            if message[-5:] == "$t3g0":
                print(message[-5:])
                break
            else:
                message += chr(int(hidden_bits[i], 2))
        if "$t3g0" in message:
            print("Hidden Message:", message[:-5])
        else:
            print("No Hidden Message Found")




        if hfpassword == message[:-5]:
            File = FileDetails.objects.all().filter(id=Id) 
            AesEnc = File[0].AES
            print('AesEnc',AesEnc)
            DesEnc = File[0].DES
            print('DesEnc',DesEnc)
            ARC2Enc = File[0].ARC2
            print('ARC2Enc',ARC2Enc)
            ARC2_key = File[0].ARC2key
            print(ARC2_key)
            #print(bytes(ARC2_key1,"utf-8"))

            '''FernetEnc = File[0].FERNET
            print('FernetEnc',FernetEnc)'''

            #Aes Decryption

            enckey = b'\xc9z*a\xd3Q[\rQ\x06oA\xb5\x0bZ\x8c\x94\x10<g\xa8\x1a\x86\x1f\xe8h\xd3\xddo\x0f.\xe9'
            #print('AES encryption key:', binascii.hexlify(key))

            #iv = secrets.randbits(256)
            iv = 55370894526525431444462074447914484483528008490751812436704349847140773044585
            print('decrypt iv',iv)

            #Aes Decryption
            Filenames = AesEnc
            ftp_server = ftplib.FTP(FTP_URL, FTP_User, Password)
            #Filenames_file = "media/document/encrypted/Aes/"+Filenames
            ftp_server.cwd("Documents/Encrypted/AES")
            #fnames = ftp_server.nlst()
            #print(fnames)
            # Enter File Name with Extension
            filename = Filenames
            # Read file in binary mode
            with open(filename, "wb") as file:
            # Command for Downloading the file "RETR filename"
                ftp_server.retrbinary(f"RETR {filename}", file.write)
                file= open(filename, "r")
                print('File Content:', file.read())
                ftp_server.cwd("../")

            with open(filename, 'rb') as q:
                data = q.read()

            print("Aes data",data)

            aesde = pyaes.AESModeOfOperationCTR(enckey, pyaes.Counter(iv))
            AesDecrypted = aesde.decrypt(data)
            print('AES Decrypted:', AesDecrypted)



            #DES Encryption     
        
            password=message[:-5]
            salt='12345678'
            
            def decrypt(ciphertext,key, mode,salt):
                encobj = DES.new(deskey,mode,salt)
                return(encobj.decrypt(ciphertext))

            deskey = hashlib.sha256(password.encode()).digest()[:8]

            DesoutFilename = DesEnc
            #Desoutput_file = "media/document/encrypted/Des/"+DesoutFilename

            ftp_server.cwd("DES")
            #fnames = ftp_server.nlst()
            #print(fnames)
            # Enter File Name with Extension
            filename = DesoutFilename
            # Read file in binary mode
            with open(filename, "wb") as file:
            # Command for Downloading the file "RETR filename"
                ftp_server.retrbinary(f"RETR {filename}", file.write)
                file= open(filename, "r")
                print('File Content:', file.read())
                ftp_server.cwd("../")

            #Des Decryption
            with open(filename, 'rb') as f:
                Desdata = f.read()


            Finalplaintext = decrypt(Desdata,deskey,DES.MODE_CBC,salt.encode())
            Des_Decrypttext = Padding.removePadding(Finalplaintext.decode(),mode='CMS')
            print("Des decrypt: "+Des_Decrypttext)

            #ARC2 Decryption
            password_provided = message[:-5]
            ARC2outFilename = ARC2Enc
            #ARC2output_file = "media/document/encrypted/ARC2/"+ARC2outFilename

            ftp_server.cwd("ARC2")
            #fnames = ftp_server.nlst()
            #print(fnames)
            # Enter File Name with Extension
            filename = ARC2outFilename
            # Read file in binary mode
            with open(filename, "wb") as file:
            # Command for Downloading the file "RETR filename"
                ftp_server.retrbinary(f"RETR {filename}", file.write)
                file= open(filename, "r")
                print('File Content:', file.read())
                ftp_server.cwd("../")
                #ftp_server.quit()

            with open(filename, 'rb') as f:
                ARC2data = f.read()
                print(ARC2data)



            iv = ARC2data[:ARC2.block_size]
            ARC2data = ARC2data[ARC2.block_size:]

            cipher = ARC2.new(ARC2_key,ARC2.MODE_CFB, iv)
            text = cipher.decrypt(ARC2data).decode("utf-8")

            print('Decrypted',text)






            '''#Fernet Encryption        
            password_provided = password1
            password = password_provided.encode() 
            salt = b'salt_'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)



            FernetsoutFilename = FernetEnc
            Fernetoutput_file = "media/document/encrypted/Fernet/"+FernetsoutFilename



            with open(Fernetoutput_file, 'rb') as f:
                Fernetdata = f.read()

            fernet = Fernet(key)
            Fernetdecrypted = fernet.decrypt(Fernetdata)
            print("Fernet Decrypted",Fernetdecrypted)'''

            encoding = 'utf-8'


            answers = str(AesDecrypted, encoding) + str(Des_Decrypttext) + str(text)
            print("answers",answers)


            outFilename = "dec_"+filename
            output_file = "media/document/decrypted/"+outFilename


            with open(output_file, 'w') as f:
                f.write(answers)


            path = "document/decrypted/"+outFilename
            file_path = os.path.join(settings.MEDIA_ROOT, path)
            print(file_path)

            if os.path.exists(file_path):
                with open(file_path, 'rb') as fh:
                    response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
                    response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
                    return response




            messages.info(request,'File Decrypted')
            return redirect('/ViewFiles/')
        else:
            messages.info(request,'Password doesnt Match')
            return redirect('/ViewFiles/')
    else:
        return redirect('/ViewFiles/')

    

def ViewFiles(request):
    if request.method == 'POST':
        pass
    else:
        u_id = request.session['User_id'] 
        Files = FileDetails.objects.all().filter(ReceiverId=u_id) 
        return render(request, 'ViewFiles.html', {'Files':Files})


def FileDetail(request,id):
    if request.method == 'POST':
        pass
    else:
        filedetails = FileDetails.objects.get(id=id)
        return render(request, 'FileDetails.html', {'filedetails':filedetails})


        