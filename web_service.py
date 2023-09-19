#!/usr/bin/python3
from bottle import route, run, template, request, response
import subprocess,sys,time,socket
import qrcode, zbarlight
from PIL import Image

def vers_8bit(c):
    chaine_binaire = bin(ord(c))[2:]
    return "0"*(8-len(chaine_binaire))+chaine_binaire

def modifier_pixel(pixel, bit):
    # on modifie que la composante rouge
    r_val = pixel[0]
    rep_binaire = bin(r_val)[2:]
    rep_bin_mod = rep_binaire[:-1] + bit
    r_val = int(rep_bin_mod, 2)
    return tuple([r_val] + list(pixel[1:]))

def recuperer_bit_pfaible(pixel):
    r_val = pixel[0]
    return bin(r_val)[-1]

def cacher(image,message):
    dimX,dimY = image.size
    im = image.load()
    message_binaire = ''.join([vers_8bit(c) for c in message])
    posx_pixel = 0
    posy_pixel = 0
    for bit in message_binaire:
        im[posx_pixel,posy_pixel] = modifier_pixel(im[posx_pixel,posy_pixel],bit)
        posx_pixel += 1
        if (posx_pixel == dimX):
            posx_pixel = 0
            posy_pixel += 1
        assert(posy_pixel < dimY)

def recuperer(image,taille):
    message = ""
    dimX,dimY = image.size
    im = image.load()
    posx_pixel = 0
    posy_pixel = 0
    for rang_car in range(0,taille):
        rep_binaire = ""
        for rang_bit in range(0,8):
            rep_binaire += recuperer_bit_pfaible(im[posx_pixel,posy_pixel])
            posx_pixel +=1
            if (posx_pixel == dimX):
                posx_pixel = 0
                posy_pixel += 1
        message += chr(int(rep_binaire, 2))
    return message


#function to send info to sign by the AC
def AC_signature(AC_certificat):
    passphrase='secret'
    tsap=('127.0.0.2',6789)
    infoTosign='info.txt'
    cipher='info.AES'

    #specifying the passphrase
    try:
        certificat=open('AC_certificat.pem','wb')
    except Exception as e:
        print(e.args)
        sys.exit(1)
    
    #encrypt the the file containning the information with AES usin the passphrase
    command1=subprocess.Popen('openssl enc -aes-128-cbc -salt -pass pass:%s -md sha256 -in %s -out %s'%(passphrase,infoTosign,cipher),shell=True,stdout=subprocess.PIPE)
    command1.communicate()
    
    #socket creation
    my_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    my_socket.connect(tsap)
    
    #receiving the AC certificate
    AC_certificat=my_socket.recv(5000)
    certificat.write(AC_certificat)
    certificat.close()


    #extracting the public key from the certificate
    command2=subprocess.Popen('openssl x509 -in AC_certificat.pem -pubkey -noout > keys/AC_public_key.pem',shell=True,stdout=subprocess.PIPE)
    command2.communicate()


    #send the inforamtion encrypted with AES
    try:
        enc_file=open(cipher,'rb')
    except Exception as e:
        print(e.args)
        sys.exit(1)

    enc=b''
    while 1:
        line=enc_file.readline()
        if not line:
            break
        enc+=line
    my_socket.sendall(enc)
    enc_file.close()

    #receive the signature encrypted with AES
    try:
        encrypted_sig=open('signature.AES','wb')
    except Exception as e:
        print(e.args)
        sys.exit(1)
        
    enc_sig=my_socket.recv(10000)
    encrypted_sig.write(enc_sig)
    encrypted_sig.close()

    command4=subprocess.Popen('openssl enc -aes-128-cbc -d -pass pass:%s -md sha256 -in signature.AES -out sign.sig'%passphrase,shell=True,stdout=subprocess.PIPE)
    command4.communicate()

    my_socket.close()


@route('/creation', method='POST')
def création_attestation():
    contenu_identite = request.forms.get('identite')
    contenu_intitule_certification = request.forms.get('intitule_certif')
    info=contenu_identite+'|'+contenu_intitule_certification 
    timestamp=time.time()
    try:
        registerTime=open('time.txt','w')
        dataToSign=open('info.txt','w')
    except Exception as e:
        sys.exit(1)
    dataToSign.write(info)
    dataToSign.close()
    
    #save time
    registerTime.write(str(timestamp))
    registerTime.close()
    
    #timeStamp signature
    query=['openssl','ts','-query','-data','time.txt','-no_nonce','-sha512','-cert','-out','time.tsq']
    subprocess.run(query)
    getCert= ['curl','-H','Content-Type: application/timestamp-query','--data-binary','@time.tsq','https://freetsa.org/tsr','-o','time.tsr']
    subprocess.run(getCert)
    
    #signature by AC
    AC_certificat=b''
    AC_signature(AC_certificat)

    #infromation to hide
    try:
        signed_timestamp=open('time.tsr','rb')
        request_timestampSig=open('time.tsq','rb')
    except Exception as e:
        sys.exit(1)
    req=b''
    while True:
        line=request_timestampSig.readline()
        if not line:
            break
        req+=line
    request_timestampSig.close()

    timeStampSignature=b''
    while True:
        line=signed_timestamp.readline()
        if not line:
            break
        timeStampSignature+=line
    signed_timestamp.close()
    if len(info)!=64:
        for i in range(len(info),65):
            info+='0'
    hideInfo=info+timeStampSignature.hex()+'|'+req.hex()
    

    #base64
    base64=subprocess.Popen('openssl base64 -in sign.sig -out sign.txt',shell=True,stdout=subprocess.PIPE)
    base64.communicate()

    #QRCODE
    try:
        toQr=open('sign.txt','r')
    except Exception as e:
        sys.exit(1)
    line=''
    while 1:
        l=toQr.readline().strip('\n')
        if not l:
            break
        line+=l
    my_file='qrcode.png'
    qr=qrcode.make(line)
    qr.save(my_file,scale=2)
    toQr.close()
    
    
    #downloading the template
    data = 'Certification en|'+contenu_intitule_certification+'|délivrée à|'+contenu_identite
    commande = ['curl', "-o", "texte.png", "http://chart.apis.google.com/chart", "--data-urlencode" ,"chst=d_text_outline" ,"--data-urlencode", 'chld=000000|56|h|FFFFFF|b|'+data]
    commande1 = subprocess.run(commande)
    
    #resize texte
    commande = subprocess.Popen('mogrify -resize 1000x600 texte.png',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commande.communicate()
    commande1 = subprocess.Popen('mogrify -resize 210x210 qrcode.png',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commande1.communicate()
    
    #combine the images
    commande1 = subprocess.Popen('composite -gravity center texte.png fond_attestation.png combinaison.png',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commande1.communicate()
    commande2 = subprocess.Popen('composite -geometry +1418+934 qrcode.png combinaison.png attestation.png',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commande2.communicate() 

    my_image = Image.open("attestation.png")
    cacher(my_image, hideInfo)
    my_image.save('final_img.png')

    print('nom prénom :', contenu_identite, ' intitulé de la certification :',contenu_intitule_certification)
    #response.set_header('Content-type', 'text/plain')
    response.set_header('Content-type', 'image/png')
    #read image
    try:
        img=open('final_img.png','rb')
    except Exception as e:
        sys.exit(1)
    image=b''
    while 1:
        line=img.readline()
        if not line:
            break
        image+=line
    img.close()
    #return the certification
    return image
    

@route('/verification', method='POST')
def vérification_attestation():
    response.set_header('Content-type', 'text/plain') 
    contenu_image = request.files.get('image')
    contenu_image.save('attestation_a_verifier.png',overwrite=True)
    
    #get the QrCode
    attestation = Image.open('attestation_a_verifier.png')
    qrImage = attestation.crop((1418,934,1418+210,934+210))
    qrImage.save("qrcoderecupere.png", "PNG")
    
    #Read the QrCode
    image = Image.open("qrcoderecupere.png")
    data64 = zbarlight.scan_codes(['qrcode'], image)
    data64 = data64[0]
    try:
        Qrout = open('qrout64.txt','w')
    except Exception as e:
        sys.exit(1)
    Qrout.write(data64.decode()+"\n")
    Qrout.close()

    #decoded from base64
    commande = "openssl base64 -d -in qrout64.txt -out signature.sig"
    commande1 = subprocess.Popen(commande,shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commande1.communicate()

    
    #Extract the hidden Information and save them in a file
    try:
        user_information=open('verify/infoToCheck.txt','w')
        timeStampSig=open('verify/timeStampSig.txt','w')
        timeStampReq=open('verify/timeStampReq.txt','w')
    except Exception as e:
        sys.exit(1)
    hidden_info = recuperer(attestation, 64+10986+1+182)
    info=''
    for i in hidden_info:
        if i!='0':
            info+=i
        else:
            break
    
    #save user info
    user_information.write(info)
    user_information.close()

    timeStampInfos=hidden_info[65:].split('|')
    
    #save timeStamp signature
    timeStampSignature=timeStampInfos[0]
    timeStampSig.write(timeStampSignature+'\n')
    timeStampSig.close()

    #save timeStamp request
    timeStampRequest=timeStampInfos[1]
    timeStampReq.write(timeStampRequest+'\n')
    timeStampReq.close()

    #Check the user info signature
    veri_commande = "openssl dgst -sha256 -verify keys/AC_public_key.pem -signature sign.sig verify/infoToCheck.txt"
    veri_commande1 = subprocess.Popen(veri_commande,shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout,stderr=veri_commande1.communicate()
    if stdout.decode().strip('\n')=='Verified OK':
        qr_sig = True
    else:
        qr_sig = False
    
    #check timeStasmp signature
    commande = ["openssl ts -verify -in time.tsr -queryfile time.tsq -CAfile tsp_cert/cacert.pem" ,"-untrusted" , "tsp_cert/tsa.crt" ]
    commande1 = subprocess.Popen(commande, shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    stdout,stderr = commande1.communicate()
    
    if stdout.decode().strip('\n')=='Verification: OK':
        tsp_sig = True
    else:
        tsp_sig = False

    if qr_sig == False or tsp_sig == False:
        return "Verification failed!\n "
    else:
        return "Verification is OK! \n"

@route('/fond')
def récupérer_fond():
    response.set_header('Content-type', 'image/png')
    descripteur_fichier = open('fond_attestation.png','rb')
    contenu_fichier = descripteur_fichier.read()
    descripteur_fichier.close()
    return contenu_fichier

run(host='0.0.0.0',port=8080,debug=True)

