from Crypto import Random
from Crypto.Cipher import AES
import PIL.Image
import wave
from tkinter import *
import tkinter as tk
from tkinter import filedialog, Text, simpledialog, messagebox
import numpy as np
import struct
import os

#AES şifreleme

# AES anahtarı
key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'

# gerekli box size için mesaja ekleme yapar. 's' kullanıcı mesajı. 
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)                          #mesajı doğru block size'a çevir
    iv = Random.new().read(AES.block_size)          #iv = initialization vector. saldırılara karşı random veri katar
    cipher = AES.new(key, AES.MODE_CBC, iv)         #şifrelemeyi tapacak asıl cipher'ın oluşturma
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")                                      #mesajı padlerden arındırma

# dosya şifrele
def encrypt_file(file_name, key):
    with open(file_name, 'rb') as f: # dosyayı açıp binary olarak oku
        plaintext = f.read() # dosyadaki texti sakla
    enc= encrypt(plaintext, key) # texti şifrele
    with open(file_name + ".enc", 'wb') as f: # .enc uzantılı yeni dosya yarat ve binary olarak yaz
        f.write(enc) # enc ciphertext'i yeni dosyada yaz veya yerleştir
    
# dosya şifre çöz
def decrypt_file(file_name, key):
    with open(file_name, 'rb') as f: # dosyayı aç, binary olarak oku
        ciphertext = f.read() # dosyadan ciphertexti sakla
    dec = decrypt(ciphertext, key) # şifresi çözülmüş metni dec değişkeninde sakla
    with open(file_name[:-4], 'wb') as f: # orjinal text dosyasını aç, binary olarak yaz
        f.write(dec) # şifresi çözülmüş metni text dosyasına yaz

# kullanıcıdan text dosyası alma
def load_text_file():
    global key, filename
    text_file = filedialog.askopenfile(filetypes=[('Metin Dosyaları', 'txt'), ('Şifrelenmiş', 'enc')]) 
    if text_file.name != None: 
        filename = text_file.name # global filename değişkenini seçilmiş dosyanın adıyla değiştir

filename = None

#these gui button functions are written for gui window. in the command paramater we give the name of a function
# but we do not put paranthesis and since that is the case, we cant have any arguments in the function that runs
# when we click those buttons. therefore we need another function that actually call that function we need to run

# gui button
def encrypt_the_file():
    global key, filename
    if filename != None:
      encrypt_file(filename, key)
    else: 
        messagebox.showerror(title="Hata:", message="Dosya yüklenmedi.") 

# gui button
def decrypt_the_file():
    global key, filename
    if filename != None: 
        fname = filename + '.enc'
        decrypt_file(fname, key)
    else:
        messagebox.showerror(title="Hata:", message="Dosya yüklenmedi.")

# GÖRSEL STEG 

def genData(data):
    # girilen verinin binary kod listesi
    newd = []

    for i in data:
        newd.append(format(ord(i), '08b'))
    return newd
def modPix(pix, data):
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):
        pix = [value for value in imdata.__next__()[:3] +
               imdata.__next__()[:3] +
               imdata.__next__()[:3]]
        for j in range(0, 8):
            if (datalist[i][j] == '0') and (pix[j] % 2 != 0):

                if (pix[j] % 2 != 0):
                    pix[j] -= 1

            elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                pix[j] -= 1
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                pix[-1] -= 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

def encode():
    img = encode_popup()
    image = PIL.Image.open(img, 'r')

    data_input= data_popup()
    if (len(data_input) == 0):
        raise ValueError('Boş!')

    newimg = image.copy()
    encode_enc(newimg, data_input)

    new_img_name = new_image_popup()
    newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

def decode():
    img = decode_popup()
    image = PIL.Image.open(img, 'r')

    data = ''
    imgdata = iter(image.getdata())

    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                  imgdata.__next__()[:3] +
                  imgdata.__next__()[:3]]
        binstr = ''

        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'

        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            return data
        
# GUI

root = tk.Tk()
root.title("AES + Steganografi.")

#canvas = tk.Canvas(root, height=300, width=300, bg="#FF9FCE")
#canvas.pack()

def encode_popup():
    image_name=simpledialog.askstring("Şifrele.","Görsel ismini uzantısıyla beraber yazınız.")
    return image_name
def data_popup():
    data=simpledialog.askstring("Metin Girişi.","Şifrelenecek metni giriniz.")
    return data
def new_image_popup():
    new_image=simpledialog.askstring("Şifrele.","Yeni görselin ismini uzantısıyla beraber yazınız.")
    return new_image
def decode_popup():
    decode_image=simpledialog.askstring("Şifre Çöz.","Şifresi çözülecek görselin ismini uzantısıyla beraber yazınız.")
    return decode_image
def output():
    f = open( 'görsel_steg_çıktı.txt', 'w' )
    f.write(decode())
    f.close()

head=tk.Label(root,text="\nAES ŞİFRELEME\n",bg="#FF9FCE",fg="black")
head.pack(padx=10)
loadButton = tk.Button(root, text="Metin yükle.", width=15, padx=0, pady=2, fg="black", bg="#FF9FCE", command=load_text_file)
loadButton.pack()

encryptButton = tk.Button(root, text="AES şifre.",width=15, padx=0, pady=2, fg="black", bg="#FF9FCE", command=encrypt_the_file)
encryptButton.pack()

decryptButton = tk.Button(root, text="AES deşifre.",width=15, padx=0, pady=2, fg="black", bg="#FF9FCE", command=decrypt_the_file)
decryptButton.pack()

close=tk.Button(root,text="Çıkış.",width=15, padx=0, pady=2, fg="black", bg="#FF9FCE",command=root.destroy)
encoding=tk.Button(root,text="Görsel steg şifre.",width=15, padx=0, pady=2, fg="black", bg="#FF9FCE",command=encode)
decoding=tk.Button(root,text="Görsel steg deşifre.",width=15, padx=0, pady=2, fg="black", bg="#FF9FCE",command=output)

w=tk.Label(root, text="\n \n",bg="#FF9FCE",fg="black")
head=tk.Label(root, text="\nGÖRSEL STEGANOGRAFİ\n", bg="#FF9FCE", fg="black")
head.pack(padx=10)
encoding.pack()
decoding.pack()
w.pack(padx=0)
close.pack()
root.configure(background="#FF9FCE")
root.geometry("400x400")

root.mainloop()

class Application(Frame):
    container = 0
    information = 0
    information_ext = 0
    information_ext_bits = ''
    information_ext_len = ''
    information_ext_len_bits = ''
    bytes_arr = []
    bytes_arr_len = 0
    bytes_arr_len_bits = 0
    maxInfo = 0
    infolen = 0
    infoLenTMP = 0
    infoString = ''
    infoHeader = 0
    maxFrames = 0

    def __init__(self, root):
        Frame.__init__(self, root, bg="#FF9FCE")
        self.master.title('Ses Steganografisi')
        self.maxInfoLabelText = StringVar()
        self.mainFrame = Frame(root).grid(row=0)
        self.fileFrame = Frame(root).grid(row=1)
        self.hideFrame = Frame(root)
        self.ButtonLSB = Button(self.hideFrame, text="LSB başlat.", command=lambda: self.lsb()).grid(column=1, row=5, sticky=E)
        

        self.LabelContainerButton = Label(self.fileFrame, text="Ses dosyası yükle:")
        self.ContainerButton = Button(self.fileFrame, text="Ses dosyası", command=lambda: self.openfile())
        self.LabelContainerButton.grid(row=1, column=0, sticky=E)
        self.ContainerButton.grid(row=1, column=1, sticky=W)

        self.LabelInfoButton = Label(self.fileFrame, text="Saklanacak veri yükle:")
        self.InfoButton = Button(self.fileFrame, text="Saklanacak veri", command=lambda: self.open_any_file())
        self.LabelInfoButton.grid(row=2, column=0, sticky=E)
        self.InfoButton.grid(row=2, column=1, sticky=W)

        self.LabelHiddenButton = Label(self.fileFrame, text="Veri çıkar:")
        self.HiddenButton = Button(self.fileFrame, text="Dosya seç", command=lambda: self.read_hidden_data())
        self.LabelHiddenButton.grid(row=3, column=0, sticky=E)
        self.HiddenButton.grid(row=3, column=1, sticky=W)
        self.maxInfoLabel = Label(self.fileFrame, textvariable=self.maxInfoLabelText)
        self.maxInfoLabel.grid(column=0, row=4, sticky=W)

    def lsb(self):
        print("BAŞLA!")
        self.container.rewind()
        newFile = wave.open('çıktı.wav', 'wb')
        newFile.setparams(self.container.getparams())
        newFile.setframerate(newFile.getframerate())

        # Gizleme işlemi

        for i in range(0, self.maxFrames, 1):
            frame = self.container.readframes(1)
            frame_int = int.from_bytes(frame, byteorder='big')
            if 1 <= i < 33:                                                                                      # veri uzunluğu saklama
                if int(self.bytes_arr_len_bits[i-1]) == 0:
                    frameNew = self.zero_lbs(frame_int)
                else:
                    frameNew = self.one_lsb(frame_int)

            elif 33 <= i <= 64:                                                                                  # uzantı uznluğu saklama
                if int(self.information_ext_len_bits[i-33]) == 0:
                    frameNew = self.zero_lbs(frame_int)
                else:
                    frameNew = self.one_lsb(frame_int)

            elif 65 <= i <= 65 + self.information_ext_len:                                                            # uzantı saklama
                if int(self.information_ext_bits[i-66]) == 0:
                    frameNew = self.zero_lbs(frame_int)
                else:
                    frameNew = self.one_lsb(frame_int)

            elif 66 + self.information_ext_len <= i <= 66 + self.information_ext_len + self.bytes_arr_len:
                if int(self.bytes_arr[i-67 - self.information_ext_len]) == 0:                                             # veri saklama
                    frameNew = self.zero_lbs(frame_int)
                else:
                    frameNew = self.one_lsb(frame_int)

            else:
                frameNew = self.zero_lbs(frame_int)

            frame = frameNew.to_bytes(4, byteorder='big')
            newFile.writeframes(frame)

        print("TAMAMLANDI!")
        newFile.close()

    @staticmethod
    def zero_lbs(number):

        if number % 2 == 0:
            LSBZero = number
        else:
            LSBZero = number - 1

        return LSBZero

    @staticmethod
    def one_lsb(number):

        if number % 2 == 1:
            LSBOne = number
        else:
            LSBOne = number + 1
        return LSBOne

    def openfile(self):
        f = wave.open(filedialog.askopenfilename(filetypes=(("Ses Dosyaları", "*.wav"),
                                                            ("Tüm dosyalar", "*.*"))), 'rb')
        self.container = f
        self.maxInfo = f.getnframes()
        self.maxInfoLabelText.set("LSB yöntemi ile" + str(self.maxInfo) + " bit saklanabilir.")
        print(self.maxInfoLabelText.get())
        self.maxFrames = self.container.getnframes()

        if self.container != 0 and self.information != 0:
            if self.maxInfo < self.infolen * 16:
                self.maxInfoLabelText.set('Dosya çok küçük!')
            else:
                self.maxInfoLabel.grid_forget()
                self.hideFrame.grid(row=5, column=0, sticky=W)

    def infotobits(self, file_string):
        self.infoString = ""
        for i in range(self.infolen):
            stringbit = ''
            stringTMP = ''
            charTMP = int(ord(file_string[i]))
            for j in range(8):
                stringTMP += str(int(charTMP % 2))
                charTMP /= 2
            stringbit += stringTMP[15]
            stringbit += stringTMP[14]
            stringbit += stringTMP[13]
            stringbit += stringTMP[12]
            stringbit += stringTMP[11]
            stringbit += stringTMP[10]
            stringbit += stringTMP[9]
            stringbit += stringTMP[8]
            stringbit += stringTMP[7]
            stringbit += stringTMP[6]
            stringbit += stringTMP[5]
            stringbit += stringTMP[4]
            stringbit += stringTMP[3]
            stringbit += stringTMP[2]
            stringbit += stringTMP[1]
            stringbit += stringTMP[0]
            self.infoString += stringbit
            self.infolen = len(self.infoString)
        print(self.infoString)

    def read_hidden_data(self):
        self.bytes_arr = []
        self.infoString = ''
        howManyCharsInfo = ''
        howManyCharsExt = ''
        extBitString = ''
        infoBitString = ''
        ext = ''

        stegoFile = wave.open(filedialog.askopenfilename(filetypes=(("Ses dosyaları", "*.wav"), ("Tüm dosyalar", "*.*"))), 'rb')

        frame = stegoFile.readframes(1)
        frame = int.from_bytes(frame, byteorder='big')
        hiddenBit = frame % 2

        if hiddenBit == 0:
            print('\nLSB ile data saklandı!')

            for i in range(0, 32):
                frame = stegoFile.readframes(1)
                frame = int.from_bytes(frame, byteorder='big')
                hiddenBit = frame % 2
                howManyCharsInfo += str(hiddenBit)

            for i in range(0, 32):
                frame = stegoFile.readframes(1)
                frame = int.from_bytes(frame, byteorder='big')
                hiddenBit = frame % 2
                howManyCharsExt += str(hiddenBit)

            ext_len = int(howManyCharsExt, 2)
            info_len = int(howManyCharsInfo, 2)
            stegoFile.readframes(1)

            for i in range(0, ext_len*8):
                frame = stegoFile.readframes(1)
                frame = int.from_bytes(frame, byteorder='big')
                hiddenBit = frame % 2
                extBitString += str(hiddenBit)
            self.information_ext = self.bits_to_ext(extBitString)
            frame = stegoFile.readframes(1)

            for i in range(0, info_len):
                frame = stegoFile.readframes(1)
                frame = int.from_bytes(frame, byteorder='big')
                hiddenBit = frame % 2
                infoBitString += str(hiddenBit)

            for i in range(len(infoBitString)):
                self.bytes_arr.append(infoBitString[i])

        file = open('sonra.txt', 'w+')
        for i in range(len(self.bytes_arr)):
            string = 'byte_arr[' + str(i) + ']\t == \t' + str(self.bytes_arr[i]) + '\n'
            file.write(string)

        file.close()
        stegoFile.close()
        self.new_any_file()
        print(self.infoString)

    @staticmethod
    def tobits(x):
        bitstringpom = ''
        bitstring = ''
        for i in range(32):
            bitstringpom += str(x % 2)
            x = int(x / 2)

        for i in range(len(bitstringpom) - 1, -1, -1):
            bitstring += bitstringpom[i]

        return bitstring

    @staticmethod
    def frombits(x):
        return int(x, 2)

    def init(self):
        width = 300
        height = 200

        xwidth = self.winfo_screenwidth()
        yheight = self.winfo_screenheight()

        x = (xwidth / 2) - (width / 2)
        y = (yheight / 2) - (height / 2)
        self.master.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def ext_to_bits(self, ext):
        bits = ''
        for i in range(len(ext), 0, -1):
            char = int(ord(ext[i-1]))
            for j in range(0, 8, 1):
                bit = int(char % 2)
                char /= 2
                bits += str(bit)

        for i in range(len(bits), 0, -1):
            self.information_ext_bits += bits[i-1]
        print(self.information_ext_bits)

    @staticmethod
    def bits_to_ext(bits):
        ext = ''
        char_tmp = ''
        for i in range(1, len(bits)+1):
            char_tmp += bits[i-1]
            if i % 8 == 0:
                ext += chr(int(char_tmp, 2))
                char_tmp = ''
        return ext

    def open_any_file(self):

        self.bytes_arr = []
        filename_ext = filedialog.askopenfilename()
        filename, file_extension = os.path.splitext(filename_ext)
        print(file_extension)
        file = open(filename_ext, 'rb')
        self.information_ext = file_extension
        self.ext_to_bits(self.information_ext)
        self.information_ext_len = len(self.information_ext)*8
        self.information_ext_len_bits = self.tobits(len(self.information_ext))

        while True:
            data = file.read(1)
            if not data:
                break
            else:
                byte = data
                byte_int = int.from_bytes(byte, byteorder='big')
                x = self.tobits(byte_int)
                for i in range(32):
                    self.bytes_arr.append(str(x)[i])
        self.bytes_arr_len = len(self.bytes_arr)
        self.bytes_arr_len_bits = self.tobits(len(self.bytes_arr))
        file.close()

        self.information = 1

        file = open('önce.txt', 'w+')
        for i in range(len(self.bytes_arr)):
            string = 'byte_arr[' + str(i) + ']\t == \t' + str(self.bytes_arr[i]) + '\n'
            file.write(string)

        file.close()

        if self.container != 0 and self.information != 0:
            if self.maxInfo < self.infolen * 16:
                self.maxInfoLabelText.set('Ses dosyası fazla küçük.')
            else:
                self.maxInfoLabel.grid_forget()
                self.hideFrame.grid(row=5, column=0, sticky=W)

    def new_any_file(self):
        newFilename = 'steg_çıkış' + self.information_ext
        file_output = open(newFilename, 'wb+')
        bits = ''
        for i in range(1, len(self.bytes_arr) + 1):
            bits += str(self.bytes_arr[i - 1])
            if i % 32 == 0:
                data = self.frombits(bits).to_bytes(1, byteorder='big')
                bits = ''
                file_output.write(data)
        print("Veri okundu!")
        file_output.close()

    def compare_files(self):                 # debug

        fileBefore = open('önce.txt', 'r')

        fileAfter = open('sonra.txt', 'r')

        for i in range(len(self.bytes_arr)):
            while True:
                dataBefore = fileBefore.readline()
                dataAfter = fileAfter.readline()
                if not dataBefore or not dataAfter:
                    break
                else:
                    if dataAfter != dataBefore:
                        string = 'dataAfter: ' + dataAfter + '\tdataBefore' + dataBefore
                        print(string)

        fileBefore.close()
        fileAfter.close()

class main:
    @staticmethod
    def window():
        program = Tk()
        app = Application(program)
        app.init()
        app.mainloop()

if __name__ == '__main__':
    main.window()
