from tkinter import *
import tkinter.messagebox
import mysql.connector
import hashlib
import binascii
import os
import math



#connecting to the database
connectiondb = mysql.connector.connect(host="localhost",user="root",passwd="Bigbalagan77",database="logininfo")
cursordb = connectiondb.cursor()
# gui for add user

def adduser():
    global root3
    root3 = Toplevel(root)
    root3.title("ADD USER")
    root3.geometry("450x300")
    root3.config(bg="white")
    global newUser
    global new_password
    Label(root3, text='Please Enter your new Account Details', bd=5, font=('arial', 12, 'bold'), relief="groove",
          fg="white",
          bg="blue", width=300).pack()
    newUser = StringVar()
    new_password = StringVar()
    Label(root3, text="").pack()
    Label(root3, text="new Username :", fg="black", font=('arial', 12, 'bold')).pack()
    Entry(root3, textvariable=newUser).pack()
    Label(root3, text="").pack()
    Label(root3, text="new Password :", fg="black", font=('arial', 12, 'bold')).pack()
    Entry(root3, textvariable=new_password, show="*").pack()
    Label(root3, text="").pack()
    Button(root3, text="Login", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'),
           command=addinguser).pack()
    Label(root3, text="")


def login():
    global root2
    root2 = Toplevel(root)
    root2.title("Account Login")
    root2.geometry("450x300")
    root2.config(bg="white")

    global username_verification
    global password_verification
    Label(root2, text='Please Enter your Account Details', bd=5,font=('arial', 12, 'bold'), relief="groove", fg="white",
                   bg="blue",width=300).pack()
    username_verification = StringVar()
    password_verification = StringVar()
    Label(root2, text="").pack()
    Label(root2, text="Username :", fg="black", font=('arial', 12, 'bold')).pack()
    Entry(root2, textvariable=username_verification).pack()
    Label(root2, text="").pack()
    Label(root2, text="Password :", fg="black", font=('arial', 12, 'bold')).pack()
    Entry(root2, textvariable=password_verification, show="*").pack()
    Label(root2, text="").pack()
    Button(root2, text="Login", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'),command=login_verification).pack()
    Label(root2, text="")

def logged_destroy():
    logged_message.destroy()
    root2.destroy()

def logged_destroy2():
    add_message.destroy()
    root3.destroy()

def failed_destroy():
    failed_message.destroy()

def logged():
    global logged_message
    logged_message = Toplevel(root2)
    logged_message.title("Welcome")
    logged_message.geometry("500x100")
    Label(logged_message, text="Login Successfully!... Welcome {} ".format(username_verification.get()), fg="green", font="bold").pack()
    Label(logged_message, text="").pack()
    Button(logged_message, text="Logout", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'), command=logged_destroy).pack()

def add():
    global add_message
    add_message = Toplevel(root3)
    add_message.title("hello")
    add_message.geometry("500x100")
    Label(add_message, text="user add Successfully!... Welcome {} ".format(newUser.get()), fg="green", font="bold").pack()
    Label(add_message, text="").pack()
    Button(add_message, text="Logout", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'), command=logged_destroy2).pack()


def failed():
    global failed_message
    failed_message = Toplevel(root2)
    failed_message.title("Invalid Message")
    failed_message.geometry("500x100")
    Label(failed_message, text="Invalid Username or Password", fg="red", font="bold").pack()
    Label(failed_message, text="").pack()
    Button(failed_message,text="Ok", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'), command=failed_destroy).pack()

def failed2():
    global failed_message
    failed_message = Toplevel(root3)
    failed_message.title("Invalid Message enterd please try agian ")
    failed_message.geometry("500x100")
    Label(failed_message, text="Invalid Username or Password", fg="red", font="bold").pack()
    Label(failed_message, text="").pack()
    Button(failed_message,text="Ok", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'), command=failed_destroy).pack()


def checkpass(newpassword):
    SpecialSym = ['$', '@', '#', '%','^','&','*','(']
    blackList = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
                   "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow",
                   "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "pussy",
                   "superman", "1qaz2wsx", "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe", "killer",
                   "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley",
                   "batman", "andrew", "tigger", "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert",
                   "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole",
                   "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
                   "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
                   "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea", "biteme", "matthew",
                   "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "william",
                   "corvette", "hello", "martin", "heather", "secret", "fucker", "merlin", "diamond", "1234qwer",
                   "gfhjkm", "hammer", "silver", "222222", "88888888", "anthony", "justin", "test", "bailey",
                   "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111", "golfer", "cookie", "richard",
                   "samantha", "bigdog", "guitar", "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy",
                   "maverick", "phoenix", "camaro", "sexy", "peanut", "morgan", "welcome", "falcon", "cowboy",
                   "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph", "mercedes", "dakota", "arsenal",
                   "eagles", "melissa", "boomer", "booboo", "spider", "nascar", "monster", "tigers", "yellow", "xxxxxx",
                   "123123123", "gateway", "marina", "diablo", "bulldog", "qwer1234", "compaq", "purple", "hardcore",
                   "banana", "junior", "hannah", "123654", "porsche", "lakers", "iceman", "money", "cowboys", "987654",
                   "london", "tennis", "999999", "ncc1701", "coffee", "scooby", "0000", "miller", "boston", "q1w2e3r4",
                   "fuckoff", "brandon", "yamaha", "chester", "mother", "forever", "johnny", "edward", "333333",
                   "oliver", "redsox", "player", "nikita", "knight", "fender", "barney", "midnight", "please", "brandy",
                   "chicago", "badboy", "iwantu", "slayer", "rangers", "charles", "angel", "flower", "bigdaddy",
                   "rabbit", "wizard", "bigdick", "jasper", "enter", "rachel", "chris", "steven", "winner", "adidas",
                  ]

    val = True

    if newpassword in blackList:
        val = False

    if len(newpassword) < 10:
     #   print('length should be at least 6')
        val = False

    if '.' in newpassword :
     #   print('the password contins a dot . )
        val = False

    if not any(char.isupper() for char in newpassword):
        val = False


    if not any(char.islower() for char in newpassword):
        val = False

    if not any(char in SpecialSym for char in newpassword):
       # print('Password should have at least one of the symbols $@#^&*(')
        val = False
    if val:
        return val

def getSalt(name):
#query = "SELECT * FROM blah WHERE email LIKE %s limit 10"
# cursor.execute(query,("%" + p + "%",))

    sql = "select salt from users_data where user = %s "
    cursordb.execute(sql, (name,))
    recored = cursordb.fetchone()
    return recored





def login_verification():
    user_verification = username_verification.get()
    pass_verification = password_verification.get()
    # trting to convert the typle typle salt to bytes for pbkdf2_hmac

    salt = getSalt(user_verification)
    print(salt)
    print(type(salt)) #tuple
    salt = salt[0][:65] #become a string
    print(type(salt)) #str
    new_salt = salt.encode()
    print(type(new_salt)) #bytes
    print(new_salt)



    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
         pass_verification.encode(),  # Convert the password to bytes
          new_salt ,    #provides the salt
          100000,  # It is recommended to use at least 100,000 iterations of SHA-256
    )

    key = binascii.hexlify(key)
    print(key)
    key = key.decode()
    print(key)



    sql = "select * from users_data where user = %s and password = %s"

    cursordb.execute(sql,[(user_verification),(key)])

    trys = 0
    results = cursordb.fetchall()
    if results:
        for i in results:
            logged()
            break
    else:
        failed()
        trys +=1
        if trys == 3:
            logged_destroy()



def addinguser():
    user_new = newUser.get()
    newpassword = new_password.get()

    salt = os.urandom(32)
    print(salt)
    print(type(salt))
    salt = binascii.hexlify(salt)
    print(salt)


    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        newpassword.encode(),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )

    key2 = binascii.hexlify(key)
    key2 =key2.decode()


    sql2 = "INSERT INTO users_data (user,password,salt) VALUES(%s,%s,%s)"

    val = (user_new,key2,salt)

    if checkpass(newpassword):
        cursordb.execute(sql2,val)
        connectiondb.commit()
        add()


    else:
        failed2()



def Exit():
    wayOut = tkinter.messagebox.askyesno("Login System", "Do you want to exit the system")
    if wayOut > 0:
        root.destroy()
        return

def main_display():
    global root
    root = Tk()
    root.config(bg="white")
    root.title("Login System")
    root.geometry("500x500")
    Label(root,text='Welcome to Log In System',  bd=20, font=('arial', 20, 'bold'), relief="groove", fg="white",
                   bg="blue",width=300).pack()
    Label(root,text="").pack()
    Button(root,text='Log In', height="1",width="20", bd=8, font=('arial', 12, 'bold'), relief="groove", fg="white",
                   bg="blue",command=login).pack()
    Label(root,text="").pack()
    Button(root, text='add user ', height="1", width="20", bd=8, font=('arial', 12, 'bold'), relief="groove", fg="white",
           bg="blue", command=adduser).pack()
    Label(root, text="").pack()
    Button(root,text='Exit', height="1",width="20", bd=8, font=('arial', 12, 'bold'), relief="groove", fg="white",
                   bg="blue",command=Exit).pack()
    Label(root,text="").pack()

main_display()
root.mainloop()

#user=moti
#Motimoti$#