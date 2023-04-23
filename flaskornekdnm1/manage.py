from distutils.util import execute
from logging import config
from unittest import result
from flask import Flask,render_template,flash,redirect,url_for,session,sessions,logging,request
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators,DateField,IntegerField,DateTimeField,EmailField,SelectField,BooleanField
from wtforms.validators import DataRequired
from passlib.hash import sha256_crypt
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import Form, PasswordField, validators
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, redirect, url_for, flash
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from wtforms import Form, PasswordField, validators

from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired



#Login Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntülemek için lütfen giriş yapın","danger")
            return redirect(url_for("login"))
    return decorated_function 

def login_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            flash("Bu sayfayı görebilmek için çıkış yapınız", "danger")
            return redirect(url_for("index"))
        else:
            return f(*args, **kwargs)
    return decorated_function

#Kullanici Kayit Formu
class RegisterForm(Form):
    name=StringField("",validators=[validators.Length(message="Lütfen geçerli bir isim adresi giriniz...",min= 4,max=25)])    
    username=StringField("",validators=[validators.Length(message="Lütfen geçerli bir kullanıcı adı giriniz...",min= 5,max=35)])
    email=StringField("", validators=[validators.Email("Lütfen geçerli bir Email adresi giriniz...")])
    school=StringField("",validators=[validators.Length(message="Lütfen geçerli bir eğitim kurumu giriniz...",min= 2,max=70)])
    password = PasswordField("", validators=[
        validators.DataRequired(message="Lütfen bir parola belirleyin"),
        validators.EqualTo(fieldname="confirm", message="Parolanız uyuşmuyor..")])

    confirm= PasswordField("")
    checkbox = BooleanField("", validators=[DataRequired()])
#Kullanici Girisi Formu
class LoginForm(Form):
    username= StringField("")
    password= PasswordField("")

#ChangePassword
class PasswordChangeForm(Form):
    old_password = PasswordField('Old Password', [validators.DataRequired()])
    new_password = PasswordField('New Password', [validators.DataRequired(),
                                                  validators.Length(min=8, message='Password must be at least 8 characters long.'),
                                                  validators.EqualTo('confirm', message='Passwords do not match.')])
    confirm = PasswordField('Confirm Password', [validators.DataRequired()])




app=Flask(__name__)
app.secret_key="adblog"
app.config["SECRET_KET"]="secret"
app.config["MYSQL_HOST"] = "127.0.0.1"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "adblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
app.config['UPLOAD_FOLDER'] = 'app/static/uploads'
mysql= MySQL(app)

#index
@app.route("/")
def index():
    return render_template("index.html")

#TopUsers
@app.route("/topusers")
def topusers():
    return render_template("topusers.html")

#About
@app.route("/about")
def about():
    return render_template("about.html")

#Login
@app.route("/login", methods =["GET","POST"])
@login_check
def login():
    
    form=LoginForm(request.form)
    if request.method == "POST" and form.validate() :
        username= form.username.data
        password_entered= form.password.data
        
        cursor= mysql.connection.cursor()

        sorgu= "Select * From users where username= %s"
        result = cursor.execute(sorgu,(username,))
        
        if result >0:
            data = cursor.fetchone()
            real_password= data["password"]
            if sha256_crypt.verify(password_entered,real_password):
                flash("Başarıyla Giriş Yaptınız..","succes")
                session["logged_in"]= True
                session["username"]= username
                return redirect(url_for("index"))
            else:
                flash("Yanlış parola girdiniz..." )
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunmuyor...","danger")
            return redirect(url_for("login"))        
    else:
        return render_template("login.html",form=form)

        
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


#Profile
@app.route("/profile")
@login_required
def profile():
    cursor=mysql.connection.cursor()
    
    sorgu="Select * From profile where author =%s"
 
    result=cursor.execute(sorgu,(session["username"],))

    if result>0:
        profile=cursor.fetchall()
        return render_template("profile.html", profile= profile)
    else:
        return redirect("editprofile")


#Settings
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


#Register
@app.route("/register",methods=["GET","POST"] )
@login_check
def register():
    form=RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name= form.name.data
        username= form.username.data
        email=form.email.data
        school=form.school.data
        password= sha256_crypt.encrypt(form.password.data)
        checkbox = form.checkbox.data
        cursor=mysql.connection.cursor()
        if cursor.execute(' SELECT * FROM users WHERE email=%s or username=%s ',(email,username)):
            if cursor.execute(' SELECT * FROM users WHERE email=%s and username=%s ',(email,username)):
                flash("E-posta veya Kullanıcı adı kullanılıyor...")
                return render_template('register.html',form=form)
            elif cursor.execute(' SELECT * FROM users WHERE email=%s ',(email,)):
                flash("E-posta zaten kullanılıyor...")
                return render_template('register.html',form=form)
            elif cursor.execute(' SELECT * FROM users WHERE username=%s ',(username,)):
                flash("Kullanıcı adı zaten kullanılıyor")
                return render_template('register.html',form=form)
        else :
            cursor.execute(' INSERT INTO users (name,email,username,password,school,checkbox) VALUES(%s,%s,%s,%s,%s,%s) ',(name,email,username,password,school,checkbox))
        mysql.connection.commit()
        cursor.close()
        flash("Başarıyla Kayıt Oldunuz...","succes")
        return redirect(url_for("login"))
    else :
        return render_template('register.html',form=form)

  
#Contact
@app.route("/contact")
def contact():
    return render_template("contact.html")

#Change Password
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordChangeForm(request.form)
    if request.method == 'POST' and form.validate():
        if 'username' in session:
            # Retrieve current user's password
            cur = mysql.connection.cursor()
            cur.execute('SELECT password FROM users WHERE username = %s', (session['username'],))
            user = cur.fetchone()
            cur.close()

            # Verify old password
            if sha256_crypt.verify(form.old_password.data, user['password']):
                # Hash new password and update in database
                new_password = sha256_crypt.hash(form.new_password.data)
                cur = mysql.connection.cursor()
                cur.execute('UPDATE users SET password = %s WHERE username = %s', (new_password, session['username']))
                mysql.connection.commit()
                cur.close()

                flash('Parolanız değiştirilmiştir...', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Eski şifreniz yanlıştır. Lütfen tekrar deneyiniz...', 'danger')
        else:
            flash('Bu sayfayı görüntülemek için lütfen giriş yapın', 'danger')
            return redirect(url_for('index'))
    return render_template('change-password.html', form=form)
#EditProfile
@app.route("/editprofile",methods=["GET","POST"])
@login_required
def editprofile():
    form = EditProfileForm(request.form)
    if request.method == "POST" and form.validate():
        namesurname=form.namesurname.data
        birthday= form.birthday.data
        gender=form.gender.data
        phonenumber=form.phonenumber.data
        city=form.city.data
        adress=form.adress.data
        school=form.school.data
        unvan=form.unvan.data

        content=form.content.data
        cursor= mysql.connection.cursor()
        
        if cursor.execute("SELECT * FROM profile WHERE phonenumber=%s",(phonenumber,)):
            flash("Bu telefon numarası zaten kullanılıyor...")
            return render_template("editprofile.html",form=form)
        else:
            cursor.execute("Insert into profile(namesurname,birthday,gender,phonenumber,city,adress,school,unvan,author,content) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(namesurname,birthday,gender,phonenumber,city,adress,school,unvan,session["username"],content))
        mysql.connection.commit()
        cursor.close()
        flash("Profiliniz başarıyla düzenlendi...","succes")
        return redirect(url_for("profile"))
    return render_template("editprofile.html",form=form)

#Edit Profile
@app.route("/editprofile/<string:id>", methods=["GET","POST"])
@login_required
def update(id):
    if request.method=="GET":
        cursor=mysql.connection.cursor()
        sorgu="Select * from profile where id =%s and author=%s"
        result= cursor.execute(sorgu,(id,session["username"]))

        if result==0:
            flash("Böyle bir işleme yetkiniz yok","danger")
            return redirect(url_for("index"))

        else:
            profile= cursor.fetchone()
            form=EditProfileForm()

            form.namesurname.data = profile["namesurname"]
            form.birthday.data= profile["birthday"]
            form.gender.data = profile["gender"]
            form.phonenumber.data= profile["phonenumber"]
            form.city.data = profile["city"]
            form.adress.data= profile["adress"]
            form.school.data = profile["school"]
            form.unvan.data= profile["unvan"]
            form.content.data = profile["content"]
            return render_template("editprofile.html",form=form)

    else:
        form= EditProfileForm(request.form)

        newNamesurname = form.namesurname.data
        newBirthday = form.birthday.data
        newGender = form.gender.data
        newPhonenumber = form.phonenumber.data
        newcity = form.city.data
        newAdress = form.adress.data
        newSchool = form.school.data
        newUnvan = form.unvan.data
        newContent = form.content.data

        sorgu2="Update profile Set namesurname=%s, birthday=%s, gender=%s, phonenumber=%s, city=%s, adress=%s, school=%s,unvan=%s,content=%s where id=%s"
        cursor=mysql.connection.cursor()
        cursor.execute(sorgu2,(newNamesurname,newBirthday,newGender,newPhonenumber,newcity,newAdress,newSchool,newUnvan,newContent,id))

        mysql.connection.commit()

        flash("Profiniz başarıyla güncellendi...","success")
        return redirect(url_for("profile"))


#Delete Account
@app.route("/delete_acount", methods=["POST"])
@login_required
def delete_account():
    cur=mysql.connection.cursor()
    username= session["username"]
    cur.execute("DELETE FROM users WHERE username=%s",[username])
    cur.execute("DELETE FROM profile WHERE author=%s", [username])
    mysql.connection.commit()
    cur.close()
    try:
        cur.execute= "Delete from users where id=%s "
        session.clear()
        flash("Profiliniz başarıyla silindi...","succes")
        

    except:
        session.clear()
        flash("Profiliniz başarıyla silindi...","succes")
        return redirect(url_for("index"))

    return redirect(url_for("index"))

#EditProfileForm
class EditProfileForm(Form):
    namesurname=StringField("Isminiz",validators=[validators.Length(min=3 , max=20)])
    birthday =DateField("Doğum Tarihiniz")
    gender=SelectField("Cinsiyetiniz",choices=[("ERKEK"),("KADIN"),("DİĞER")])
    phonenumber = StringField("Numaranız", validators=[DataRequired()])
    city = SelectField("Şehir", choices=[("ADANA"),("ADIYAMAN"),("AFYONKARAHİSAR"),("AĞRI"),("AKSARAY"),("AMASYA"),("ANKARA"),("ANTALYA"),("ARDAHAN"),("ARTVİN"),("AYDIN"),("BALIKESİR"),("BARTIN"),("BATMAN"),("BAYBURT"),("BİLECİK"),("BİNGÖL"),("BİTLİS"),("BOLU"),("BURDUR"),("BURSA"),("ÇANAKKALE"),("ÇANKIRI"),("ÇORUM"),("DENİZLİ"),("DİYARBAKIR"),("DÜZCE"),("EDİRNE"),("ELAZIĞ"),("ERZİNCAN"),("ERZURUM"),("ESKİŞEHİR"),("GAZİANTEP"),("GİRESUN"),("GÜMÜŞHANE"),("HAKKARİ"),("HATAY"),("IĞDIR"),("ISPARTA"),("İSTANBUL"),("İZMİR"),("KAHRAMANMARAŞ"),("KARABÜK"),("KARAMAN"),("KARS"),("KASTAMONU"),("KAYSERİ"),("KIRIKKALE"),("KIRKLARELİ"),("KIRŞEHİR"),("KİLİS"),("KOCAELİ"),("KONYA"),("KÜTAHYA"),("MALATYA"),("MANİSA"),("MARDİN"),("MERSİN"),("MUĞLA"),("MUŞ"),("NEVŞEHİR"),("NİĞDE"),("ORDU"),("OSMANİYE"),("RİZE"),("SAKARYA"),("SAMSUN"),("SİİRT"),("SİNOP"),("SİVAS"),("ŞANLIURFA"),("ŞIRNAK"),("TEKİRDAĞ"),("TOKAT"),("TRABZON"),("TUNCELİ"),("UŞAK"),("VAN"),("YALOVA"),("YOZGAT"),("ZONGULDAK")])
    adress=TextAreaField("Adres",validators=[validators.Length(min=5,max=100)])
    school=StringField("Eğitim Gördüğünüz Kurum",validators=[validators.Length(min=2, max=20)])
    unvan=StringField("Meslek",validators=[validators.Length(min=2, max=20)])
    content=TextAreaField("Hakkında bir şeyler",validators=[validators.Length(min=5 , max=500)])

if __name__ == "__main__":
    app.run(debug=True)

    


    

