'''Configuration'''
import os
import random
from datetime import datetime

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from flask_migrate import Migrate
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SelectField
from wtforms.validators import DataRequired
from flask_login import FlaskLoginClient, LoginManager, login_required, login_user,logout_user,current_user,UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect


basedir=os.path.abspath(os.path.dirname(__file__))

csrf = CSRFProtect()
app = Flask(__name__)
csrf = CSRFProtect(app)
csrf.init_app(app)

app.config["APP_NAME"]="baigiamasis"
app.config["SECRET_KEY"]="duhsadgusafdbdsfdhsfbhudsbfhubf45158945645df4156df46dxfv3dx2f6dx5"
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///"+ os.path.join(basedir, "data.sqlite")
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
moment = Moment(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
csrf.init_app(app)

Base = declarative_base()
Session = sessionmaker()
session1 = Session()

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

'''Models'''
class Kategorija(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    category=db.Column(db.String(25), unique=False, nullable=True)
    user=db.Column(db.Integer())
    
    def __repr__(self):
        return f"<User {self.name}>"
    
    with app.app_context():
        db.create_all()

class Uzrasas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(25), unique=False)
    note=db.Column(db.String(200))
    category=db.Column(db.String(25))
    user=db.Column(db.Integer())

    with app.app_context():
        db.create_all()

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(40), unique=False, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)

    @login_manager.user_loader
    def user_loader(id):
        return Users.query.get(int(id))
       
    def __repr__(self):
        return f"<User {self.name}>"
   
    def is_active(self):
        return True

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False
    
    with app.app_context():
        db.create_all()
        

'''Forms'''
class Registration(FlaskForm):

    name = StringField("Jusu vardas", validators=[DataRequired()])
    password =PasswordField("Slaptazodis", validators=[DataRequired()])
    password2 =PasswordField("Pakartoti slapatazodi", validators=[DataRequired()])
    email=EmailField("Jusu elektroninis pastas", validators=[DataRequired()])
    submit = SubmitField("Submit")

class Login(FlaskForm):

    name = StringField("Jusu vardas", validators=[DataRequired()])
    password =PasswordField("Slaptazodis", validators=[DataRequired()])
    submit = SubmitField("Submit")

class Category(FlaskForm):

    kategorija = StringField("Nauja kategorija", validators=[DataRequired()])
    submit = SubmitField("Submit")

class Priminimas(FlaskForm):
    name=StringField('Priminimo pavadinimas',validators=[DataRequired(25)])
    note=StringField('Priminimas',validators=[DataRequired(200)])
    category = SelectField('Pasirinkite kategorija', coerce=str)
    submit = SubmitField("Submit")

    def __init__(self, *args, **kwargs):
        super(Priminimas, self).__init__(*args, **kwargs)
        self.category.choices = [(Kategorija.category, Kategorija.category) 
                                        for Kategorija in Kategorija.query.filter_by(user=current_user.id)]


class Search(FlaskForm):

    paieska = StringField("Įveskite norimos kategorijos ar priminimo pavadinimą", validators=[DataRequired()])
    submit = SubmitField("Submit")

class DeleteNote(FlaskForm):
    submit = SubmitField("Ištrinti")


class UpdateNote(FlaskForm):
    text= StringField("Jūsų tekstas")
    submit = SubmitField("Pakeisti zinute")

'''Routes'''

@app.route('/', methods=['GET','POST'])
def index():
    count=0
    lastuser=[]
    try:
        users=Users.query.order_by(Users.id)
        for user in users:
            count=count+1
            lastuser.append(user.name)
        return render_template('index.html', count=count, lastuser=lastuser)
    except:
        return render_template('index.html')

@app.route('/registration.html', methods=['GET','POST'])
def register():
    form=Registration()
    if form.validate_on_submit():
        hashedPass = bcrypt.generate_password_hash(request.form["password"]).decode('utf-8')
        user=Users.query.filter_by(name=form.name.data)
        try:
            user=Users(name=form.name.data,
            password=hashedPass,
            email=form.email.data)
            if form.password.data==form.password2.data:
                db.session.add(user)
                db.session.commit()
                db.create_all()
                flash('Registracija sėkminga!')
                return redirect(url_for('index'))
            else:                
                flash('Įvyko klaida')
                return render_template('registration.html', form=form)
        except:
            flash('toks vartotojas jau yra')
            return redirect(url_for('register'))
    return render_template('registration.html', form=form)

    

@app.route('/login.html', methods=['GET','POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        user = Users.query.filter_by(name=form.name.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Neteisingi duomenys!")
            return redirect(url_for("login"))
    else:
        return render_template('login.html', form=form)

@app.route('/dashboard.html', methods=['GET','POST'])
@login_required
def dashboard():
    form=DeleteNote()
    form1=UpdateNote()
    form2=Search()
    note=Uzrasas.query.order_by(Uzrasas.id)
    return render_template(
        'dashboard.html',
        notes=note,
        form=form, 
        form1=form1,
        form2=form2
        )

@app.route('/newcategory.html',methods=['GET','POST'])
@login_required
def newcategory():
    form=Category()
    try:
        if form.validate_on_submit():
            newCategory = Kategorija(
                category=request.form['kategorija'],
                user=current_user.id
                )
            db.session.add(newCategory)
            db.session.commit()            
            return redirect(url_for('dashboard'))
    except:
        flash('Tokia kategorija jau yra!')
        return render_template('newcategory.html', form1=form)
    return render_template('newcategory.html', form1=form)

@app.route("/newnote.html", methods=["GET","POST"])
@login_required
def newnote():
    form=Priminimas()
    if form.validate_on_submit():
        note=Uzrasas.query.order_by(Uzrasas.id)
        note=Uzrasas(
            name=request.form["name"],
            note=request.form["note"],
            category=request.form['category'],
            user=current_user.id
        )
        db.session.add(note)
        db.session.commit()
        db.create_all()
        return redirect(url_for('dashboard'))
    else:
        return render_template(
        "newnote.html",
        form=form
        )

@app.route("/deleteNote/<int:id>", methods=["GET","POST"])
@login_required
def deleteNote(id):
    form=DeleteNote()
    note=Uzrasas.query.get_or_404(id)
    note_to_delete=Uzrasas.query.get_or_404(id)
    if form.validate_on_submit():
        db.session.delete(note_to_delete)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template(
    "deleteNote.html",
    noteid=note,
    form=form
    )

@app.route("/UpdateNote/<int:id>", methods=["GET","POST"])
@login_required
def updateNote(id):
    form=UpdateNote()
    note=Uzrasas.query.get_or_404(id)
    note_to_update=Uzrasas.query.get_or_404(id)
    if form.validate_on_submit():
        note_to_update.note=request.form['text']
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template(
    "UpdateNote.html",
    noteid=note,
    form=form
    )

@app.route('/search.html', methods=['GET','POST'])
@login_required
def search():
    form=Search()
    if form.validate_on_submit():
        category_to_find=Kategorija.query.filter_by(category=request.form['paieska'])
        kateg=category_to_find
    else:
        flash('Paieška nesėkminga')
        return redirect(url_for('dashboard'))
    return render_template(
        'search.html', 
        form2=form, 
        resulCategory=kateg,
    )



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
