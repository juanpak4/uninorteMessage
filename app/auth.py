import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST')) ## nombre Activate Ruta /activate Metodos HTTP Get Post 
def activate(): ## logica
    try:
        if g.user: ##busca si existe un usuario con session activa si es asi lo envia directamente a la pagina de visualizacion de mensajes 
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth']  ## consulta el token generado por el metodo de registro el cual es el numero que se ve enseguida de la url /auth/activate?auth=f32c82796db8933905ca1bf08becb3a1df75aa30fec2ef3af45659fd1733b80a5419817f55c7d597e2abfdd44c9066579d80541502d3a53068a1892001e29999
            
            db = get_db() 
            attempt = db.execute( ## consulta si existe una activacion con lo que es el numero generado por el registro asi como en un estado sin confirmar
                'SELECT * FROM activationlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None: ##si encuentra una peticion de activacion procede a actualizar esa peticion a confirmada y crea el usuario con la informacion suministrada
                db.execute(
                    'UPDATE activationlink SET state = ? WHERE id = ?', (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    'INSERT INTO user (username, password,salt,email) VALUES (?,?,?,?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit() ## realiza el commit en la bd

        return redirect(url_for('auth.login')) #redirecciona al login
    except Exception as e:
        print(e) ## si encuentra algun error imprime el error resultante
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST')) ## nombre register Ruta /register Metodos HTTP Get Post 
def register():
    try:
        if g.user: ##busca si existe un usuario con session activa si es asi lo envia directamente a la pagina de visualizacion de mensajes 
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':    #mediante el metodo post realiza la solicitud de la informacion ingresada en el formulario
            username = request.form['username'] ## en el formulario generado busca el nombre de usuario
            password = request.form['password'] ## en el formulario generado busca la contraseña a asignar
            email = request.form['email'] ## en el formulario generado busca el correo electronico
            
            db = get_db() ##solicita la base de datos(bd)
            error = None

            if not username: ## consulta si por parte del input dedicado a el usuario no se encuentra vacio de ser asi arrojara un error que indica que se requiere un usuario y lo reenvia al registro
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username): ## consulta si por parte del input dedicado a el usuario cuenta con los parametros de ingreso
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password: ## consulta si por parte del input dedicado a la contraseña no se encuentra vacio
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None: ## busca si el usuario ingresado ya se encuentra registrado de ser asi le enviara un error ene l que indica que el usuario ya se encuentra registrado
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html')
            
            if((not email) or (not utils.isEmailValid(email))): ##verifica que el correo electronico se encuentre ingresado y que sea valido
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None: ## verifica que el correo electronico no se encuentre registrado por otro usuario
                error =  'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html')
            
            if(not utils.isPasswordValid(password)): ## verifica que la contraseña ingresada cumpla con las propiedades establecidas
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:] #genera un numero aleatorio
            hashP = generate_password_hash(password + salt) #combina la contraseña y el salt para despues por medio del metodo generar una contraseña encriptada
            number = hex(random.getrandbits(512))[2:] #genera el numero para el link de activacion

            db.execute( ##inserta en la tabla activationlink los atributos como el numero o token de activacion, la variable sin confirmar, usuario, contraseña , salt  y el email que determinan al usuario que se ha registrado parcialmente
                'INSERT INTO activationlink (challenge, state, username, password,salt,email) VALUES (?,?,?,?,?,?)',
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit() #comitea o ejecuta las querys realizadas

            credentials = db.execute( ## busca las credenciales para enviar el correo de activacion
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()
            print('credenciales', credentials['user'])
            print('credenciales', credentials['password'])
            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content) ## envia el correo de activacion
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') ## redirige a la pantalla de logueo

        return render_template('auth/register.html') 
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST'))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': 
            password = request.form['password']  #adquiere el valor de la contraseña
            password1 = request.form['password1'] #adquiere el valor de la confirmar contraseña 
            authid = request.form['authid'] #adquiere el token que se envia mediante la Url

            if not authid: # valida que si exzista un token de autenticacion
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password: #valida que si se ingreso una contraseña
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1: #valida que si se ingreso una confirmacion de contraseña
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid)

            if password1 != password: #valida que las dos contraseñas ingresadas sean iguales
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password): # valida que la contraseña cumpla las pautas establecidos
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()
            attempt = db.execute( ## busca el link que determina el cambio de contraseña por medio del numero de autenticacion
                'SELECT * FROM forgotlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (authid, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None: # determina si existe una query con ese numero de autenticacion y si no lo redirecciona a la pantalla contraseña olvidada
                db.execute(
                    'UPDATE forgotlink SET state = ? WHERE id = ?', (utils.F_INACTIVE, attempt['id']) #actualiza el estado de la query que se asigno para el cambio de contraseña
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    'UPDATE user SET password = ?, salt=? WHERE id = ?', (hashP, salt, attempt['userid']) #ãctualiza la contraseña del usuario
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                'SELECT * FROM forgotlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (number, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email']
            
            if ((not email) or (not utils.isEmailValid(email))):
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'SELECT * FROM user WHERE email = ?', (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    'UPDATE forgotlink SET state = ? WHERE userid = ?',
                    (utils.F_INACTIVE,user['id'])
                )
                db.execute(
                    'INSERT INTO forgotlink (userid, challenge,state ) VALUES (?,?,?)',
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            if not username:
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html')

            db = get_db()
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if user is None:
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')
    except:
        return render_template('auth/login.html')
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()