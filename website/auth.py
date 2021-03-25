from flask import Blueprint, render_template, request, flash, redirect, url_for
from . import db 
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Successful Login', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('password is invalided', category='error')
        else:
            flash('User doesn\'t existed', category='error')

    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        password = request.form.get('password')
        confirmpass = request.form.get('confirmpass')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('email already existed', category='error')
        elif len(email) < 4:
            flash('email must be greater than 4 char', category='error')
        elif len(firstname) < 2:
            flash('firstname must be greater than 2 char', category='error')
        elif len(lastname) < 2:
            flash('lastname must be greater than 2 char', category='error')
        elif len(password) < 7:
            flash('password must be greater than 7 char', category='error')
        elif password != confirmpass:
            flash('password must be matched with confirmed password', category='error')
        else:
            new_user = User(email=email, firstname=firstname, lastname=lastname, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Successful registered', category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html', user=current_user)