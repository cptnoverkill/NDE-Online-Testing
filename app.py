from flask import Flask, render_template, request, redirect, url_for, flash, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from flask_admin.contrib.fileadmin import FileAdmin
from flask_mail import Mail, Message
import click
from flask.cli import with_appcontext
import os.path as op
import csv
from flask_migrate import Migrate
from datetime import datetime
from sqlalchemy.orm import joinedload
import random
import pdfkit
import pytz
from flask import render_template, make_response, session
import logging
import pytest
from models import db, User, Exam, Question, ExamAccess, ExamResult, MissedQuestion, ExamAccessRequest


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///knowledge_test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",  # or "None" if you need third-party context
    SESSION_COOKIE_SECURE=True      # Use True if your site is served over HTTPS
)

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'




def utc_to_pacific(utc_dt):
    utc = pytz.UTC
    pacific = pytz.timezone('US/Pacific')
    return utc.localize(utc_dt).astimezone(pacific)

# Make this function available to all templates
app.jinja_env.globals.update(utc_to_pacific=utc_to_pacific)



@app.before_request
def reset_session_on_navigation():
    Exam_endpoints = ['take_Exam', 'submit_Exam']
    current_endpoint = request.endpoint

    if current_endpoint is None:
        return
    
    
    #if current_endpoint not in Exam_endpoints and session.get('taking_Exam'):
        # Reset session only if the user is navigating away and not refreshing or reloading
       # session.clear()  # Clear all session data if needed or be selective
    #elif current_endpoint in Exam_endpoints:
    #    session['taking_Exam'] = True



@app.context_processor
def utility_processor():
    def format_pacific_time(utc_dt):
        pacific_time = utc_to_pacific(utc_dt)
        return pacific_time.strftime('%Y-%m-%d %I:%M:%S %p %Z')
    return dict(format_pacific_time=format_pacific_time)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create customized model view class
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

# Create admin
admin = Admin(app, name='Knowledge Exam Admin', template_mode='bootstrap3')

# Add model views
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Exam, db.session))
admin.add_view(SecureModelView(Question, db.session))
admin.add_view(SecureModelView(ExamAccess, db.session))  # Assuming SecureModelView is used instead of ExamAccessModelView
admin.add_view(SecureModelView(ExamResult, db.session))
admin.add_view(SecureModelView(MissedQuestion, db.session))

# Add file admin
path = op.join(op.dirname(__file__), 'static')
admin.add_view(FileAdmin(path, '/static/', name='Static Files'))


@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            accessible_Exams = Exam.query.all()  # Admins see all Exams
            inaccessible_Exams = []
            pending_Exams = []
        else:
            # Fetch all ExamAccess records for the user
            Exam_accesses = ExamAccess.query.filter_by(user_id=current_user.id).all()
            
            accessible_Exams = []
            inaccessible_Exams = []
            pending_Exams = []

            for access in Exam_accesses:
                if access.is_accessible:
                    accessible_Exams.append(access.Exam)
                else:
                    inaccessible_Exams.append(access.Exam)

            # Get Exams the user has requested access to, but are pending approval
            pending_requests = ExamAccessRequest.query.filter_by(user_id=current_user.id, status='pending').all()
            pending_Exams = [request.Exam for request in pending_requests]

            # Get Exams the user has not requested access to
            all_accessible_Exam_ids = [Exam.id for Exam in accessible_Exams]
            all_inaccessible_Exam_ids = [Exam.id for Exam in inaccessible_Exams]
            all_pending_Exam_ids = [Exam.id for Exam in pending_Exams]
            all_Exam_ids = all_accessible_Exam_ids + all_inaccessible_Exam_ids + all_pending_Exam_ids

            unavailable_Exams = Exam.query.filter(~Exam.id.in_(all_Exam_ids)).all()
            inaccessible_Exams.extend(unavailable_Exams)

        # Ensure no duplicates
        accessible_Exams = list(set(accessible_Exams))
        inaccessible_Exams = list(set(inaccessible_Exams) - set(accessible_Exams))

        # Get the Exams that have been taken by the current user
        taken_Exams = ExamResult.query.filter_by(user_id=current_user.id).all()

        return render_template(
            'home.html',
            accessible_Exams=accessible_Exams,
            inaccessible_Exams=inaccessible_Exams,
            taken_Exams=taken_Exams,
            pending_Exams=pending_Exams
        )
    else:
        return render_template('home.html')








@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
       
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')

        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the current password matches
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))

        # Check if the new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))

        # Update the password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated successfully.', 'success')
        return redirect(url_for('home'))

    return render_template('change_password.html')

@app.before_request
def manage_Exam_session():
    if 'start_new_Exam' in request.args:
        # Clear session when starting a new Exam
        session.pop('answers', None)
        session.pop('flagged', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
    elif 'Exam_submitted' in session and request.endpoint != 'Exam_results':
        # Clear session after viewing results, but not on the results page itself
        session.pop('answers', None)
        session.pop('flagged', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
        session.pop('Exam_submitted', None)




@app.route('/submit_Exam/<int:Exam_id>', methods=['POST'])
@login_required
def submit_Exam(Exam_id):
    Exam = Exam.query.get_or_404(Exam_id)
    user_id = current_user.id

    total_questions = len(Exam.questions)
    correct_answers = 0

    # Debugging: Check the session data
    print("Session data before processing:", session.get('answers'))

    if 'answers' not in session:
        flash("There was an issue with your session data. Please try again.", "error")
        return redirect(url_for('take_Exam', Exam_id=Exam_id))

    Exam_result = ExamResult(user_id=user_id, Exam_id=Exam_id, score=0)
    db.session.add(Exam_result)
    db.session.commit()

    for question in Exam.questions:
        question_id_str = str(question.id)
        user_answer = session['answers'].get(question_id_str)

        # Determine the correct answer content
        if question.correct_answer in ['A', 'B', 'C', 'D']:
            correct_answer_content = getattr(question, f"option_{question.correct_answer.lower()}")
        else:
            correct_answer_content = question.correct_answer

        # Normalize both contents to lowercase and strip any whitespace
        correct_answer_content = correct_answer_content.strip().lower()
        user_answer_content = None
        
        # Determine the user's answer content
        if user_answer in ['A', 'B', 'C', 'D']:
            user_answer_content = getattr(question, f"option_{user_answer.lower()}", user_answer).strip().lower()
        else:
            user_answer_content = user_answer.strip().lower()

        # Compare user's answer content with the correct answer content
        if user_answer_content == correct_answer_content:
            correct_answers += 1
        else:
            missed_question = MissedQuestion(
                Exam_result_id=Exam_result.id,
                question_id=question.id,
                user_answer=user_answer_content
            )
            db.session.add(missed_question)

    score = (correct_answers / total_questions) * 100
    Exam_result.score = score
    db.session.commit()

    # Mark the Exam as no longer accessible
    Exam_access = ExamAccess.query.filter_by(user_id=user_id, Exam_id=Exam_id).first()
    if Exam_access:
        Exam_access.is_accessible = False
        db.session.commit()

    # Clear session data after submission
    session.pop('answers', None)
    session.pop('flagged', None)
    session.pop('skipped', None)
    session.pop('current_index', None)
    session.pop('start_time', None)
    session.pop('taking_Exam', None)

    flash(f'You scored {score:.2f}%.', 'success')
    return redirect(url_for('home'))







@app.route('/request_access/<int:Exam_id>', methods=['POST'])
@login_required
def request_access(Exam_id):
    Exam = Exam.query.get_or_404(Exam_id)
    existing_request = ExamAccessRequest.query.filter_by(user_id=current_user.id, Exam_id=Exam_id, status='pending').first()
    if existing_request:
        flash('You have already requested access to this Exam.', 'info')
    else:
        new_request = ExamAccessRequest(user_id=current_user.id, Exam_id=Exam_id)
        db.session.add(new_request)
        db.session.commit()
        flash('Your access request has been submitted and is pending approval.', 'success')
    return redirect(url_for('home'))


@app.route('/admin/access_requests')
@login_required
def admin_access_requests():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))
    
    pending_requests = ExamAccessRequest.query.filter_by(status='pending').all()
    return render_template('admin_access_requests.html', requests=pending_requests)

@app.route('/admin/approve_access/<int:request_id>', methods=['POST'])
@login_required
def approve_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))
    
    access_request = ExamAccessRequest.query.get_or_404(request_id)
    access_request.status = 'approved'
    access_request.response_date = datetime.utcnow()
    
    new_access = ExamAccess(user_id=access_request.user_id, Exam_id=access_request.Exam_id, is_accessible=True)
    db.session.add(new_access)
    db.session.commit()

    flash(f'Access request for Exam "{access_request.Exam.title}" by user "{access_request.user.username}" approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deny_access/<int:request_id>', methods=['POST'], endpoint='admin_deny_access')
@login_required
def deny_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    access_request = ExamAccessRequest.query.get_or_404(request_id)
    access_request.status = 'denied'
    access_request.response_date = datetime.utcnow()
    access_request.admin_comment = request.form.get('admin_comment', '')
    db.session.commit()

    flash(f'Access request for Exam "{access_request.Exam.title}" by user "{access_request.user.username}" denied.', 'success')
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/grant_Exam_access/<int:user_id>', methods=['POST'])
@login_required
def grant_Exam_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    Exam_id = request.form['Exam_id']
    Exam = Exam.query.get_or_404(Exam_id)

    # Check if the user already has access to the Exam
    existing_access = ExamAccess.query.filter_by(user_id=user.id, Exam_id=Exam.id).first()
    if existing_access:
        flash(f'User "{user.username}" already has access to the Exam "{Exam.title}".', 'info')
    else:
        # Grant access to the Exam
        new_access = ExamAccess(user_id=user.id, Exam_id=Exam.id, is_accessible=True)
        db.session.add(new_access)
        db.session.commit()
        flash(f'Access to Exam "{Exam.title}" has been granted to user "{user.username}".', 'success')

    return redirect(url_for('manage_users'))

@app.route('/admin/manage_questions/<int:Exam_id>', methods=['GET', 'POST'])
@login_required
def manage_questions(Exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    Exam = Exam.query.get_or_404(Exam_id)
    questions = Question.query.filter_by(Exam_id=Exam.id).all()

    if request.method == 'POST':
        question_type = request.form['question_type']
        content = request.form['content']
        correct_answer = request.form['correct_answer']

        if question_type == 'multiple_choice':
            option_a = request.form['option_a']
            option_b = request.form['option_b']
            option_c = request.form['option_c']
            option_d = request.form['option_d']
            question = Question(
                content=content,
                option_a=option_a,
                option_b=option_b,
                option_c=option_c,
                option_d=option_d,
                correct_answer=correct_answer,
                Exam_id=Exam.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                Exam_id=Exam.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('manage_questions', Exam_id=Exam.id))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to Exam "{Exam.title}".', 'success')
        return redirect(url_for('manage_questions', Exam_id=Exam.id))

    return render_template('manage_questions.html', Exam=Exam, questions=questions)


@app.route('/admin/deny_access/<int:request_id>', methods=['POST'])
@login_required
def deny_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))
    
    access_request = ExamAccessRequest.query.get_or_404(request_id)
    access_request.status = 'denied'
    access_request.response_date = datetime.utcnow()
    access_request.admin_comment = request.form.get('admin_comment', '')
    db.session.commit()

    
    flash('Access request denied.', 'success')
    return redirect(url_for('admin_access_requests'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    user_requests = ExamAccessRequest.query.filter_by(user_id=current_user.id).all()
    Exam_results = ExamResult.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', requests=user_requests, Exam_results=Exam_results)


@app.route('/Exam_results/<int:Exam_result_id>', methods=['GET'])
@login_required
def Exam_results(Exam_result_id):
    Exam_result = ExamResult.query.get_or_404(Exam_result_id)
    questions = Exam_result.Exam.questions
    
    # Ensure the user has permission to view this result
    if not current_user.is_admin and Exam_result.user_id != current_user.id:
        flash('You do not have permission to view this Exam result.', 'error')
        return redirect(url_for('home'))

    return render_template('Exam_results.html', Exam_result=Exam_result, questions=questions)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    completed_Exams = ExamResult.query.all()  # Ensure this query is executed correctly
    pending_requests = ExamAccessRequest.query.filter_by(status='pending').all()

    return render_template('admin_dashboard.html', completed_Exams= [] or completed_Exams, pending_requests=pending_requests)





@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Handle new user creation
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form  # Checkbox to set admin status

        if username and password:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists. Please choose a different one.', 'error')
            else:
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, password=hashed_password, is_admin=is_admin)
                db.session.add(new_user)
                db.session.commit()
                flash(f'User "{username}" has been created successfully.', 'success')
        else:
            flash('Username and password are required.', 'error')

    users = User.query.all()  # Get all users
    Exams = Exam.query.all()  # Get all Exams

    return render_template('manage_users.html', users=users, Exams=Exams)




@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User "{user.username}" has been deleted successfully.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_Exam', methods=['GET', 'POST'])
@login_required
def create_Exam():
    if request.method == 'POST':
        title = request.form['title']
        question_count = request.form.get('question_count')

        if question_count is None:
            flash('Please provide the number of questions.', 'error')
            return redirect(url_for('create_Exam'))

        # Convert question_count to an integer if it's provided
        question_count = int(question_count)

        new_Exam = Exam(title=title, question_count=question_count)
        db.session.add(new_Exam)
        db.session.commit()
        flash('Exam created successfully!', 'success')
        return redirect(url_for('manage_Exams'))

    return render_template('create_Exam.html')

    

@app.route('/admin/manage_Exams', methods=['GET', 'POST'])
@login_required
def manage_Exams():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    Exams = Exam.query.all()  # Get all Exams from the database
    return render_template('manage_Exams.html', Exams=Exams)


@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    Exam_id = question.Exam_id  # Store the Exam ID before deleting the question
    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully.', 'success')
    return redirect(url_for('manage_questions', Exam_id=Exam_id))


@app.route('/admin/revoke_Exam_access/<int:user_id>', methods=['POST'])
@login_required
def revoke_Exam_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    Exam_id = request.form['Exam_id']
    
    # Eager load the Exam relationship using joinedload
    access = ExamAccess.query.options(joinedload(ExamAccess.Exam)).filter_by(user_id=user.id, Exam_id=Exam_id).first()

    if access:
        db.session.delete(access)
        db.session.commit()
        flash(f'Access to Exam "{access.Exam.title}" has been revoked from user "{user.username}".', 'success')
    else:
        flash(f'User "{user.username}" does not have access to the selected Exam.', 'error')

    return redirect(url_for('manage_users'))


@app.route('/admin/completed_Exam/<int:Exam_result_id>/view', methods=['GET'])
@login_required
def view_completed_Exam(Exam_result_id):
    Exam_result = ExamResult.query.get_or_404(Exam_result_id)
    questions = Exam_result.Exam.questions

    # Ensure the user has permission to view this result
    if not current_user.is_admin and Exam_result.user_id != current_user.id:
        flash('You do not have permission to view this Exam result.', 'error')
        return redirect(url_for('home'))

    return render_template('view_completed_Exam.html', Exam_result=Exam_result, questions=questions)



@app.route('/admin/delete_completed_Exam/<int:Exam_result_id>', methods=['POST'])
@login_required
def delete_completed_Exam(Exam_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    # Use joinedload to eagerly load the 'Exam' relationship
    Exam_result = ExamResult.query.options(joinedload(ExamResult.Exam), joinedload(ExamResult.user)).get_or_404(Exam_result_id)

    # Store information for the flash message before deleting
    Exam_title = Exam_result.Exam.title if Exam_result.Exam else "Unknown Exam"
    username = Exam_result.user.username if Exam_result.user else "Unknown User"

    try:
        db.session.delete(Exam_result)
        db.session.commit()
        flash(f'Exam result for "{Exam_title}" by {username} has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the Exam result: {str(e)}', 'error')

    return redirect(url_for('admin_dashboard'))


@app.cli.command("delete-all-users")
def delete_all_users():
    """Delete all users from the database"""
    confirm = input("Are you sure you want to delete all users? Type 'yes' to confirm: ")
    if confirm.lower() == 'yes':
        num_deleted = User.query.delete()  # This deletes all records in the User table
        db.session.commit()
        print(f"Deleted {num_deleted} users.")
    else:
        print("Operation canceled.")


@app.cli.command("create-admin")
@click.argument("username")

@click.argument("password")
def create_admin_command(username, password):
    """Create an admin user."""
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        click.echo(f'User {username} already exists.')
        return
    
    hashed_password = generate_password_hash(password)
    new_admin = User(username=username, password=hashed_password, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    click.echo(f'Admin user {username} created successfully.')

@app.cli.command("list-users")
def list_users():
    """List all users"""
    users = User.query.all()
    if not users:
        print("No users found.")
        return

    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Admin: {user.is_admin}")


@app.cli.command("add-Exam")
@click.argument("title")
def add_Exam_command(title):
    """Add a new Exam."""
    new_Exam = Exam(title=title)
    db.session.add(new_Exam)
    db.session.commit()
    click.echo(f'Exam "{title}" added successfully with ID: {new_Exam.id}')


@app.route('/admin/edit_Exam/<int:Exam_id>', methods=['GET', 'POST'])
@login_required
def edit_Exam(Exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    Exam = Exam.query.get_or_404(Exam_id)

    if request.method == 'POST':
        title = request.form['title'].strip()

        # Check if a Exam with the new title already exists
        existing_Exam = Exam.query.filter_by(title=title).first()
        if existing_Exam and existing_Exam.id != Exam_id:
            flash(f'A Exam with the title "{title}" already exists. Please choose a different title.', 'error')
            return redirect(url_for('edit_Exam', Exam_id=Exam_id))

        if title:
            Exam.title = title
            db.session.commit()
            flash(f'Exam "{title}" has been updated successfully.', 'success')
            return redirect(url_for('manage_Exams'))
        else:
            flash('Title is required to update the Exam.', 'error')

    return render_template('edit_Exam.html', Exam=Exam)


@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    Exams = Exam.query.all()  # Get all available Exams

    if request.method == 'POST':
        Exam_id = request.form['Exam_id']  # Get the selected Exam ID
        Exam = Exam.query.get_or_404(Exam_id)

        question_type = request.form['question_type']
        content = request.form['content']
        correct_answer = request.form['correct_answer']

        if question_type == 'multiple_choice':
            option_a = request.form['option_a']
            option_b = request.form['option_b']
            option_c = request.form['option_c']
            option_d = request.form['option_d']
            question = Question(
                content=content,
                option_a=option_a,
                option_b=option_b,
                option_c=option_c,
                option_d=option_d,
                correct_answer=correct_answer,
                Exam_id=Exam.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                Exam_id=Exam.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('add_question'))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to Exam "{Exam.title}".', 'success')
        return redirect(url_for('add_question'))

    return render_template('add_question.html', Exams=Exams)



@app.route('/admin/import_questions', methods=['GET', 'POST'])
@login_required
def import_questions():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    Exams = Exam.query.all()  # Fetch all Exams from the database

    if request.method == 'POST':
        file = request.files['file']
        Exam_id = request.form.get('Exam_id')
        Exam = Exam.query.get(Exam_id)  # Fetch the Exam

        if not Exam:
            flash('Exam not found.', 'error')
            return redirect(url_for('import_questions'))

        if not file:
            flash('No file selected!', 'error')
            return redirect(request.url)

        # Read the file and handle potential BOM
        file_stream = file.stream.read().decode('utf-8-sig').splitlines()
        csv_reader = csv.DictReader(file_stream)

        for row in csv_reader:
            try:
                question_type = row['type'].strip().lower()
                content = row['content'].strip()
                correct_answer = row['correct_answer'].strip()

                if question_type == 'multiple_choice':
                    option_a = row['option_a'].strip()
                    option_b = row['option_b'].strip()
                    option_c = row.get('option_c', '').strip() or ''
                    option_d = row.get('option_d', '').strip() or ''
                elif question_type == 'true_false':
                    option_a = 'True'
                    option_b = 'False'
                    option_c = ''
                    option_d = ''
                else:
                    flash(f'Unknown question type: {question_type}', 'error')
                    continue

                question = Question(
                    content=content,
                    option_a=option_a,
                    option_b=option_b,
                    option_c=option_c,
                    option_d=option_d,
                    correct_answer=correct_answer,
                    Exam_id=Exam.id  # Ensure this is set
                )
                db.session.add(question)
            except Exception as e:
                db.session.rollback()
                flash(f'Error importing question: {e}', 'error')
                continue

        db.session.commit()
        flash('Questions imported successfully!', 'success')
        return redirect(url_for('manage_questions', Exam_id=Exam.id))

    return render_template('import_questions.html', Exams=Exams)




@app.route('/admin/list_Exams')
@login_required
def list_Exams():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    Exams = Exam.query.all()
    return render_template('list_Exams.html', Exams=Exams)

@app.route('/admin/')
@login_required
def admin_redirect():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))


@app.route('/admin/delete_Exam/<int:Exam_id>', methods=['POST'])
@login_required
def delete_Exam(Exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    Exam = Exam.query.get_or_404(Exam_id)

    # Delete the Exam from the database
    db.session.delete(Exam)
    db.session.commit()
    flash(f'Exam "{Exam.title}" has been deleted successfully.', 'success')

    return redirect(url_for('manage_Exams'))



@app.route('/take_Exam/<int:Exam_id>', methods=['GET', 'POST'])
@login_required
def take_Exam(Exam_id):
    Exam_access = ExamAccess.query.filter_by(user_id=current_user.id, Exam_id=Exam_id).first()
    if not Exam_access or not Exam_access.is_accessible:
        flash('You do not have access to this Exam.', 'error')
        return redirect(url_for('home'))

    Exam = Exam.query.get_or_404(Exam_id)
    total_questions = len(Exam.questions)

    # Initialize session data if not already present
    if 'answers' not in session:
        session['answers'] = {}
    if 'flagged' not in session:
        session['flagged'] = {str(q.id): False for q in Exam.questions}
    if 'current_index' not in session:
        session['current_index'] = 0
    if 'start_time' not in session:
        session['start_time'] = datetime.utcnow().isoformat()

    if request.method == 'POST':
        action = request.form.get('action')
        current_question_id = str(Exam.questions[session['current_index']].id)

        print(f"Before Processing: Current Index: {session['current_index']}, Answers: {session['answers']}")

        if action == 'submit_answer':
            answer = request.form.get('answer')
            if answer:
                session['answers'][current_question_id] = answer
                session['current_index'] = (session['current_index'] + 1) % total_questions
                flash('Answer saved', 'success')

        elif action == 'flag':
            session['flagged'][current_question_id] = not session['flagged'][current_question_id]
            flag_status = 'flagged' if session['flagged'][current_question_id] else 'unflagged'
            flash(f'Question {flag_status}', 'info')

        elif action == 'submit_Exam':
            session.modified = True  # Ensure session is saved before redirect
            return redirect(url_for('submit_Exam', Exam_id=Exam_id))

        session.modified = True

        print(f"After Processing: Current Index: {session['current_index']}, Answers: {session['answers']}")

    current_question = Exam.questions[session['current_index']]
    progress = sum(1 for answer in session['answers'].values() if answer)
    flagged_questions = [i for i, q in enumerate(Exam.questions) if session['flagged'][str(q.id)]]
    time_elapsed = (datetime.utcnow() - datetime.fromisoformat(session['start_time'])).total_seconds() / 60

    all_questions_answered = progress == total_questions

    return render_template('take_Exam.html', 
                           Exam=Exam,
                           current_question=current_question,
                           current_index=session['current_index'], 
                           progress=progress,
                           total_questions=total_questions, 
                           flagged_questions=flagged_questions,
                           time_elapsed=time_elapsed, 
                           answers=session['answers'],
                           flagged=session['flagged'],
                           all_questions_answered=all_questions_answered)








@app.route('/request_retake/<int:Exam_id>', methods=['POST'])
@login_required
def request_retake(Exam_id):
    Exam_access = ExamAccess.query.filter_by(user_id=current_user.id, Exam_id=Exam_id).first()
    if Exam_access:
        Exam_access.is_accessible = True
        db.session.commit()
        flash('Retake request submitted successfully.', 'success')
    else:
        flash('You do not have access to retake this Exam.', 'error')
    return redirect(url_for('home'))



@app.route('/admin/export_Exam_result/<int:Exam_result_id>', methods=['GET'])
@login_required
def export_Exam_result(Exam_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch the Exam result object
    Exam_result = ExamResult.query.get_or_404(Exam_result_id)
    user_answers = {}

    # Fetch answers directly from session or another reliable source
    for question in Exam_result.Exam.questions:
        missed_question = MissedQuestion.query.filter_by(Exam_result_id=Exam_result.id, question_id=question.id).first()

        if missed_question:
            # Use the missed question's user answer if it exists
            user_answers[question.id] = missed_question.user_answer
        else:
            # Attempt to fetch the correct answer from session or default to 'No Answer'
            user_answer = session.get('answers', {}).get(str(question.id))
            if user_answer:
                user_answer_content = getattr(question, f"option_{user_answer.lower()}", user_answer)
                user_answers[question.id] = user_answer_content
            else:
                user_answers[question.id] = "No Answer"

    return render_template('export_Exam_result.html', Exam_result=Exam_result, user_answers=user_answers)








if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)