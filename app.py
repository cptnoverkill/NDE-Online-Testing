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
import os
from models import db, User, Exam, Question, ExamAccess, ExamResult, MissedQuestion, ExamAccessRequest


app = Flask(__name__)
app.config['SECRET_KEY'] = 'FF93B3ABE7'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or'sqlite:///knowledge_test.db'
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
    exam_endpoints = ['take_exam', 'submit_exam']
    current_endpoint = request.endpoint

    if current_endpoint is None:
        return
    
def clear_session_before_new_exam():
    if 'start_new_exam' in request.args:
        session.clear()

@app.route('/clear_cache')
@login_required
def clear_cache():
    session.clear()  # Clear Flask session
    flash('Cache cleared.', 'success')
    return redirect(url_for('home'))


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
    # Flash the exam score if present in session
    if 'exam_score' in session:
        flash(f'You scored {session["exam_score"]:.2f}%.', 'success')
        session.pop('exam_score', None)

    if current_user.is_authenticated:
        if current_user.is_admin:
            accessible_exams = Exam.query.all()  # Admins see all Exams
            inaccessible_exams = []
            pending_exams = []
        else:
            # Fetch all ExamAccess records for the user
            exam_accesses = ExamAccess.query.filter_by(user_id=current_user.id).all()
            
            accessible_exams = []
            inaccessible_exams = []
            pending_exams = []

            for access in exam_accesses:
                if access.is_accessible:
                    accessible_exams.append(access.exam)
                else:
                    inaccessible_exams.append(access.exam)

            # Get Exams the user has requested access to, but are pending approval
            pending_requests = ExamAccessRequest.query.filter_by(user_id=current_user.id, status='pending').all()
            pending_exams = [request.exam for request in pending_requests]

            # Get Exams the user has not requested access to
            all_accessible_exam_ids = [exam.id for exam in accessible_exams]
            all_inaccessible_exam_ids = [exam.id for exam in inaccessible_exams]
            all_pending_exam_ids = [exam.id for exam in pending_exams]
            all_exam_ids = all_accessible_exam_ids + all_inaccessible_exam_ids + all_pending_exam_ids

            unavailable_exams = Exam.query.filter(~Exam.id.in_(all_exam_ids)).all()
            inaccessible_exams.extend(unavailable_exams)

        # Ensure no duplicates
        accessible_exams = list(set(accessible_exams))
        inaccessible_exams = list(set(inaccessible_exams) - set(accessible_exams))

        # Get the Exams that have been taken by the current user
        taken_exams = ExamResult.query.filter_by(user_id=current_user.id).all()

        return render_template(
            'home.html',
            accessible_exams=accessible_exams,
            inaccessible_exams=inaccessible_exams,
            taken_exams=taken_exams,
            pending_exams=pending_exams
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
    session.clear()
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
def manage_exam_session():
    if 'start_new_exam' in request.args:
        # Clear session when starting a new Exam
        session.pop('answers', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
    elif 'exam_submitted' in session and request.endpoint != 'exam_results':
        # Clear session after viewing results, but not on the results page itself
        session.pop('answers', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
        session.pop('exam_submitted', None)




@app.route('/submit_exam/<int:exam_id>', methods=['POST'])
@login_required
def submit_exam(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    user_id = current_user.id

    total_questions = len(exam.questions)
    correct_answers = 0

    answers = session.get('answers', {})

    if not answers:
        flash("There was an issue with your session data. Please try again.", "error")
        return redirect(url_for('take_exam', exam_id=exam_id))

    exam_result = ExamResult(user_id=user_id, exam_id=exam_id, score=0)
    db.session.add(exam_result)
    db.session.commit()

    for question in exam.questions:
        question_id_str = str(question.id)
        user_answer = answers.get(question_id_str)

        if user_answer is not None:
            if question.correct_answer in ['A', 'B', 'C', 'D']:
                correct_answer_content = getattr(question, f"option_{question.correct_answer.lower()}")
            else:
                correct_answer_content = question.correct_answer

            correct_answer_content = correct_answer_content.strip().lower()
            user_answer_content = getattr(question, f"option_{user_answer.lower()}", user_answer).strip().lower()

            if user_answer_content == correct_answer_content:
                correct_answers += 1
            else:
                missed_question = MissedQuestion(
                    exam_result_id=exam_result.id,
                    question_id=question.id,
                    user_answer=user_answer_content
                )
                db.session.add(missed_question)

    score = (correct_answers / total_questions) * 100
    exam_result.score = score
    db.session.commit()

    # Store the score in the session
    session['exam_score'] = score

    exam_access = ExamAccess.query.filter_by(user_id=user_id, exam_id=exam_id).first()
    if exam_access:
        exam_access.is_accessible = False
        db.session.commit()
        
    # Flash the score immediately
    flash(f'You scored {score:.2f}%.', 'success')
    session.clear()  # Clear all session data after submission

    return redirect(url_for('home'))



   
    return redirect(url_for('home'))






@app.route('/request_access/<int:exam_id>', methods=['POST'])
@login_required
def request_access(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    existing_request = ExamAccessRequest.query.filter_by(user_id=current_user.id, exam_id=exam_id, status='pending').first()
    if existing_request:
        flash('You have already requested access to this Exam.', 'info')
    else:
        new_request = ExamAccessRequest(user_id=current_user.id, exam_id=exam_id)
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
    
    new_access = ExamAccess(user_id=access_request.user_id, exam_id=access_request.exam_id, is_accessible=True)
    db.session.add(new_access)
    db.session.commit()

    flash(f'Access request for Exam "{access_request.exam.title}" by user "{access_request.user.username}" approved.', 'success')
    return redirect(url_for('admin_dashboard'))

    if exam_access_request:
        exam_access_request.user_id = user_id  # Ensure user_id is not None
        db.session.commit()
    else:
        flash("Request not found.", "error")

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

    flash(f'Access request for Exam "{access_request.exam.title}" by user "{access_request.user.username}" denied.', 'success')
    return redirect(url_for('admin_dashboard'))

    if exam_access_request:
        exam_access_request.user_id = user_id  # Ensure user_id is not None
        db.session.commit()
    else:
        flash("Request not found.", "error")


@app.route('/admin/grant_exam_access/<int:user_id>', methods=['POST'])
@login_required
def grant_exam_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    exam_id = request.form['exam_id']
    exam = Exam.query.get_or_404(exam_id)

    # Check if the user already has access to the Exam
    existing_access = ExamAccess.query.filter_by(user_id=user.id, exam_id=exam.id).first()
    if existing_access:
        flash(f'User "{user.username}" already has access to the Exam "{exam.title}".', 'info')
    else:
        # Grant access to the Exam
        new_access = ExamAccess(user_id=user.id, exam_id=exam.id, is_accessible=True)
        db.session.add(new_access)
        db.session.commit()
        flash(f'Access to Exam "{exam.title}" has been granted to user "{user.username}".', 'success')

    return redirect(url_for('manage_users'))

@app.route('/admin/manage_questions/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def manage_questions(exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam.id).all()

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
                exam_id=exam.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                exam_id=exam.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('manage_questions', exam_id=exam.id))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to Exam "{exam.title}".', 'success')
        return redirect(url_for('manage_questions', exam_id=exam.id))

    return render_template('manage_questions.html', exam=exam, questions=questions)


@app.route('/dashboard')
@login_required
def user_dashboard():
    user_requests = ExamAccessRequest.query.filter_by(user_id=current_user.id).all()
    exam_results = ExamResult.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', requests=user_requests, exam_results=exam_results)


@app.route('/exam_results/<int:exam_result_id>', methods=['GET'])
@login_required
def exam_results(exam_result_id):
    exam_result = ExamResult.query.get_or_404(exam_result_id)
    questions = exam_result.exam.questions
    
    # Ensure the user has permission to view this result
    if not current_user.is_admin and exam_result.user_id != current_user.id:
        flash('You do not have permission to view this Exam result.', 'error')
        return redirect(url_for('home'))

    return render_template('exam_results.html', exam_result=exam_result, questions=questions)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    completed_exams = ExamResult.query.all()  # Ensure this query is executed correctly
    pending_requests = ExamAccessRequest.query.filter_by(status='pending').all()

    return render_template('admin_dashboard.html', completed_exams= [] or completed_exams, pending_requests=pending_requests)





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
    exams = Exam.query.all()  # Get all Exams

    return render_template('manage_users.html', users=users, exams=exams)




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
        try:
            # Delete related ExamResults
            ExamResult.query.filter_by(user_id=user_id).delete()

            # Add any other related deletions here if necessary

            db.session.delete(user)
            db.session.commit()
            flash(f'User "{user.username}" has been deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while deleting the user: {str(e)}", "error")

    return redirect(url_for('manage_users'))

   


@app.route('/create_exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    if request.method == 'POST':
        title = request.form['title']
        question_count = request.form.get('question_count')


        if question_count is None:
            flash('Please provide the number of questions.', 'error')
            return redirect(url_for('create_exam'))

        # Convert question_count to an integer if it's provided
        question_count = int(question_count)

        new_exam = Exam(title=title, question_count=question_count)
        db.session.add(new_exam)
        db.session.commit()
        flash('Exam created successfully!', 'success')
        return redirect(url_for('manage_exams'))

    return render_template('create_exam.html')

    

@app.route('/admin/manage_exams', methods=['GET', 'POST'])
@login_required
def manage_exams():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    exams = Exam.query.all()  # Get all Exams from the database
    return render_template('manage_exams.html', exams=exams)


@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id  # Store the Exam ID before deleting the question
    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully.', 'success')
    return redirect(url_for('manage_questions', exam_id=exam_id))


@app.route('/admin/revoke_exam_access/<int:user_id>', methods=['POST'])
@login_required
def revoke_exam_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    exam_id = request.form['exam_id']
    
    # Eager load the Exam relationship using joinedload
    access = ExamAccess.query.options(joinedload(ExamAccess.exam)).filter_by(user_id=user.id, exam_id=exam_id).first()

    if access:
        db.session.delete(access)
        db.session.commit()
        flash(f'Access to Exam "{access.exam.title}" has been revoked from user "{user.username}".', 'success')
    else:
        flash(f'User "{user.username}" does not have access to the selected Exam.', 'error')

    return redirect(url_for('manage_users'))


@app.route('/admin/completed_exam/<int:exam_result_id>/view', methods=['GET'])
@login_required
def view_completed_exam(exam_result_id):
    exam_result = ExamResult.query.get_or_404(exam_result_id)
    questions = exam_result.exam.questions

    # Ensure the user has permission to view this result
    if not current_user.is_admin and exam_result.user_id != current_user.id:
        flash('You do not have permission to view this Exam result.', 'error')
        return redirect(url_for('home'))

    return render_template('view_completed_exam.html', exam_result=exam_result, questions=questions)



@app.route('/admin/delete_completed_exam/<int:exam_result_id>', methods=['POST'])
@login_required
def delete_completed_exam(exam_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    # Use joinedload to eagerly load the 'Exam' relationship
    exam_result = ExamResult.query.options(joinedload(ExamResult.exam), joinedload(ExamResult.user)).get_or_404(exam_result_id)

    # Store information for the flash message before deleting
    exam_title = exam_result.exam.title if exam_result.exam else "Unknown Exam"
    username = exam_result.user.username if exam_result.user else "Unknown User"

    try:
        db.session.delete(exam_result)
        db.session.commit()
        flash(f'Exam result for "{exam_title}" by {username} has been deleted.', 'success')
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
def add_exam_command(title):
    """Add a new Exam."""
    new_exam = Exam(title=title)
    db.session.add(new_exam)
    db.session.commit()
    click.echo(f'Exam "{title}" added successfully with ID: {new_exam.id}')


@app.route('/admin/edit_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def edit_exam(exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    Exam = Exam.query.get_or_404(exam_id)

    if request.method == 'POST':
        title = request.form['title'].strip()

        # Check if a Exam with the new title already exists
        existing_exam = Exam.query.filter_by(title=title).first()
        if existing_exam and existing_exam.id != exam_id:
            flash(f'A Exam with the title "{title}" already exists. Please choose a different title.', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))

        if title:
            Exam.title = title
            db.session.commit()
            flash(f'Exam "{title}" has been updated successfully.', 'success')
            return redirect(url_for('manage_exams'))
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
        exam_id = request.form['exam_id']  # Get the selected Exam ID
        Exam = Exam.query.get_or_404(exam_id)

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
                exam_id=exam.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                exam_id=exam.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('add_question'))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to Exam "{Exam.title}".', 'success')
        return redirect(url_for('add_question'))

    return render_template('add_question.html', exams=exams)



@app.route('/admin/import_questions', methods=['GET', 'POST'])
@login_required
def import_questions():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    exams = Exam.query.all()  # Fetch all Exams from the database

    if request.method == 'POST':
        file = request.files['file']
        exam_id = request.form.get('exam_id')
        exam = Exam.query.get(exam_id)  # Fetch the Exam

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
                    exam_id=exam.id  # Ensure this is set
                )
                db.session.add(question)
            except Exception as e:
                db.session.rollback()
                flash(f'Error importing question: {e}', 'error')
                continue

        db.session.commit()
        flash('Questions imported successfully!', 'success')
        return redirect(url_for('manage_questions', exam_id=exam.id))

    return render_template('import_questions.html', exams=exams)




@app.route('/admin/list_exams')
@login_required
def list_exams():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    Exams = Exam.query.all()
    return render_template('list_exams.html', exams=exams)

@app.route('/admin/')
@login_required
def admin_redirect():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))


@app.route('/admin/delete_exam/<int:exam_id>', methods=['POST'])
@login_required
def delete_exam(exam_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    exam = Exam.query.get_or_404(exam_id)

    # Delete the Exam from the database
    db.session.delete(exam)
    db.session.commit()
    flash(f'Exam "{exam.title}" has been deleted successfully.', 'success')

    return redirect(url_for('manage_exams'))



@app.route('/take_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def take_exam(exam_id):
    exam_access = ExamAccess.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    if not exam_access or not exam_access.is_accessible:
        flash('You do not have access to this exam.', 'error')
        return redirect(url_for('home'))

    exam = Exam.query.get_or_404(exam_id)

    if 'answers' not in session:
        session['answers'] = {}

    if request.method == 'POST':
        for question in exam.questions:
            answer = request.form.get(f'answer_{question.id}')
            if answer:
                session['answers'][str(question.id)] = answer
        
        session.modified = True
        return redirect(url_for('review_exam', exam_id=exam_id))

    questions = exam.questions

    return render_template('take_exam.html', 
                           exam=exam,
                           questions=questions,
                           answers=session['answers'])




@app.route('/review_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def review_exam(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    answers = session.get('answers', {})

    if request.method == 'POST':
        # When the form is submitted, redirect to submit_exam
        return redirect(url_for('submit_exam', exam_id=exam_id))

    questions = exam.questions  # No need to call .all() since questions is already a list

    return render_template('review_exam.html', exam=exam, questions=questions, answers=answers)





@app.route('/request_retake/<int:exam_id>', methods=['POST'])
@login_required
def request_retake(exam_id):
    exam_access = ExamAccess.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    if exam_access:
        exam_access.is_accessible = True
        db.session.commit()
        flash('Retake request submitted successfully.', 'success')
    else:
        flash('You do not have access to retake this Exam.', 'error')
    return redirect(url_for('home'))



@app.route('/admin/export_exam_result/<int:exam_result_id>', methods=['GET'])
@login_required
def export_exam_result(exam_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch the Exam result object
    exam_result = ExamResult.query.get_or_404(exam_result_id)
    user_answers = {}

    # Fetch answers directly from session or another reliable source
    for question in exam_result.exam.questions:
        missed_question = MissedQuestion.query.filter_by(exam_result_id=exam_result.id, question_id=question.id).first()

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

    return render_template('export_exam_result.html', exam_result=exam_result, user_answers=user_answers)



@app.cli.command("cleanup")
def cleanup():
    """Clean up orphaned data in the database."""
    # Add your queries to delete orphaned data here
    db.session.commit()
    print("Cleanup completed.")




#if __name__ == '__main__':
#    with app.app_context():
#        db.create_all()
#    app.run(debug=True)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)