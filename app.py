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
from models import db, User, Test, Question, TestAccess, TestResult, MissedQuestion, TestAccessRequest

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
    test_endpoints = ['take_test', 'submit_test']
    current_endpoint = request.endpoint

    if current_endpoint is None:
        return
    
    
    #if current_endpoint not in test_endpoints and session.get('taking_test'):
        # Reset session only if the user is navigating away and not refreshing or reloading
       # session.clear()  # Clear all session data if needed or be selective
    #elif current_endpoint in test_endpoints:
    #    session['taking_test'] = True



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
admin = Admin(app, name='Knowledge Test Admin', template_mode='bootstrap3')

# Add model views
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Test, db.session))
admin.add_view(SecureModelView(Question, db.session))
admin.add_view(SecureModelView(TestAccess, db.session))  # Assuming SecureModelView is used instead of TestAccessModelView
admin.add_view(SecureModelView(TestResult, db.session))
admin.add_view(SecureModelView(MissedQuestion, db.session))

# Add file admin
path = op.join(op.dirname(__file__), 'static')
admin.add_view(FileAdmin(path, '/static/', name='Static Files'))


@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            accessible_tests = Test.query.all()  # Admins see all tests
            inaccessible_tests = []
            pending_tests = []
        else:
            # Fetch all TestAccess records for the user
            test_accesses = TestAccess.query.filter_by(user_id=current_user.id).all()
            
            accessible_tests = []
            inaccessible_tests = []
            pending_tests = []

            for access in test_accesses:
                if access.is_accessible:
                    accessible_tests.append(access.test)
                else:
                    inaccessible_tests.append(access.test)

            # Get tests the user has requested access to, but are pending approval
            pending_requests = TestAccessRequest.query.filter_by(user_id=current_user.id, status='pending').all()
            pending_tests = [request.test for request in pending_requests]

            # Get tests the user has not requested access to
            all_accessible_test_ids = [test.id for test in accessible_tests]
            all_inaccessible_test_ids = [test.id for test in inaccessible_tests]
            all_pending_test_ids = [test.id for test in pending_tests]
            all_test_ids = all_accessible_test_ids + all_inaccessible_test_ids + all_pending_test_ids

            unavailable_tests = Test.query.filter(~Test.id.in_(all_test_ids)).all()
            inaccessible_tests.extend(unavailable_tests)

        # Ensure no duplicates
        accessible_tests = list(set(accessible_tests))
        inaccessible_tests = list(set(inaccessible_tests) - set(accessible_tests))

        # Get the tests that have been taken by the current user
        taken_tests = TestResult.query.filter_by(user_id=current_user.id).all()

        return render_template(
            'home.html',
            accessible_tests=accessible_tests,
            inaccessible_tests=inaccessible_tests,
            taken_tests=taken_tests,
            pending_tests=pending_tests
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
def manage_test_session():
    if 'start_new_test' in request.args:
        # Clear session when starting a new test
        session.pop('answers', None)
        session.pop('flagged', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
    elif 'test_submitted' in session and request.endpoint != 'test_results':
        # Clear session after viewing results, but not on the results page itself
        session.pop('answers', None)
        session.pop('flagged', None)
        session.pop('current_index', None)
        session.pop('start_time', None)
        session.pop('test_submitted', None)




@app.route('/submit_test/<int:test_id>', methods=['POST'])
@login_required
def submit_test(test_id):
    test = Test.query.get_or_404(test_id)
    user_id = current_user.id

    total_questions = len(test.questions)
    correct_answers = 0

    # Debugging: Check the session data
    print("Session data before processing:", session.get('answers'))

    if 'answers' not in session:
        flash("There was an issue with your session data. Please try again.", "error")
        return redirect(url_for('take_test', test_id=test_id))

    test_result = TestResult(user_id=user_id, test_id=test_id, score=0)
    db.session.add(test_result)
    db.session.commit()

    for question in test.questions:
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
                test_result_id=test_result.id,
                question_id=question.id,
                user_answer=user_answer_content
            )
            db.session.add(missed_question)

    score = (correct_answers / total_questions) * 100
    test_result.score = score
    db.session.commit()

    # Mark the test as no longer accessible
    test_access = TestAccess.query.filter_by(user_id=user_id, test_id=test_id).first()
    if test_access:
        test_access.is_accessible = False
        db.session.commit()

    # Clear session data after submission
    session.pop('answers', None)
    session.pop('flagged', None)
    session.pop('skipped', None)
    session.pop('current_index', None)
    session.pop('start_time', None)
    session.pop('taking_test', None)

    flash(f'You scored {score:.2f}%.', 'success')
    return redirect(url_for('home'))







@app.route('/request_access/<int:test_id>', methods=['POST'])
@login_required
def request_access(test_id):
    test = Test.query.get_or_404(test_id)
    existing_request = TestAccessRequest.query.filter_by(user_id=current_user.id, test_id=test_id, status='pending').first()
    if existing_request:
        flash('You have already requested access to this test.', 'info')
    else:
        new_request = TestAccessRequest(user_id=current_user.id, test_id=test_id)
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
    
    pending_requests = TestAccessRequest.query.filter_by(status='pending').all()
    return render_template('admin_access_requests.html', requests=pending_requests)

@app.route('/admin/approve_access/<int:request_id>', methods=['POST'])
@login_required
def approve_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))
    
    access_request = TestAccessRequest.query.get_or_404(request_id)
    access_request.status = 'approved'
    access_request.response_date = datetime.utcnow()
    
    new_access = TestAccess(user_id=access_request.user_id, test_id=access_request.test_id, is_accessible=True)
    db.session.add(new_access)
    db.session.commit()

    flash(f'Access request for test "{access_request.test.title}" by user "{access_request.user.username}" approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deny_access/<int:request_id>', methods=['POST'], endpoint='admin_deny_access')
@login_required
def deny_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    access_request = TestAccessRequest.query.get_or_404(request_id)
    access_request.status = 'denied'
    access_request.response_date = datetime.utcnow()
    access_request.admin_comment = request.form.get('admin_comment', '')
    db.session.commit()

    flash(f'Access request for test "{access_request.test.title}" by user "{access_request.user.username}" denied.', 'success')
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/grant_test_access/<int:user_id>', methods=['POST'])
@login_required
def grant_test_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    test_id = request.form['test_id']
    test = Test.query.get_or_404(test_id)

    # Check if the user already has access to the test
    existing_access = TestAccess.query.filter_by(user_id=user.id, test_id=test.id).first()
    if existing_access:
        flash(f'User "{user.username}" already has access to the test "{test.title}".', 'info')
    else:
        # Grant access to the test
        new_access = TestAccess(user_id=user.id, test_id=test.id, is_accessible=True)
        db.session.add(new_access)
        db.session.commit()
        flash(f'Access to test "{test.title}" has been granted to user "{user.username}".', 'success')

    return redirect(url_for('manage_users'))

@app.route('/admin/manage_questions/<int:test_id>', methods=['GET', 'POST'])
@login_required
def manage_questions(test_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    test = Test.query.get_or_404(test_id)
    questions = Question.query.filter_by(test_id=test.id).all()

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
                test_id=test.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                test_id=test.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('manage_questions', test_id=test.id))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to test "{test.title}".', 'success')
        return redirect(url_for('manage_questions', test_id=test.id))

    return render_template('manage_questions.html', test=test, questions=questions)


@app.route('/admin/deny_access/<int:request_id>', methods=['POST'])
@login_required
def deny_access(request_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))
    
    access_request = TestAccessRequest.query.get_or_404(request_id)
    access_request.status = 'denied'
    access_request.response_date = datetime.utcnow()
    access_request.admin_comment = request.form.get('admin_comment', '')
    db.session.commit()

    
    flash('Access request denied.', 'success')
    return redirect(url_for('admin_access_requests'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    user_requests = TestAccessRequest.query.filter_by(user_id=current_user.id).all()
    test_results = TestResult.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', requests=user_requests, test_results=test_results)


@app.route('/test_results/<int:test_result_id>', methods=['GET'])
@login_required
def test_results(test_result_id):
    test_result = TestResult.query.get_or_404(test_result_id)
    questions = test_result.test.questions
    
    # Ensure the user has permission to view this result
    if not current_user.is_admin and test_result.user_id != current_user.id:
        flash('You do not have permission to view this test result.', 'error')
        return redirect(url_for('home'))

    return render_template('test_results.html', test_result=test_result, questions=questions)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    completed_tests = TestResult.query.all()  # Ensure this query is executed correctly
    pending_requests = TestAccessRequest.query.filter_by(status='pending').all()

    return render_template('admin_dashboard.html', completed_tests= [] or completed_tests, pending_requests=pending_requests)





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
    tests = Test.query.all()  # Get all tests

    return render_template('manage_users.html', users=users, tests=tests)




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


@app.route('/create_test', methods=['GET', 'POST'])
@login_required
def create_test():
    if request.method == 'POST':
        title = request.form['title']
        question_count = request.form.get('question_count')

        if question_count is None:
            flash('Please provide the number of questions.', 'error')
            return redirect(url_for('create_test'))

        # Convert question_count to an integer if it's provided
        question_count = int(question_count)

        new_test = Test(title=title, question_count=question_count)
        db.session.add(new_test)
        db.session.commit()
        flash('Test created successfully!', 'success')
        return redirect(url_for('manage_tests'))

    return render_template('create_test.html')

    

@app.route('/admin/manage_tests', methods=['GET', 'POST'])
@login_required
def manage_tests():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    tests = Test.query.all()  # Get all tests from the database
    return render_template('manage_tests.html', tests=tests)


@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    test_id = question.test_id  # Store the test ID before deleting the question
    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully.', 'success')
    return redirect(url_for('manage_questions', test_id=test_id))


@app.route('/admin/revoke_test_access/<int:user_id>', methods=['POST'])
@login_required
def revoke_test_access(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    test_id = request.form['test_id']
    
    # Eager load the test relationship using joinedload
    access = TestAccess.query.options(joinedload(TestAccess.test)).filter_by(user_id=user.id, test_id=test_id).first()

    if access:
        db.session.delete(access)
        db.session.commit()
        flash(f'Access to test "{access.test.title}" has been revoked from user "{user.username}".', 'success')
    else:
        flash(f'User "{user.username}" does not have access to the selected test.', 'error')

    return redirect(url_for('manage_users'))


@app.route('/admin/completed_test/<int:test_result_id>/view', methods=['GET'])
@login_required
def view_completed_test(test_result_id):
    test_result = TestResult.query.get_or_404(test_result_id)
    questions = test_result.test.questions

    # Ensure the user has permission to view this result
    if not current_user.is_admin and test_result.user_id != current_user.id:
        flash('You do not have permission to view this test result.', 'error')
        return redirect(url_for('home'))

    return render_template('view_completed_test.html', test_result=test_result, questions=questions)



@app.route('/admin/delete_completed_test/<int:test_result_id>', methods=['POST'])
@login_required
def delete_completed_test(test_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    # Use joinedload to eagerly load the 'test' relationship
    test_result = TestResult.query.options(joinedload(TestResult.test), joinedload(TestResult.user)).get_or_404(test_result_id)

    # Store information for the flash message before deleting
    test_title = test_result.test.title if test_result.test else "Unknown Test"
    username = test_result.user.username if test_result.user else "Unknown User"

    try:
        db.session.delete(test_result)
        db.session.commit()
        flash(f'Test result for "{test_title}" by {username} has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the test result: {str(e)}', 'error')

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


@app.cli.command("add-test")
@click.argument("title")
def add_test_command(title):
    """Add a new test."""
    new_test = Test(title=title)
    db.session.add(new_test)
    db.session.commit()
    click.echo(f'Test "{title}" added successfully with ID: {new_test.id}')


@app.route('/admin/edit_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def edit_test(test_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    test = Test.query.get_or_404(test_id)

    if request.method == 'POST':
        title = request.form['title'].strip()

        # Check if a test with the new title already exists
        existing_test = Test.query.filter_by(title=title).first()
        if existing_test and existing_test.id != test_id:
            flash(f'A test with the title "{title}" already exists. Please choose a different title.', 'error')
            return redirect(url_for('edit_test', test_id=test_id))

        if title:
            test.title = title
            db.session.commit()
            flash(f'Test "{title}" has been updated successfully.', 'success')
            return redirect(url_for('manage_tests'))
        else:
            flash('Title is required to update the test.', 'error')

    return render_template('edit_test.html', test=test)


@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    tests = Test.query.all()  # Get all available tests

    if request.method == 'POST':
        test_id = request.form['test_id']  # Get the selected test ID
        test = Test.query.get_or_404(test_id)

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
                test_id=test.id
            )
        elif question_type == 'true_false':
            question = Question(
                content=content,
                option_a='True',
                option_b='False',
                correct_answer='A' if correct_answer.lower() == 'true' else 'B',
                test_id=test.id
            )
        else:
            flash('Invalid question type.', 'error')
            return redirect(url_for('add_question'))

        db.session.add(question)
        db.session.commit()
        flash(f'Question added to test "{test.title}".', 'success')
        return redirect(url_for('add_question'))

    return render_template('add_question.html', tests=tests)



@app.route('/admin/import_questions', methods=['GET', 'POST'])
@login_required
def import_questions():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    tests = Test.query.all()  # Fetch all tests from the database

    if request.method == 'POST':
        file = request.files['file']
        test_id = request.form.get('test_id')
        test = Test.query.get(test_id)  # Fetch the test

        if not test:
            flash('Test not found.', 'error')
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
                    test_id=test.id  # Ensure this is set
                )
                db.session.add(question)
            except Exception as e:
                db.session.rollback()
                flash(f'Error importing question: {e}', 'error')
                continue

        db.session.commit()
        flash('Questions imported successfully!', 'success')
        return redirect(url_for('manage_questions', test_id=test.id))

    return render_template('import_questions.html', tests=tests)




@app.route('/admin/list_tests')
@login_required
def list_tests():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))

    tests = Test.query.all()
    return render_template('list_tests.html', tests=tests)

@app.route('/admin/')
@login_required
def admin_redirect():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))


@app.route('/admin/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    test = Test.query.get_or_404(test_id)

    # Delete the test from the database
    db.session.delete(test)
    db.session.commit()
    flash(f'Test "{test.title}" has been deleted successfully.', 'success')

    return redirect(url_for('manage_tests'))



@app.route('/take_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def take_test(test_id):
    test_access = TestAccess.query.filter_by(user_id=current_user.id, test_id=test_id).first()
    if not test_access or not test_access.is_accessible:
        flash('You do not have access to this test.', 'error')
        return redirect(url_for('home'))

    test = Test.query.get_or_404(test_id)
    total_questions = len(test.questions)

    # Initialize session data if not already present
    if 'answers' not in session:
        session['answers'] = {}
    if 'flagged' not in session:
        session['flagged'] = {str(q.id): False for q in test.questions}
    if 'current_index' not in session:
        session['current_index'] = 0
    if 'start_time' not in session:
        session['start_time'] = datetime.utcnow().isoformat()

    if request.method == 'POST':
        action = request.form.get('action')
        current_question_id = str(test.questions[session['current_index']].id)

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

        elif action == 'submit_test':
            session.modified = True  # Ensure session is saved before redirect
            return redirect(url_for('submit_test', test_id=test_id))

        session.modified = True

        print(f"After Processing: Current Index: {session['current_index']}, Answers: {session['answers']}")

    current_question = test.questions[session['current_index']]
    progress = sum(1 for answer in session['answers'].values() if answer)
    flagged_questions = [i for i, q in enumerate(test.questions) if session['flagged'][str(q.id)]]
    time_elapsed = (datetime.utcnow() - datetime.fromisoformat(session['start_time'])).total_seconds() / 60

    all_questions_answered = progress == total_questions

    return render_template('take_test.html', 
                           test=test,
                           current_question=current_question,
                           current_index=session['current_index'], 
                           progress=progress,
                           total_questions=total_questions, 
                           flagged_questions=flagged_questions,
                           time_elapsed=time_elapsed, 
                           answers=session['answers'],
                           flagged=session['flagged'],
                           all_questions_answered=all_questions_answered)








@app.route('/request_retake/<int:test_id>', methods=['POST'])
@login_required
def request_retake(test_id):
    test_access = TestAccess.query.filter_by(user_id=current_user.id, test_id=test_id).first()
    if test_access:
        test_access.is_accessible = True
        db.session.commit()
        flash('Retake request submitted successfully.', 'success')
    else:
        flash('You do not have access to retake this test.', 'error')
    return redirect(url_for('home'))



@app.route('/admin/export_test_result/<int:test_result_id>', methods=['GET'])
@login_required
def export_test_result(test_result_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    # Fetch the test result object
    test_result = TestResult.query.get_or_404(test_result_id)
    user_answers = {}

    # Fetch answers directly from session or another reliable source
    for question in test_result.test.questions:
        missed_question = MissedQuestion.query.filter_by(test_result_id=test_result.id, question_id=question.id).first()

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

    return render_template('export_test_result.html', test_result=test_result, user_answers=user_answers)








if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)