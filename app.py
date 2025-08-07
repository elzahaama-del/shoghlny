from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import check_password_hash
from datetime import datetime
from models import db, User, Job, Company, UserSettings

from flask_dance.contrib.facebook import make_facebook_blueprint, facebook  # ⬅️ إضافة فيسبوك
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shoghlny.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# تهيئة قواعد البيانات
db.init_app(app)
migrate = Migrate(app, db)

# إعداد تسجيل الدخول
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# تحميل المستخدم الحالي
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ إضافة إعدادات فيسبوك
facebook_bp = make_facebook_blueprint(
    client_id="24103036579345459",
    client_secret="8187fcc0b12394a7092092b45970461f",
    redirect_url="/facebook_login",
    scope="email",
)
app.register_blueprint(facebook_bp, url_prefix="/facebook_login")


# ✅ تسجيل دخول عبر فيسبوك
@app.route('/facebook_login')
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for('facebook.login'))

    resp = facebook.get('/me?fields=name,email')
    if resp.ok:
        facebook_info = resp.json()
        email = facebook_info.get("email")
        name = facebook_info.get("name")

        if not email:
            flash("لا يمكن الحصول على البريد الإلكتروني من فيسبوك", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            # إنشاء مستخدم جديد إذا لم يكن موجودًا
            user = User(name=name, email=email, username=email.split('@')[0], role='user')
            user.set_password('facebook_default')  # كلمة سر وهمية
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash('تم تسجيل الدخول باستخدام فيسبوك!', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        flash("حدث خطأ أثناء تسجيل الدخول باستخدام فيسبوك", "danger")
        return redirect(url_for("login"))


# الصفحة الرئيسية
@app.route('/')
def index():
    stats = {
        'jobs': Job.query.count(),
        'users': User.query.count(),
        'companies': Company.query.count()
    }
    return render_template('index.html', stats=stats)

# استرجاع كلمة المرور
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني', 'success')
        else:
            flash('البريد الإلكتروني غير موجود', 'danger')
        return redirect(url_for('login'))
    return render_template('recover_password.html')

# صفحة تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('تم تسجيل الدخول بنجاح!', 'success')

            if user.role == 'company':
                return redirect(url_for('company_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('البريد الإلكتروني أو كلمة المرور غير صحيحة', 'danger')

    return render_template('login.html')

# لوحة تحكم المستخدم
@app.route('/dashboard/user')
@login_required
def user_dashboard():
    return render_template('dashboard_user.html')

# لوحة تحكم الشركة
@app.route('/dashboard/company')
@login_required
def company_dashboard():
    return render_template('dashboard_company.html')

# صفحة التسجيل
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role') or 'user'

        if User.query.filter_by(email=email).first():
            flash('البريد الإلكتروني مسجل مسبقًا', 'warning')
            return redirect(url_for('register'))

        new_user = User(name=name, username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('تم إنشاء الحساب بنجاح، يمكنك تسجيل الدخول', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# صفحة الوظائف
@app.route('/jobs')
def show_jobs():
    return render_template('jobs.html')

# صفحة الشركات
@app.route('/companies')
def companies():
    return render_template('companies.html')

# من نحن
@app.route('/about')
def about():
    return render_template('about.html')

# البحث
@app.route('/search', methods=['GET'])
def search_jobs():
    query = request.args.get('q')
    return render_template('search_results.html', query=query)

# إعدادات المستخدم
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if not current_user.settings:
            settings = UserSettings(user_id=current_user.id)
            db.session.add(settings)
            db.session.commit()
            current_user.settings = settings

        current_user.settings.language = request.form.get('language')
        current_user.settings.theme = request.form.get('theme')
        db.session.commit()
        flash('تم تحديث الإعدادات بنجاح', 'success')
    return render_template('settings.html')

# تسجيل الخروج
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('login'))

# تشغيل التطبيق
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
