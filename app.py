from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
import os

# استيراد db ونماذج البيانات من models
from models import db, User, Company, Job, Application, SavedJob, Message, Notification, ActivityLog, UserSettings, LoginHistory


app = Flask(__name__)

# إعدادات التطبيق يجب أن تسبق تهيئة db
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shoghlny.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ربط التطبيق مع db (تهيئة واحدة فقط!)
# db.init_app(app)
 
# لسه
@app.route('/job/<int:job_id>/applicants')
@login_required
def view_applicants(job_id):
    job = Job.query.get_or_404(job_id)
    applications = Application.query.filter_by(job_id=job_id).all()
    return render_template('applicants.html', job=job, applicants=applications)
# موافقه او كنسل

# التفاصيل

@app.route('/applicant/<int:id>')
def view_applicant(id):
    applicant = User.query.get(id)
    if not applicant:
        abort(404)
    applications = Application.query.filter_by(user_id=id).all()
    return render_template('view_applicant.html', applicant=applicant, applications=applications)


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

        # تحقق من وجود اسم المستخدم
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('اسم المستخدم موجود بالفعل، جرب اسم مختلف', 'danger')
            return redirect(url_for('register'))

        # تحقق من وجود البريد الإلكتروني مسبقًا
        if User.query.filter_by(email=email).first():
            flash('البريد الإلكتروني مسجل مسبقًا', 'warning')
            return redirect(url_for('register'))

        # تشفير كلمة المرور
        hashed_password = generate_password_hash(password)

        # إنشاء المستخدم الجديد
        new_user = User(
            name=name,
            username=username,
            email=email,
            password_hash=hashed_password,
            role='user',
            created_at=datetime.utcnow()
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('حصل خطأ أثناء التسجيل، حاول مرة أخرى', 'danger')
            return redirect(url_for('register'))

        print(name, username, email)  # ← جرب تطبع هنا علشان تتأكد إنه فعلا جاي البيانات

        flash('تم إنشاء الحساب بنجاح، يمكنك تسجيل الدخول', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')       

# إنشاء وظيفة جديدة

@app.route('/create_job', methods=['GET', 'POST'])
@login_required
def create_job():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        
        job = Job(
            title=title,
            description=description,
            location=location,
            company_id=current_user.id  # 📌 هنخزن ID المستخدم كصاحب الوظيفة
        )
        db.session.add(job)
        db.session.commit()

        flash("تم نشر الوظيفة بنجاح ✅", "success")
        return redirect(url_for('jobs_list'))


    return render_template('create_job.html')
# مقدمين على الوظيفة
    # نجيب الوظيفة
    job = Job.query.get_or_404(job_id)

    # نجيب كل الطلبات المقدمة على الوظيفة
    applications = Application.query.filter_by(job_id=job.id).all()

    # نحولها لقائمة بيانات منظمة
    applicants_list = [
        {
            'id': app.id,
            'username': app.applicant.username if app.applicant else 'غير متوفر',
            'email': app.applicant.email if app.applicant else 'غير متوفر',
            'status': app.status,
            'applied_date': app.submitted_at.strftime('%Y-%m-%d %H:%M') if app.submitted_at else 'غير محدد'
        }
        for app in applications
    ]

    # نرسل البيانات للـ HTML
    return render_template('applicants.html', job=job, applicants=applications)

    # return render_template('applicants.html', job=job, applicants=applicants_list)
# تقديم
@app.route('/applicant/<int:applicant_id>/reject')
@login_required
def reject_applicant(applicant_id):
    application = Application.query.get_or_404(applicant_id)
    application.status = 'rejected'
    db.session.commit()

    # إنشاء إشعار للمتقدم
    notif = Notification(
        user_id=application.user_id,  # نفترض application يحتوي على user_id
        message=f"تم رفض طلبك لوظيفة: {application.job.title if application.job else 'غير محددة'}"
    )
    db.session.add(notif)
    db.session.commit()

    flash('تم رفض المتقدم وإرسال إشعار له.', 'success')
    return redirect(url_for('view_applicants', job_id=application.job_id))


@app.route('/applicant/<int:applicant_id>/accept')
@login_required
def accept_applicant(applicant_id):
    application = Application.query.get_or_404(applicant_id)
    application.status = 'accepted'
    db.session.commit()

    # إنشاء إشعار للمتقدم
    notif = Notification(
        user_id=application.user_id,
        message=f"تم قبول طلبك لوظيفة: {application.job.title if application.job else 'غير محددة'}"
    )
    db.session.add(notif)
    db.session.commit()

    flash('تم قبول المتقدم وإرسال إشعار له.', 'success')
    return redirect(url_for('view_applicants', job_id=application.job_id))

# تقديم
@app.route('/job/<int:job_id>/apply', methods=['POST'])
@login_required
def apply_job(job_id):
    # تحقق إذا المستخدم مقدم على الوظيفة قبل كده
    existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if existing_application:
        flash('لقد قمت بالتقديم على هذه الوظيفة من قبل.', 'warning')
        return redirect(url_for('job_detail', job_id=job_id))
   
# إنشاء الطلب
    application = Application(
    user_id=current_user.id,
    job_id=job_id,
    cover_letter=request.form.get("cover_letter"),
    status="pending"  # أو أي حالة افتراضية
)

# حفظ الطلب في قاعدة البيانات
    db.session.add(application)
    db.session.commit()

    flash('تم التقديم على الوظيفة بنجاح!', 'success')
    return redirect(url_for('job_detail', job_id=job_id))


    # تحقق لو المستخدم قدم قبل كده على نفس الوظيفة
    existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if existing_application:
        flash('لقد قدمت على هذه الوظيفة سابقًا.', 'warning')
        return redirect(url_for('job_detail', job_id=job_id))

    # إنشاء طلب تقديم جديد
    application = Application(
        user_id=current_user.id,
        job_id=job_id,
        applied_at=datetime.utcnow(),
        status='pending'  # أو الحالة الافتراضية اللي عندك
    )
    db.session.add(application)
    db.session.commit()

    flash('تم التقديم على الوظيفة بنجاح!', 'success')
    return redirect(url_for('job_detail', job_id=job_id))
@app.route('/applicant/<int:id>')
def view_applicant_detail(id):
    applicant = User.query.get_or_404(id)
    return render_template('view_applicant.html', applicant=applicant)

# بروفيل
@app.route('/profile')
def profile():
    return render_template('profile.html')
# لسهه





# تفصايل الوظيفة
@app.route('/job/<int:job_id>')
def job_detail(job_id):
    job = Job.query.get_or_404(job_id)
    return render_template('job_detail.html', job=job)

# صفحة الوظائف
@app.route('/jobs', methods=['GET'])
def jobs_list():
    # جلب جميع الوظائف من قاعدة البيانات
    jobs = Job.query.order_by(Job.created_at.desc()).all()

    # لو مفيش وظائف
    if not jobs:
        flash("لا توجد وظائف متاحة حالياً", "info")

    # عرض الصفحة
    return render_template('jobs_list.html', jobs=jobs)
 

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
# رسايل

@app.route("/messages", methods=["GET", "POST"])
def messages():
    if request.method == "POST":
        sender = request.form.get("sender")
        receiver = request.form.get("receiver")
        content = request.form.get("content")

        if not sender or not receiver or not content:
            flash("يرجى ملء جميع الحقول", "error")
        else:
            new_msg = Message(sender=sender, receiver=receiver, content=content)
            db.session.add(new_msg)
            db.session.commit()
            flash("تم إرسال الرسالة بنجاح", "success")
            return redirect(url_for("messages"))

    all_messages = Message.query.order_by(Message.timestamp.desc()).all() # pyright: ignore[reportUndefinedVariable]
    return render_template("messages.html", messages=all_messages)


# انشاء

# تسجيل الخروج
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
