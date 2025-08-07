import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # إعدادات عامة
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key'

    # إعدادات قاعدة البيانات
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'shoghlny.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # إعدادات البريد الإلكتروني (إن أردت استخدامه لاحقًا)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    # رفع الملفات
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}

    # عدد العناصر في كل صفحة (Pagination)
    ITEMS_PER_PAGE = 10

    # إعدادات أخرى مستقبلية
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB كحد أقصى للملف المرفوع
