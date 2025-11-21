import time
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from database import init_db, get_db_connection
from config import Config
import sqlite3
import os
from datetime import datetime, timezone, timedelta
import secrets
from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'avatars')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'false').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# if app.config.get('EMAIL_BACKEND') == 'smtp':
print(f"BACKEND = {os.environ.get('EMAIL_BACKEND', 'smtp').lower()}")
print("[DEBUG] SMTP Configuration:")
print(f"  MAIL_SERVER = {app.config.get('MAIL_SERVER')}")
print(f"  MAIL_PORT = {app.config.get('MAIL_PORT')}")
print(f"  MAIL_USE_TLS = {app.config.get('MAIL_USE_TLS')}")
print(f"  MAIL_USE_SSL = {app.config.get('MAIL_USE_SSL')}")
print(f"  MAIL_USERNAME = {app.config.get('MAIL_USERNAME')}")
print(f"  MAIL_DEFAULT_SENDER = {app.config.get('MAIL_DEFAULT_SENDER')}")

mail = Mail(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

last_resend = {}


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_first_letter(username):
    """Получает первую букву имени пользователя (игнорирует небуквенные символы)"""
    for char in username:
        if char.isalpha():
            return char.upper()
    return username[0].upper() if username else '?'


def is_valid_username(username):
    """Проверяет допустимость имени пользователя"""
    if not username or len(username) < 3:
        return False

    allowed_chars = set(
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.')

    for char in username:
        if char not in allowed_chars:
            return False

    return True


def format_datetime(dt_str, timezone_offset=3):
    """Форматирует дату и время в нужный формат с учетом часового пояса"""
    try:
        dt = datetime.fromisoformat(dt_str.replace('T', ' '))

        dt = dt + timedelta(hours=timezone_offset)

        return dt.strftime('%d %B %Y, %H:%M')
    except:
        return dt_str


def escape_code_html(text):
    """Экранирует HTML-символы только для блоков кода"""
    if text is None:
        return ''
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))


def send_verification_email(email, token):
    verify_url = url_for('verify_email', token=token, _external=True)
    html_content = render_template('email/verify.html', verify_url=verify_url)
    subject = "📧 Подтвердите e-mail — Учебный Блог"

    backend = os.environ.get('EMAIL_BACKEND', 'smtp').lower()

    if backend == 'smtp':

        msg = Message(
            subject=subject,
            recipients=[email],
            html=html_content,
            body=f"Подтвердите регистрацию: {verify_url}"
        )
        mail.send(msg)
        print("[EMAIL] Отправлено через SMTP")

    elif backend == 'email_api':

        message = SendGridMail(
            from_email=os.environ.get('MAIL_DEFAULT_SENDER'),
            to_emails=email,
            subject=subject,
            html_content=html_content
        )
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(f"[EMAIL] Отправлено через SendGrid API: {response.status_code}")

    else:
        raise ValueError(f"Неизвестный EMAIL_BACKEND: {backend}")


@app.route('/')
def index():
    """Главная страница со списком постов"""
    try:
        conn = get_db_connection()
        posts = conn.execute('''
            SELECT p.*, u.username as author_name, u.avatar as author_avatar, u.timezone_offset
            FROM posts p 
            JOIN users u ON p.author_id = u.id 
            ORDER BY p.created_at DESC
        ''').fetchall()

        formatted_posts = []
        for post in posts:
            post_dict = dict(post)
            post_dict['formatted_date'] = format_datetime(post['created_at'], post['timezone_offset'])
            post_dict['first_letter'] = get_first_letter(post['author_name'])

            if post['updated_at']:
                post_dict['edited_info'] = {
                    'formatted_date': format_datetime(post['updated_at'], post['timezone_offset']),
                    'is_edited': True
                }
            else:
                post_dict['edited_info'] = {'is_edited': False}

            formatted_posts.append(post_dict)

        conn.close()
        return render_template('index.html', posts=formatted_posts)
    except sqlite3.OperationalError as e:
        init_db()
        return redirect(url_for('index'))


@app.route('/post/<int:post_id>')
def post_detail(post_id):
    """Страница отдельного поста"""
    try:
        conn = get_db_connection()
        post = conn.execute('''
            SELECT p.*, u.username as author_name, u.avatar as author_avatar, u.timezone_offset
            FROM posts p 
            JOIN users u ON p.author_id = u.id 
            WHERE p.id = ?
        ''', (post_id,)).fetchone()

        comments = conn.execute('''
            SELECT c.*, u.username as author_name, u.avatar as author_avatar, u.timezone_offset
            FROM comments c 
            LEFT JOIN users u ON c.author_name = u.username 
            WHERE c.post_id = ? 
            ORDER BY c.created_at DESC
        ''', (post_id,)).fetchall()

        if post:
            post_dict = dict(post)
            post_dict['formatted_date'] = format_datetime(post['created_at'], post['timezone_offset'])
            post_dict['first_letter'] = get_first_letter(post['author_name'])

            if post['updated_at']:
                post_dict['edited_info'] = {
                    'formatted_date': format_datetime(post['updated_at'], post['timezone_offset']),
                    'is_edited': True
                }
            else:
                post_dict['edited_info'] = {'is_edited': False}

            formatted_comments = []
            for comment in comments:
                comment_dict = dict(comment)

                timezone_offset = comment['timezone_offset'] if comment['timezone_offset'] is not None else 3
                comment_dict['formatted_date'] = format_datetime(comment['created_at'], timezone_offset)
                comment_dict['first_letter'] = get_first_letter(comment['author_name'])
                comment_dict['escaped_content'] = escape_code_html(comment['content'])
                formatted_comments.append(comment_dict)

            conn.close()
            return render_template('post.html', post=post_dict, comments=formatted_comments)
        else:
            conn.close()
            flash('Пост не найден', 'error')
            return redirect(url_for('index'))
    except sqlite3.OperationalError as e:
        init_db()
        return redirect(url_for('post_detail', post_id=post_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form_data = {'username': session.get('login_username', '')}

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if not user:
            flash('Неверное имя пользователя или пароль', 'error')
        elif not check_password_hash(user['password_hash'], password):
            flash('Неверное имя пользователя или пароль', 'error')
        else:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['avatar'] = user['avatar']
            session['timezone_offset'] = user['timezone_offset']
            return redirect(url_for('index'))

    return render_template('login.html', **form_data)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form_data = {
        'username': session.get('register_username', ''),
        'email': session.get('register_email', ''),
        'confirm_email': session.get('register_confirm_email', '')
    }

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email'].strip().lower()
        confirm_email = request.form['confirm_email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        session['register_username'] = username
        session['register_email'] = email
        session['register_confirm_email'] = confirm_email

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html', **form_data)

        if len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов', 'error')
            return render_template('register.html', **form_data)

        if not is_valid_username(username):
            flash('Имя пользователя содержит недопустимые символы. Разрешены только буквы, цифры, _, - и .', 'error')
            return render_template('register.html', **form_data)

        try:
            valid = validate_email(email)
            email = valid.email

            session['register_email'] = email
            form_data['email'] = email
        except EmailNotValidError:
            flash('Некорректный адрес электронной почты', 'error')
            return render_template('register.html', **form_data)

        conn = get_db_connection()
        conn.execute("DELETE FROM unverified_users WHERE created_at < datetime('now', '-5 minutes')")
        conn.commit()

        if conn.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
            conn.close()
            flash('Этот e-mail уже зарегистрирован.', 'error')
            return render_template('register.html', **form_data)

        unverified_email = conn.execute('SELECT created_at FROM unverified_users WHERE email = ?', (email,)).fetchone()
        if unverified_email:
            created_at = datetime.fromisoformat(unverified_email['created_at'])
            if datetime.now(timezone.utc) - created_at < timedelta(minutes=5):
                remaining = timedelta(minutes=5) - (datetime.now(timezone.utc) - created_at)
                total_seconds = int(remaining.total_seconds())
                mins, secs = divmod(total_seconds, 60)
                conn.close()
                flash(f'Этот e-mail временно недоступен. Повторная регистрация возможна через {mins} мин {secs} сек.',
                      'error')
                return render_template('register.html', **form_data)
            else:
                conn.execute('DELETE FROM unverified_users WHERE email = ?', (email,))
                conn.commit()

        if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            conn.close()
            flash('Это имя уже занято.', 'error')
            return render_template('register.html', **form_data)

        unverified_username = conn.execute('SELECT created_at FROM unverified_users WHERE username = ?',
                                           (username,)).fetchone()
        if unverified_username:
            created_at = datetime.fromisoformat(unverified_username['created_at'])
            if datetime.now(timezone.utc) - created_at < timedelta(minutes=5):
                remaining = timedelta(minutes=5) - (datetime.now(timezone.utc) - created_at)
                total_seconds = int(remaining.total_seconds())
                mins, secs = divmod(total_seconds, 60)
                conn.close()
                flash(f'Имя занято. Повторная регистрация возможна через {mins} мин {secs} сек.', 'error')
                return render_template('register.html', **form_data)
            else:
                conn.execute('DELETE FROM unverified_users WHERE username = ?', (username,))
                conn.commit()

        password_hash = generate_password_hash(password)
        token = secrets.token_urlsafe(32)

        try:
            conn.execute('''
                INSERT INTO unverified_users 
                (username, email, password_hash, verification_token, last_email_sent_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (username, email, password_hash, token))
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            flash('Произошла ошибка при регистрации. Попробуйте другое имя или e-mail.', 'error')
            return render_template('register.html', **form_data)
        finally:
            conn.close()

        try:
            send_verification_email(email, token)
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
            conn = get_db_connection()
            conn.execute('DELETE FROM unverified_users WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            flash('Не удалось отправить письмо. Попробуйте позже.', 'error')
            return render_template('register.html', **form_data)

        session.pop('register_username', None)
        session.pop('register_email', None)
        session.pop('register_confirm_email', None)

        flash('Регистрация начата! Проверьте e-mail для подтверждения.', 'success')
        return redirect(url_for('resend_verification', email=email))

    return render_template('register.html', **form_data)


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    email = request.args.get('email', '').strip().lower()

    if not email:
        flash('Некорректный запрос.', 'error')
        return redirect(url_for('register'))

    conn = get_db_connection()
    unverified = conn.execute('SELECT * FROM unverified_users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not unverified:
        flash('Нет активной регистрации с таким e-mail.', 'error')
        return redirect(url_for('register'))

    if request.method == 'GET':
        cooldown_seconds = 0
        last_sent = unverified['last_email_sent_at']
        if last_sent:
            last_sent_time = datetime.fromisoformat(last_sent)
            elapsed = datetime.now(timezone.utc).replace(tzinfo=None) - last_sent_time
            if elapsed < timedelta(minutes=2):
                remaining = timedelta(minutes=2) - elapsed
                cooldown_seconds = int(remaining.total_seconds())

        return render_template('resend_verification.html', email=email, cooldown_seconds=cooldown_seconds)

    if request.method == 'POST':

        last_sent = unverified['last_email_sent_at']
        if last_sent:
            last_sent_time = datetime.fromisoformat(last_sent)
            if datetime.now(timezone.utc) - last_sent_time < timedelta(minutes=2):
                remaining = timedelta(minutes=2) - (datetime.now(timezone.utc) - last_sent_time)
                total_seconds = int(remaining.total_seconds())
                mins, secs = divmod(total_seconds, 60)
                flash(f'Повторная отправка возможна через {mins} мин {secs} сек.', 'error')
                return render_template('resend_verification.html', email=email)

        try:
            send_verification_email(email, unverified['verification_token'])

            conn.execute('''
                UPDATE unverified_users 
                SET last_email_sent_at = CURRENT_TIMESTAMP 
                WHERE email = ?
            ''', (email,))
            conn.commit()
            flash('Письмо отправлено повторно! Проверьте ваш e-mail.', 'success')
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
            flash('Не удалось отправить письмо. Попробуйте позже.', 'error')
        finally:
            conn.close()

        return render_template('resend_verification.html', email=email)

    conn.close()
    return render_template('resend_verification.html', email=email)


@app.route('/cancel-unverified')
def cancel_unverified():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return redirect(url_for('register'))

    conn = get_db_connection()
    conn.execute('DELETE FROM unverified_users WHERE email = ?', (email,))
    conn.commit()
    conn.close()

    flash('Регистрация отменена. Вы можете зарегистрироваться заново.', 'message')
    return redirect(url_for('register'))


@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db_connection()
    unverified = conn.execute('SELECT * FROM unverified_users WHERE verification_token = ?', (token,)).fetchone()

    if not unverified:
        flash('Неверная или устаревшая ссылка.', 'error')
        conn.close()
        return redirect(url_for('register'))

    conn.execute('''
        INSERT INTO users (username, email, password_hash, avatar, timezone_offset)
        VALUES (?, ?, ?, 'default.png', 3)
    ''', (unverified['username'], unverified['email'], unverified['password_hash']))

    conn.execute('DELETE FROM unverified_users WHERE verification_token = ?', (token,))
    conn.commit()
    conn.close()

    flash('E-mail подтверждён! Теперь вы можете войти.', 'success')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        conn = get_db_connection()
        user = conn.execute('SELECT id, email FROM users WHERE email = ?', (email,)).fetchone()

        if user:

            token = secrets.token_urlsafe(48)
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')

            conn.execute('''
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user['id'], token, expires_at))
            conn.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            backend = os.environ.get('EMAIL_BACKEND', 'smtp').lower()
            if backend == 'smtp':
                msg = Message(
                    subject="Сброс пароля — Учебный Блог",
                    recipients=[user['email']],
                    html=render_template('email/reset_password.html', reset_url=reset_url),
                    body=f"Сбросить пароль: {reset_url}"
                )
                try:
                    mail.send(msg)
                except Exception as e:
                    print(f"[EMAIL ERROR] {e}")
            else:
                message = SendGridMail(
                    from_email=os.environ.get('MAIL_DEFAULT_SENDER'),
                    to_emails=user['email'],
                    subject="Сброс пароля — Учебный Блог",
                    html_content=render_template('email/reset_password.html', reset_url=reset_url)
                )
                sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
                try:
                    sg.send(message)
                except Exception as e:
                    print(f"[EMAIL ERROR] {e}")

        flash('Если указанный e-mail зарегистрирован, вы получите письмо с инструкциями.', 'message')
        conn.close()
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    reset_record = conn.execute('''
        SELECT * FROM password_reset_tokens 
        WHERE token = ? AND expires_at > datetime('now')
    ''', (token,)).fetchone()

    if not reset_record:
        conn.close()
        flash('Неверная или устаревшая ссылка для сброса пароля.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Пароли не совпадают.', 'error')
        elif len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов.', 'error')
        else:
            password_hash = generate_password_hash(password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, reset_record['user_id']))
            conn.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            flash('Пароль успешно изменён. Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)


@app.route('/logout')
def logout():
    """Выход из системы"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Страница профиля с возможностью загрузки аватара"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename != '':
                if file and allowed_file(file.filename):
                    filename = f"user_{session['user_id']}.{file.filename.rsplit('.', 1)[1].lower()}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)

                    conn = get_db_connection()
                    conn.execute('UPDATE users SET avatar = ? WHERE id = ?',
                                 (filename, session['user_id']))
                    conn.commit()
                    conn.close()

                    session['avatar'] = filename
                    flash('Аватар успешно загружен!', 'success')
                    return redirect(url_for('profile'))
                else:
                    flash('Недопустимый формат файла. Разрешены: png, jpg, jpeg, gif', 'error')

        elif 'remove_avatar' in request.form:
            conn = get_db_connection()
            user = conn.execute('SELECT avatar FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            current_avatar = user['avatar'] if user else None
            conn.close()

            if current_avatar and current_avatar != 'default.png':
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], current_avatar)
                try:
                    if os.path.exists(avatar_path):
                        os.remove(avatar_path)
                        print(f"[INFO] Аватар удалён: {avatar_path}")
                except Exception as e:
                    print(f"[ERROR] Не удалось удалить аватар: {e}")

            conn = get_db_connection()
            conn.execute('UPDATE users SET avatar = ? WHERE id = ?', ('default.png', session['user_id']))
            conn.commit()
            conn.close()

            session['avatar'] = 'default.png'
            flash('Аватар успешно удален!', 'success')
            return redirect(url_for('profile'))

        elif 'delete_account' in request.form:

            conn = get_db_connection()
            conn.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
            conn.commit()
            conn.close()

            session.clear()
            flash('Аккаунт успешно удален!', 'success')
            return redirect(url_for('index'))

        elif 'timezone_offset' in request.form:

            timezone_offset = int(request.form['timezone_offset'])
            conn = get_db_connection()
            conn.execute('UPDATE users SET timezone_offset = ? WHERE id = ?',
                         (timezone_offset, session['user_id']))
            conn.commit()
            conn.close()

            session['timezone_offset'] = timezone_offset
            flash('Часовой пояс успешно обновлен!', 'success')
            return redirect(url_for('profile'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    return render_template('profile.html', user=user)


@app.route('/new_post', methods=['GET', 'POST'])
def new_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form_data = {
        'title': session.get('new_post_title', ''),
        'content': session.get('new_post_content', '')
    }

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title.strip() or not content.strip():
            session['new_post_title'] = title
            session['new_post_content'] = content
            flash('Заголовок и содержание не могут быть пустыми', 'error')
            return render_template('new_post.html', **form_data)

        session.pop('new_post_title', None)
        session.pop('new_post_content', None)

        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                     (title, content, session['user_id']))
        conn.commit()
        conn.close()

        flash('Пост успешно создан!', 'success')
        return redirect(url_for('index'))

    return render_template('new_post.html', **form_data)


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND author_id = ?',
                        (post_id, session['user_id'])).fetchone()
    if not post:
        conn.close()
        flash('У вас нет прав на редактирование этого поста', 'error')
        return redirect(url_for('index'))

    form_data = {
        'title': session.get(f'edit_post_{post_id}_title', post['title']),
        'content': session.get(f'edit_post_{post_id}_content', post['content'])
    }

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title.strip() or not content.strip():
            session[f'edit_post_{post_id}_title'] = title
            session[f'edit_post_{post_id}_content'] = content
            conn.close()
            flash('Заголовок и содержание не могут быть пустыми', 'error')
            return render_template('edit_post.html', post=post, **form_data)

        session.pop(f'edit_post_{post_id}_title', None)
        session.pop(f'edit_post_{post_id}_content', None)

        conn.execute('''UPDATE posts 
                       SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP 
                       WHERE id = ?''',
                     (title, content, post_id))
        conn.commit()
        conn.close()

        flash('Пост успешно отредактирован!', 'success')
        return redirect(url_for('post_detail', post_id=post_id))

    conn.close()
    return render_template('edit_post.html', post=post, **form_data)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    """Удаление поста (только создателем)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND author_id = ?',
                        (post_id, session['user_id'])).fetchone()

    if post:
        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        flash('Пост успешно удален!', 'success')
    else:
        flash('У вас нет прав на удаление этого поста', 'error')

    conn.close()
    return redirect(url_for('index'))


@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    """Добавление комментария"""
    content = request.form['content']
    if not content.strip():
        flash('Комментарий не может быть пустым', 'error')
        return redirect(url_for('post_detail', post_id=post_id))

    author_name = session.get('username', 'Гость')

    conn = get_db_connection()
    conn.execute('INSERT INTO comments (content, post_id, author_name) VALUES (?, ?, ?)',
                 (content, post_id, author_name))
    conn.commit()
    conn.close()

    return redirect(url_for('post_detail', post_id=post_id))


init_db()

# if __name__ == '__main__':
#     app.run(debug=True)
