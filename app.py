from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from database import init_db, get_db_connection
from config import Config
import sqlite3
import os
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'avatars')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Создаем папку для аватаров если не существует
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


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

    # Разрешены: буквы, цифры, подчеркивание, дефис, точка
    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.')

    for char in username:
        if char not in allowed_chars:
            return False

    return True


def format_datetime(dt_str, timezone_offset=3):
    """Форматирует дату и время в нужный формат с учетом часового пояса"""
    try:
        dt = datetime.fromisoformat(dt_str.replace('T', ' '))

        # Применяем смещение часового пояса
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

        # Добавляем отформатированную дату
        formatted_posts = []
        for post in posts:
            post_dict = dict(post)
            post_dict['formatted_date'] = format_datetime(post['created_at'], post['timezone_offset'])
            post_dict['first_letter'] = get_first_letter(post['author_name'])

            # Если пост был отредактирован, добавляем информацию о редактировании
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

        # Форматируем данные
        if post:
            post_dict = dict(post)
            post_dict['formatted_date'] = format_datetime(post['created_at'], post['timezone_offset'])
            post_dict['first_letter'] = get_first_letter(post['author_name'])

            # Если пост был отредактирован, добавляем информацию о редактировании
            if post['updated_at']:
                post_dict['edited_info'] = {
                    'formatted_date': format_datetime(post['updated_at'], post['timezone_offset']),
                    'is_edited': True
                }
            else:
                post_dict['edited_info'] = {'is_edited': False}

            # Форматируем комментарии
            formatted_comments = []
            for comment in comments:
                comment_dict = dict(comment)
                # Правильный способ получения timezone_offset из sqlite3.Row
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
    """Форма входа"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?',
                            (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['avatar'] = user['avatar']
            session['timezone_offset'] = user['timezone_offset']
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Форма регистрации"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов', 'error')
            return render_template('register.html')

        # Проверка на допустимые символы в нике
        if not is_valid_username(username):
            flash('Имя пользователя содержит недопустимые символы. Разрешены только буквы, цифры, _, - и .', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?',
                                     (username,)).fetchone()

        if existing_user:
            conn.close()
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password_hash, timezone_offset) VALUES (?, ?, ?)',
                     (username, password_hash, 3))  # По умолчанию UTC+3
        conn.commit()
        conn.close()

        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


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

                    # Обновляем аватар в базе данных
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET avatar = ? WHERE id = ?',
                                 (filename, session['user_id']))
                    conn.commit()
                    conn.close()

                    # Обновляем сессию
                    session['avatar'] = filename
                    flash('Аватар успешно загружен!', 'success')
                    return redirect(url_for('profile'))
                else:
                    flash('Недопустимый формат файла. Разрешены: png, jpg, jpeg, gif', 'error')

        elif 'remove_avatar' in request.form:
            # Удаляем аватар
            conn = get_db_connection()
            conn.execute('UPDATE users SET avatar = ? WHERE id = ?', ('default.png', session['user_id']))
            conn.commit()
            conn.close()

            # Обновляем сессию
            session['avatar'] = 'default.png'
            flash('Аватар успешно удален!', 'success')
            return redirect(url_for('profile'))

        elif 'delete_account' in request.form:
            # Удаляем аккаунт
            conn = get_db_connection()
            conn.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
            conn.commit()
            conn.close()

            # Очищаем сессию
            session.clear()
            flash('Аккаунт успешно удален!', 'success')
            return redirect(url_for('index'))

        elif 'timezone_offset' in request.form:
            # Обновляем часовой пояс
            timezone_offset = int(request.form['timezone_offset'])
            conn = get_db_connection()
            conn.execute('UPDATE users SET timezone_offset = ? WHERE id = ?',
                         (timezone_offset, session['user_id']))
            conn.commit()
            conn.close()

            # Обновляем сессию
            session['timezone_offset'] = timezone_offset
            flash('Часовой пояс успешно обновлен!', 'success')
            return redirect(url_for('profile'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    return render_template('profile.html', user=user)


@app.route('/new_post', methods=['GET', 'POST'])
def new_post():
    """Создание нового поста (только для авторизованных)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title.strip() or not content.strip():
            flash('Заголовок и содержание не могут быть пустыми', 'error')
            return render_template('new_post.html')

        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                     (title, content, session['user_id']))
        conn.commit()
        conn.close()

        flash('Пост успешно создан!', 'success')
        return redirect(url_for('index'))

    return render_template('new_post.html')


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    """Редактирование поста (только создателем)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND author_id = ?',
                        (post_id, session['user_id'])).fetchone()

    if not post:
        conn.close()
        flash('У вас нет прав на редактирование этого поста', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title.strip() or not content.strip():
            conn.close()
            flash('Заголовок и содержание не могут быть пустыми', 'error')
            return render_template('edit_post.html', post=post)

        # Обновляем пост
        conn.execute('''UPDATE posts 
                       SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP 
                       WHERE id = ?''',
                     (title, content, post_id))
        conn.commit()
        conn.close()

        flash('Пост успешно отредактирован!', 'success')
        return redirect(url_for('post_detail', post_id=post_id))

    conn.close()
    return render_template('edit_post.html', post=post)


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


# if __name__ == '__main__':
#     init_db()
#     app.run(debug=True)