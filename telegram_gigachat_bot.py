import requests
import uuid
import json
import time
import logging
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Настройка логирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Данные для подключения к GigaChat
CLIENT_ID = 'ee029f52-ac7a-4778-bd89-c06640cc9da0'
AUTH_KEY = 'ZWUwMjlmNTItYWM3YS00Nzc4LWJkODktYzA2NjQwY2M5ZGEwOmQ2OTk3ZjNkLWNkNWUtNDJmNC1iMDY0LWU4NWNmODc1MzhiNw=='
SCOPE = 'GIGACHAT_API_PERS'
GIGACHAT_API_URL = 'https://api.gigachat.devices.sberbank.ru/api/v2/chat/completions'
AUTH_URL = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth'

# Глобальные переменные для токена GigaChat
access_token = None
token_expires_at = 0

# Инициализация Flask
app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Для сессий Flask

# Telegram токен
TELEGRAM_TOKEN = '7705234760:AAFjd85N-4egdP3e7YWd90RXvpbn-FXJDag'

# Инициализация базы данных SQLite
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Таблица пользователей
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            telegram_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            is_blocked BOOLEAN DEFAULT 0,
            last_message_date TEXT
        )''')
        # Таблица логов запросов
        c.execute('''CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            user_message TEXT,
            bot_response TEXT,
            request_date TEXT
        )''')
        # Таблица администраторов веб-панели
        c.execute('''CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password_hash TEXT
        )''')
        # Добавление администратора по умолчанию (логин: admin, пароль: admin123)
        c.execute('SELECT * FROM admins WHERE username = ?', ('admin',))
        if not c.fetchone():
            password_hash = generate_password_hash('admin123')
            c.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', ('admin', password_hash))
        conn.commit()

init_db()

def get_access_token():
    """Получение OAuth-токена для GigaChat."""
    global access_token, token_expires_at
    try:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'RqUID': str(uuid.uuid4()),
            'Authorization': f'Basic {AUTH_KEY}',
        }
        data = {'scope': SCOPE}
        response = requests.post(AUTH_URL, headers=headers, data=data, verify=False)
        
        if response.status_code != 200:
            logger.error(f"Ошибка получения токена: {response.status_code} - {response.text}")
            return None
        
        response_data = response.json()
        if 'access_token' in response_data:
            access_token = response_data['access_token']
            token_expires_at = time.time() + response_data.get('expires_in', 1800) - 60
            logger.info("Токен успешно получен")
            return access_token
        else:
            logger.error("Токен не найден в ответе")
            return None
    except Exception as e:
        logger.error(f"Ошибка при получении токена: {e}")
        return None

def is_token_valid():
    """Проверка, действителен ли токен."""
    return access_token is not None and time.time() < token_expires_at

def query_gigachat(message):
    """Отправка сообщения к GigaChat и получение ответа."""
    if not is_token_valid():
        logger.info("Обновление токена...")
        if not get_access_token():
            return "Ошибка: не удалось получить токен GigaChat."

    try:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}',
        }
        payload = {
            'model': 'Grok',
            'messages': [
                {
                    'role': 'system',
                    'content': 'Ты дружелюбный и полезный чат-бот. Отвечай на русском языке, лаконично и по делу. Если пользователь спрашивает о программировании, включай код в формате ```язык\nкод\n```. Для любых вопросов старайся быть максимально полезным.'
                },
                {
                    'role': 'user',
                    'content': message
                }
            ],
            'max_tokens': 1000,
            'temperature': 0.7,
        }
        response = requests.post(GIGACHAT_API_URL, headers=headers, json=payload, verify=False)
        
        if response.status_code == 401:
            logger.info("Токен истек, обновляем...")
            if get_access_token():
                return query_gigachat(message)
            return "Ошибка: не удалось обновить токен GigaChat."
        
        if response.status_code != 200:
            logger.error(f"Ошибка API: {response.status_code} - {response.text}")
            return f"Ошибка API: {response.status_code}"
        
        response_data = response.json()
        return response_data['choices'][0]['message']['content']
    except Exception as e:
        logger.error(f"Ошибка при запросе к GigaChat: {e}")
        return f"Ошибка: {str(e)}"

def log_request(telegram_id, user_message, bot_response):
    """Логирование запроса в базу данных."""
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        request_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('INSERT INTO requests (telegram_id, user_message, bot_response, request_date) VALUES (?, ?, ?, ?)',
                  (telegram_id, user_message, bot_response, request_date))
        conn.commit()

def update_user(telegram_id, username, first_name, last_name):
    """Обновление или добавление пользователя в базу данных."""
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        last_message_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''INSERT OR REPLACE INTO users (telegram_id, username, first_name, last_name, is_blocked, last_message_date)
                     VALUES (?, ?, ?, ?, (SELECT is_blocked FROM users WHERE telegram_id = ?), ?)''',
                  (telegram_id, username, first_name, last_name, telegram_id, last_message_date))
        conn.commit()

# Flask маршруты для веб-панели
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash FROM admins WHERE username = ?', (username,))
            result = c.fetchone()
            if result and check_password_hash(result[0], password):
                session['username'] = username
                return redirect(url_for('dashboard'))
            flash('Неверный логин или пароль')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM users WHERE is_blocked = 1')
        blocked_users = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM requests')
        total_requests = c.fetchone()[0]
        c.execute('SELECT COUNT(DISTINCT telegram_id) FROM requests')
        active_users = c.fetchone()[0]
    return render_template('dashboard.html', total_users=total_users, blocked_users=blocked_users,
                           total_requests=total_requests, active_users=active_users)

@app.route('/users')
def users():
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT telegram_id, username, first_name, last_name, is_blocked, last_message_date FROM users')
        users = c.fetchall()
    return render_template('users.html', users=users)

@app.route('/block_user/<int:telegram_id>')
def block_user(telegram_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET is_blocked = 1 WHERE telegram_id = ?', (telegram_id,))
        conn.commit()
    flash(f'Пользователь {telegram_id} заблокирован')
    return redirect(url_for('users'))

@app.route('/unblock_user/<int:telegram_id>')
def unblock_user(telegram_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET is_blocked = 0 WHERE telegram_id = ?', (telegram_id,))
        conn.commit()
    flash(f'Пользователь {telegram_id} разблокирован')
    return redirect(url_for('users'))

@app.route('/requests')
def requests():
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT r.id, r.telegram_id, u.username, r.user_message, r.bot_response, r.request_date FROM requests r JOIN users u ON r.telegram_id = u.telegram_id')
        requests = c.fetchall()
    return render_template('requests.html', requests=requests)

@app.route('/broadcast', methods=['GET', 'POST'])
def broadcast():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message']
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT telegram_id FROM users WHERE is_blocked = 0')
            users = c.fetchall()
        for user in users:
            try:
                app.bot.send_message(chat_id=user[0], text=message)
            except Exception as e:
                logger.error(f"Ошибка отправки сообщения пользователю {user[0]}: {e}")
        flash('Сообщение отправлено всем активным пользователям')
        return redirect(url_for('broadcast'))
    return render_template('broadcast.html')

# Telegram-бот
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /start."""
    user = update.effective_user
    update_user(user.id, user.username, user.first_name, user.last_name)
    await update.message.reply_text(
        "Привет! Я чат-бот, работающий на GigaChat. Задавай вопросы или пиши сообщения, "
        "например, 'Как написать цикл в Python?' или 'Расскажи анекдот'. Я отвечу на русском языке!"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик текстовых сообщений."""
    user = update.effective_user
    user_message = update.message.text
    logger.info(f"Получено сообщение от {user.id}: {user_message}")
    
    update_user(user.id, user.username, user.first_name, user.last_name)
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT is_blocked FROM users WHERE telegram_id = ?', (user.id,))
        result = c.fetchone()
        if result and result[0]:
            await update.message.reply_text("Вы заблокированы и не можете использовать бота.")
            return
    
    await update.message.reply_text("Думаю...")
    response = query_gigachat(user_message)
    log_request(user.id, user_message, response)
    await update.message.reply_text(response)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик ошибок."""
    logger.error(f"Ошибка: {context.error}")
    if update and update.message:
        await update.message.reply_text("Произошла ошибка. Попробуй снова!")

def main():
    """Запуск Telegram-бота и веб-панели."""
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)
    
    # Сохраняем bot в app для рассылки
    app.bot = application.bot
    
    logger.info("Бот и веб-панель запущены")
    
    # Запуск Flask в отдельном потоке
    from threading import Thread
    flask_thread = Thread(target=lambda: app.run(debug=False, use_reloader=False))
    flask_thread.start()
    
    # Запуск Telegram-бота
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
