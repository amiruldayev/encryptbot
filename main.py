import telebot
from telebot import types
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import mysql.connector


TOKEN = '6323376518:AAHqdDLlJfhBxEos-yICy_wW8JDEy225qMk'
bot = telebot.TeleBot(TOKEN)



# Состояния для отслеживания контекста диалога
states = {}

# Переменные для хранения текста и ключа для шифрования и расшифрования
text_to_encrypt = None
encryption_key = None


# Подключение к базе данных
db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="encbot"
)

# Создание курсора для выполнения SQL-запросов
cursor = db_connection.cursor()

# Создание таблицы для хранения данных
table_creation_query = """
CREATE TABLE IF NOT EXISTS encrypted_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    encrypted_text TEXT,
    decrypted_text TEXT,
    encryption_key INT
);
"""
cursor.execute(table_creation_query)

# Закрываем курсор и подключение к базе данных
cursor.close()
db_connection.close()

# Обработчик команды /start
@bot.message_handler(commands=['start'])
def handle_start(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn_enc = types.KeyboardButton('Encrypt text')
    btn_des = types.KeyboardButton('Decrypt text')
    btn_fenc = types.KeyboardButton('Encrypt text to file')
    btn_fdes = types.KeyboardButton('Decrypt text to file')

    markup.add(btn_enc, btn_des, btn_fenc, btn_fdes)
    bot.send_message(message.chat.id, 'SIS-2121 Amiruldayev Emil, Rakhmetuly Zhanserik, Nurpeisov Daniyar',
                     reply_markup=markup)


# Обработчик для кнопки "Encrypt text"
@bot.message_handler(func=lambda message: message.text == 'Encrypt text')
def handle_encrypt_start(message):
    # Устанавливаем состояние "ожидание текста для шифрования"
    states[message.chat.id] = 'encrypt_text'
    bot.send_message(message.chat.id, 'Enter the text that needs to be encrypted')


# Обработчик для ответа на текст для шифрования
@bot.message_handler(func=lambda message: states.get(message.chat.id) == 'encrypt_text')
def handle_encrypt_text(message):
    global text_to_encrypt
    # Получаем текст для шифрования из сообщения пользователя
    text_to_encrypt = message.text

    # Спрашиваем у пользователя ключ для шифрования
    bot.send_message(message.chat.id, 'Enter the key for encryption')

    # Устанавливаем состояние "ожидание ключа для шифрования"
    states[message.chat.id] = 'encrypt_key'


# Обработчик для ответа на ключ для шифрования
@bot.message_handler(func=lambda message: states.get(message.chat.id) == 'encrypt_key')
def handle_encrypt_key(message):
    global encryption_key, text_to_encrypt

    encryption_key = message.text

    if not encryption_key.isdigit():
        bot.send_message(message.chat.id, 'Please enter a valid numeric key.')
        return

    # Зашифровываем текст
    encrypted_text = encrypt(text_to_encrypt, int(encryption_key))

    # Сохраняем данные в базе данных
    save_to_database(encrypted_text, text_to_encrypt, int(encryption_key))

    bot.send_message(message.chat.id, f'Encrypted text: {encrypted_text}\nEncryption key: {encryption_key}')
    states[message.chat.id] = None


# Обработчик для кнопки "Decrypt text"
@bot.message_handler(func=lambda message: message.text == 'Decrypt text')
def handle_decrypt_start(message):
    # Устанавливаем состояние "ожидание текста для расшифрования"
    states[message.chat.id] = 'decrypt_text'
    bot.send_message(message.chat.id, 'Enter the text that needs to be decrypted')


# Обработчик для ответа на текст для расшифрования
@bot.message_handler(func=lambda message: states.get(message.chat.id) == 'decrypt_text')
def handle_decrypt_text(message):
    global text_to_encrypt
    # Получаем текст для расшифрования из сообщения пользователя
    text_to_encrypt = message.text

    # Спрашиваем у пользователя ключ для расшифрования
    bot.send_message(message.chat.id, 'Enter the key for decryption')

    # Устанавливаем состояние "ожидание ключа для расшифрования"
    states[message.chat.id] = 'decrypt_key'


# Обработчик для ответа на ключ для расшифрования
@bot.message_handler(func=lambda message: states.get(message.chat.id) == 'decrypt_key')
def handle_decrypt_key(message):
    global text_to_encrypt

    decryption_key = message.text

    if not decryption_key.isdigit():
        bot.send_message(message.chat.id, 'Please enter a valid numeric key.')
        return

    # Извлекаем данные из базы данных
    encrypted_data = fetch_from_database(int(decryption_key))

    # Расшифровываем текст
    decrypted_text = decrypt(encrypted_data['encrypted_text'], int(decryption_key))

    bot.send_message(message.chat.id, f'Decrypted text: {decrypted_text}')
    states[message.chat.id] = None


# Ваша функция шифрования с использованием PyCryptodome
def encrypt(text, key):
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC)

    # Подготовка текста (добавление padding)
    plaintext = text.encode('utf-8')
    plaintext = pad(plaintext, AES.block_size)

    # Шифрование
    ciphertext = cipher.encrypt(plaintext)

    # Кодирование в base64 для удобства передачи
    ciphertext_base64 = base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
    return ciphertext_base64


# Ваша функция расшифрования с использованием PyCryptodome
def decrypt(ciphertext, key):
    # Декодируем base64
    ciphertext = base64.b64decode(ciphertext)

    # Извлекаем IV и шифрованный текст
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Инициализируем объект шифрования
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)

    # Расшифровываем текст и убираем padding
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return decrypted_text


def save_to_database(encrypted_text, decrypted_text, encryption_key):
    db_connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="encbot"
    )

    cursor = db_connection.cursor()

    insert_query = "INSERT INTO encrypted_data (encrypted_text, decrypted_text, encryption_key) VALUES (%s, %s, %s)"
    cursor.execute(insert_query, (encrypted_text, decrypted_text, encryption_key))

    db_connection.commit()

    cursor.close()
    db_connection.close()

def fetch_from_database(encryption_key):
    db_connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="encbot"
    )

    cursor = db_connection.cursor(dictionary=True)

    select_query = "SELECT encrypted_text FROM encrypted_data WHERE encryption_key = %s"
    cursor.execute(select_query, (encryption_key,))
    result = cursor.fetchone()

    cursor.close()
    db_connection.close()

    return result


# Запуск бота
bot.polling(none_stop=True, interval=0)
