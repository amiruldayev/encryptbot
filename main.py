import telebot
from telebot import types
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

TOKEN = '6323376518:AAHqdDLlJfhBxEos-yICy_wW8JDEy225qMk'
bot = telebot.TeleBot(TOKEN)

# Состояния для отслеживания контекста диалога
states = {}

# Переменные для хранения текста и ключа для шифрования и расшифрования
text_to_encrypt = None
encryption_key = None


# Обработчик команды /start
@bot.message_handler(commands=['start'])
def handle_start(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn_enc = types.KeyboardButton('Encrypt text')
    btn_des = types.KeyboardButton('Decrypt text')
    markup.add(btn_enc, btn_des)
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
    global encryption_key
    # Получаем ключ для шифрования из сообщения пользователя
    encryption_key = message.text

    # Проверяем, что ключ состоит только из цифр
    if not encryption_key.isdigit():
        bot.send_message(message.chat.id, 'Please enter a valid numeric key.')
        return

    # Здесь вы можете использовать ваш алгоритм шифрования
    # Например, простой шифр цезаря
    ciphertext = encrypt(text_to_encrypt, int(encryption_key))

    # Отправляем зашифрованный текст и ключ пользователю
    bot.send_message(message.chat.id, f'Encrypted text: {ciphertext}\nEncryption key: {encryption_key}')

    # Сбрасываем состояние
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
    global encryption_key
    # Получаем ключ для расшифрования из сообщения пользователя
    decryption_key = message.text

    # Проверяем, что ключ состоит только из цифр
    if not decryption_key.isdigit():
        bot.send_message(message.chat.id, 'Please enter a valid numeric key.')
        return

    # Расшифровываем текст
    decrypted_text = decrypt(text_to_encrypt, int(decryption_key))

    # Отправляем расшифрованный текст
    bot.send_message(message.chat.id, f'Decrypted text: {decrypted_text}')

    # Сбрасываем состояние
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


# Запуск бота
bot.polling(none_stop=True, interval=0)
