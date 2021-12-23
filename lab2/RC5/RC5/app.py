from RC5.RC5 import RC5

key = bytes(input("Введите ключ: "), 'utf-8')
block_size = int(input("Введите размер блока: "))
rounds = int(input("Введите раунд: "))
text = bytes(input("Введите текст: "), 'utf-8')

encrypt_text = RC5(key, block_size, rounds)
decrypt_text = RC5(key, block_size, rounds)

print("Зашифрованное слово:", encrypt_text.encrypt(text))

print("Расшифрованное слово: " + (decrypt_text.decrypt(decrypt_text.encrypt(text))).decode('utf-8'))