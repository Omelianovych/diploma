#!/bin/bash

echo "🚀 [TRIGGER] Начинаем генерацию событий..."

# 1. OPENAT
# Создаем файл с уникальным именем, чтобы легко найти в логах
FILENAME="diploma_test_openat.txt"
echo "🔹 [1] Генерируем OPENAT (touch $FILENAME)..."
touch $FILENAME
rm $FILENAME

sleep 0.5

# 2. EXECVE
# Запускаем команду. Используем ls с конкретным флагом
echo "🔹 [2] Генерируем EXECVE (ls -la)..."
ls -la /tmp >/dev/null

sleep 0.5

# 3. CONNECT
# Подключаемся к Python-серверу (который ты запустишь отдельно)
# Это вызовет CONNECT у curl и ACCEPT у python3
TARGET="127.0.0.1:8000"
echo "🔹 [3] Генерируем CONNECT (curl -> $TARGET)..."
curl -s http://$TARGET >/dev/null

echo "✅ [TRIGGER] Готово."
