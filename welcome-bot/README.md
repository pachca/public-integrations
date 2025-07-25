# Pachca Welcome Bot

Бот для автоматического приветствия новых участников рабочего пространства в Пачке с настраиваемыми шаблонами приветственных сообщений.

## Подготовка к запуску

### Настройка в Пачке

1. В Пачке перейдите в раздел «Интеграции» → «Чат-боты и Вебхуки».
2. Создайте бота для нескольких чатов.
3. Сделайте бота публичным — иначе он не сможет создавать личные чаты с пользователями.
4. Выберите тип события исходящего Webhook: «Изменение участников пространства».
5. Сохраните токен бота (`access_token`) и Signing secret — они понадобятся далее.

---

## Локальный запуск

### 1. Клонируйте репозиторий

```sh
git clone https://github.com/pachca/pachca-welcome-bot.git
cd pachca-welcome-bot
```

### 2. Создание и редактирование файла окружения

```sh
copy .env.example .env
notepad .env
```

Заполните необходимые переменные в `.env`.

> **Примечание:**
> Шаблоны приветствий (`default`, `extended`, `short`) находятся в `messages.yml`. Изменяйте их по необходимости. В `.env` переменная `WELCOME_MESSAGE_TYPE` определяет используемый шаблон.

### 3. Установка зависимостей и запуск сервера

```sh
bundle install
ruby run.rb
```

Сервер будет доступен по адресу: [http://localhost:4567](http://localhost:4567)

---

### 4. Использование ngrok для тестирования

Чтобы принимать вебхуки из Пачки при локальном запуске, сервер должен быть публичным. Для этого удобно использовать ngrok:

```sh
npm install -g ngrok
ngrok http 4567
```

ngrok выдаст URL вида:
```
https://7357-51-159-135-74.ngrok-free.app
```

Укажите этот URL в настройках вебхука в Пачке:
```
https://7357-51-159-135-74.ngrok-free.app/webhook
```

---

## Локальный запуск с Docker

### 1. Убедитесь, что Docker и Docker Compose установлены на вашем компьютере. Если нет, скачайте и установите их с официального сайта Docker. 

Проверить наличие Docker можно командами `docker --version` и `docker-compose --version`

### 2. Клонируйте репозиторий на сервер:
   ```sh
   git clone https://github.com/pachca/pachca-welcome-bot.git
   cd pachca-welcome-bot
   ```
### 3. Создайте файл `.env` на основе примера:
   ```sh
   copy .env.example .env
   ```
### 4. Заполните необходимые переменные:
   ```sh
   notepad .env
   ```
### 5. Проверьте файлы: 
- в  `docker-compose.yml` указан правильный порт: `4567:4567`
- в `Gemfile` на 5 строчке разместите `gem 'webrick', '~> 1.8'`, при этом ничего не удаляйте

### 6. Откройте приложение Запустите контейнер с ботом:
   ```sh
   docker-compose up -d
   ```
   Эта команда:
   - Соберёт Docker-образ с ботом
   - Запустит контейнер в фоновом режиме
   - Пробросит порт 4567 на ваш компьютер

### 7. В отдельном терминале установите и запустите ngrok:
   ```sh
   npm install -g ngrok
   ngrok http 4567
   ```
   ngrok выдаст URL вида:
   ```
   https://7357-51-159-135-74.ngrok-free.app
   ```
   Используйте этот URL в настройках вебхука в Пачке:
   ```
   https://7357-51-159-135-74.ngrok-free.app/api/webhook
   ```

## Деплой для прода

### Развертывание на Vercel

1. Если у вас ещё нет аккаунта Vercel, зарегистрируйтесь на сайте [vercel.com](https://vercel.com).
2. Импортируйте репозиторий в Vercel из GitHub и настройте переменные окружения (раздел **Settings → Environment Variables**):
   - `PACHCA_TOKEN`
   - `PACHCA_WEBHOOK_SECRET`
   - `WELCOME_MESSAGE_TYPE`
3. После деплоя используйте URL в настройках вебхука в Пачке:
   ```
   https://your-project.vercel.app/api/webhook
   ```
---

### Развертывание на собственном сервере (Linux/Ubuntu)

#### С использованием Docker

1. Клонируйте репозиторий на сервер:
   ```sh
   git clone https://github.com/pachca/pachca-welcome-bot.git
   cd pachca-welcome-bot
   ```
2. Создайте файл `.env` на основе примера:
   ```sh
   cp .env.example .env
   ```
3. Заполните переменные окружения:
   ```sh
   nano .env
   ```
4. Настройте порты в `docker-compose.yml` (например, `80:4567`, где `80` — внешний порт, `4567` — внутренний). Ваш сервер будет доступен по адресу внешнего порта.

5. В `Gemfile` на 5 строчке разместите `gem 'webrick', '~> 1.8'` для корректной установки зависимостей, при этом ничего не удаляйте

6. Запустите контейнер с ботом:
   ```sh
   docker-compose up -d
   ```
7. Другие команды:
- Проверка статуса:
   ```sh
   docker-compose ps
   ```
- Остановить контейнер:
   ```sh
   docker-compose stop
   ```
- Полностью удалить контейнер:
   ```sh
   docker-compose down
   ```

> **Используйте URL в настройках вебхука в Пачке**
> ```
> https://your-domain.com:port/api/webhook
> ```
---

#### С использованием systemd

1. Клонируйте репозиторий на сервер:
   ```sh
   git clone https://github.com/pachca/pachca-welcome-bot.git
   cd pachca-welcome-bot
   ```
2. Установите зависимости:
   ```sh
   bundle install
   ```
3. Создайте файл `.env` на основе примера:
   ```sh
   cp .env.example .env
   ```
4. Заполните переменные окружения:
   ```sh
   nano .env
   ```
5. В `Gemfile` на 5 строчке разместите `gem 'webrick', '~> 1.8'` для корректной установки зависимостей, при этом ничего не удаляйте

6. Создайте systemd-сервис для автозапуска:
   ```sh
   sudo nano /etc/systemd/system/pachca-welcome-bot.service
   ```
   Пример содержимого файла:
   ```ini
   [Unit]
   Description=Pachca Welcome Bot
   After=network.target

   [Service]
   Type=simple
   User=your_user
   WorkingDirectory=/path/to/pachca-welcome-bot
   ExecStart=/usr/bin/ruby /path/to/pachca-welcome-bot/run.rb
   Restart=on-failure
   Environment=RACK_ENV=production
   EnvironmentFile=/path/to/pachca-welcome-bot/.env

   [Install]
   WantedBy=multi-user.target
   ```
7. Активируйте и запустите сервис:
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl start pachca-welcome-bot
   ```
8. Для автозапуска при загрузке системы:
   ```sh
   sudo systemctl enable pachca-welcome-bot
   ```

> **Используйте URL в настройках вебхука в Пачке**
> ```
> https://your-domain.com:port/webhook
> ```

> **Рекомендуется**: Настройте Nginx как обратный прокси и SSL через Let's Encrypt для продакшена.

8. Другие команды:
- Для проверки статуса
```
sudo systemctl status pachca-welcome-bot
```
- Для остановки
```
sudo systemctl stop pachca-welcome-bot
```
- Для перезагрузки
```
sudo systemctl restart pachca-welcome-bot
```

## Безопасность

Бот реализует следующие меры безопасности:

- Аутентификация через токены API Пачки
- Хранение токенов в переменных окружения (не в коде)
- Проверка подписи вебхуков с использованием HMAC SHA256
- Проверка времени вебхука для предотвращения replay-атак
- Валидация IP-адреса отправителя вебхуков
- Использование HTTPS для всех запросов
- Минимальные необходимые права для бота
- Логирование событий с маскированием чувствительных данных

### Проблемы с безопасностью вебхуков

Для отладки можно временность отключить проверку подписи, IP-адреса и времени:
- `SKIP_SIGNATURE_VERIFICATION=true`
- `SKIP_IP_VERIFICATION=true`
- `SKIP_TIMESTAMP_VERIFICATION=true`

**Важно**: Не рекомендуется для продакшена.

---

## Мониторинг и обслуживание

### Эндпоинты для проверки состояния

- **GET /health** — Healthcheck-эндпоинт для автоматического мониторинга. Возвращает JSON `{ "status": "ok" }` и HTTP 200. Удобен для внешних систем мониторинга и проверки работоспособности сервиса.
  
  ```sh
  curl http://localhost:4567/health
  # Ответ: {"status":"ok"}
  ```
- **GET /** — Проверка статуса бота. Возвращает простой текст и HTTP 200, если бот работает.
  
  ```sh
  curl http://localhost:4567/
  # Ответ: Pachca Welcome Bot is running!
  ```
- **GET /api/webhook** или **GET /webhook** — Проверка доступности эндпоинтов для вебхуков (возвращает статус и документацию, если настроено).

### Проверка состояния и логирование

1. В логах автоматически маскируются все чувствительные данные (токены, секреты).
- Пример строки лога:
  ```
  [2025-06-12 17:20:53 +0300] WARN: [ОТЛАДКА] Получен вебхук от Pachca
  ```
2. Для просмотра последних строк лога:
- При запуске через systemd:
  ```sh
  journalctl -u pachca-welcome-bot -n 50
  ```
- При запуске через Docker:
  ```sh
  docker logs <container_name>
  ```

## Лицензия

MIT