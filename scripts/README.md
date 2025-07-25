# Pachca Unfurling Bot (Ruby)

Бот для разворачивания ссылок (unfurling) в Пачке с поддержкой Trello, Kaiten и сообщений из Пачки и возможностью добавить другие обработчики для сторонних сервисов.

## Быстрый старт

## Настройка в Пачке

1. В Пачке перейдите в раздел "Интеграции" -> "Чат-боты и Вебхуки"
2. Создайте Unfurl бота
3. Сохраните токен и Signing secret бота. Они будут использоваться в следующих шагах
4. Для разворачивания ссылок на сообщения из Пачки понадобится дополнительный токен бота

### Локальный запуск для тестов

1. Клонируйте репозиторий и перейдите в папку:
   ```sh
   git clone https://github.com/artemypmnchk/pachca_unfurl_public.git
   cd pachca_unfurl_public
   ```

2. Создайте файл `.env` на основе `.env.example` и заполните необходимые переменные:
   ```sh
   cp .env.example .env
   # Отредактируйте .env и добавьте ваши токены
   ```

3. Установите зависимости и запустите сервер:
   ```sh
   bundle install
   bundle exec ruby app.rb
   ```

4. Сервер будет доступен по адресу http://localhost:4567

### Запуск с использованием Docker

Пошаговая инструкция по запуску бота в Docker. Этот вариант подойдет, чтобы не устанавливать Ruby и зависимости на вашем компьютере и сразу запустить бота:

#### Шаг 1: Подготовка

1. Убедитесь, что Docker и Docker Compose установлены на вашем компьютере. Если нет, скачайте и установите их с официального сайта Docker.
   - Проверить наличие Docker можно командами `docker --version` и `docker-compose --version`

2. Создайте файл `.env` с необходимыми переменными окружения:
   ```sh
   cp .env.example .env
   ```

3. Откройте файл `.env` в любом текстовом редакторе и заполните переменные окружения.

#### Шаг 2: Запуск бота

1. Откройте терминал и перейдите в папку с проектом

2. Запустите контейнер с ботом:
   ```sh
   docker-compose up -d
   ```
   Эта команда сделает следующее:
   - Соберёт Docker-образ с ботом
   - Запустит контейнер в фоновом режиме
   - Пробросит порт 4567 на ваш компьютер

3. Проверьте, что бот запущен и работает. Откройте в браузере:
   ```
   http://localhost:4567/health
   ```
   Вы должны увидеть JSON-ответ со статусом бота

#### Шаг 3: Настройка публичного URL с помощью ngrok

1. **Важно**: Для работы с Пачкой боту нужен публичный URL, чтобы отправлять на него вебхуки. При локальном запуске через Docker используйте ngrok для получения публичного URL.

2. **Установите ngrok** на вашу локальную машину (не в Docker):
   - Для Mac: `brew install ngrok` или скачайте с [ngrok.com](https://ngrok.com/download)
   - Для Windows: скачайте с [ngrok.com](https://ngrok.com/download)
   - Для Linux: `sudo snap install ngrok` или скачайте с [ngrok.com](https://ngrok.com/download)

3. **Запустите ngrok в отдельном терминале** (параллельно с работающим Docker):
   ```sh
   ngrok http 4567
   ```
   После запуска ngrok покажет вам URL вида `https://xxxx-xx-xx-xxx-xx.ngrok-free.app`

4. **Настройте вебхук в Пачке**, указав URL в формате:
   ```
   https://xxxx-xx-xx-xxx-xx.ngrok-free.app/v1/unfurl
   ```
   
   > **Примечание**: Обратите внимание, что бесплатный URL ngrok меняется при каждом запуске. Для постоянного URL нужна платная подписка ngrok или реальный хостинг.

#### Шаг 4: Управление ботом

1. Для просмотра логов бота используйте:
   ```sh
   docker-compose logs -f
   ```

2. Для остановки бота:
   ```sh
   docker-compose down
   ```

3. Для перезапуска бота (например, после изменения настроек):
   ```sh
   docker-compose restart
   ```

4. Для проверки статуса бота:
   ```sh
   docker-compose ps
   ```



## Деплой для прода

### Вариант 1: Быстрый деплой на Vercel (рекомендуется для проверок или полноценной работы без сервера)

1. Если у вас еще нет аккаунта Vercel, зарегистрируйтесь на сайте [vercel.com](https://vercel.com)

2. Дальше импортируйте репозиторий в Vercel из GitHub и настройте переменные окружения. Их можно задать при импорте проекта, а также в разделе "Settings" -> "Environment Variables":
   - `UNFURL_BOT_TOKEN` - токен для авторизации в API Пачки
   - `PACHCA_WEBHOOK_SECRET` - Signing secret ботов в Пачке
   - `PACHCA_API_TOKEN` - токен с расширенными правами для разворачивания сообщений из Пачки
   - Другие токены для используемых сервисов (`TRELLO_KEY`, `TRELLO_TOKEN`, `KAITEN_TOKEN` и т.д.)

3. Настройте вебхук в Пачке, указав URL вашего приложения с путем `/unfurl` (например, `https://your-app.vercel.app/unfurl`)

> **Примечание по бессерверным средам**: Бот автоматически определяет работу в Vercel или других бессерверных средах и настраивает логирование в STDOUT вместо файла, чтобы избежать ошибок с файловой системой, доступной только для чтения.

### Вариант 2: Деплой на собственный сервер (Linux)

У вас есть два способа развернуть бота на собственном сервере:

#### Вариант 2.1: С использованием Docker (рекомендуется)

Это самый простой способ, который не требует установки Ruby и других зависимостей:

1. Установите Docker и Docker Compose на сервере:
   ```sh
   # Для Ubuntu/Debian
   sudo apt update
   sudo apt install docker.io docker-compose
   sudo systemctl enable docker
   sudo systemctl start docker
   ```

2. Клонируйте репозиторий и настройте переменные окружения:
   ```sh
   git clone https://github.com/artemypmnchk/pachca_unfurl_public.git
   cd pachca_unfurl_public
   cp .env.example .env
   nano .env  # Заполните переменные окружения
   ```

3. Настройте порты в `docker-compose.yml` (при необходимости):
   ```yaml
   ports:
     - "80:8080"  # Если хотите использовать порт 80
   ```

4. **Запуск и управление ботом**

   - **Первый запуск:**
     Команда `docker-compose up -d` соберет образ (если его нет) и запустит контейнер с ботом в фоновом режиме (`-d` означает detached).
     ```sh
     docker-compose up -d
     ```

   - **Просмотр логов (журнала работы):**
     Это основная команда для отладки. Выполняйте ее, чтобы видеть, что происходит с ботом, когда он получает запросы от Пачки.
     ```sh
     # Показать логи в реальном времени (нажмите Ctrl+C для выхода)
     docker-compose logs -f

     # Показать последние 200 строк логов
     docker-compose logs --tail=200
     ```

   - **Проверка статуса:**
     Убедитесь, что контейнер запущен и работает. В колонке `State` должно быть `Up`.
     ```sh
     docker-compose ps
     ```

   - **Остановка и выключение:**
     ```sh
     # Просто остановить контейнер (можно запустить снова через docker-compose start)
     docker-compose stop

     # Полностью выключить и удалить контейнер (нужно перед обновлением)
     docker-compose down
     ```

5. **Обновление бота до последней версии**
   Для обновления бота до последней версии из Git-репозитория выполните следующие команды:
   ```sh
   # 1. Убедитесь, что вы в директории проекта
   # cd /путь/к/вашему/проекту/pachca_unfurl_public

   # 2. Остановите и удалите старый контейнер
   docker-compose down

   # 3. Скачайте последние изменения из репозитория
   git pull

   # 4. Запустите новую версию, пересобрав образ с изменениями
   docker-compose up -d --build
   ```
   Флаг `--build` заставит Docker Compose пересобрать образ, если в коде проекта были изменения.

6. **Автозапуск Docker при перезагрузке сервера**
   Чтобы Docker и ваши контейнеры (с политикой перезапуска `unless-stopped` или `always`) автоматически запускались после перезагрузки сервера:
   ```sh
   sudo systemctl enable docker
   ```

7. **Настройка Nginx и SSL (рекомендуется для продакшена)**
   Для надежной и безопасной работы в продакшене рекомендуется настроить веб-сервер Nginx как обратный прокси (reverse proxy) и подключить бесплатный SSL-сертификат от Let's Encrypt. Это обеспечит работу вашего бота по защищенному протоколу `https://`. Подробные инструкции можно найти в интернете.

#### Вариант 2.2: Без Docker (требуется установка Ruby)

Если вы предпочитаете установить бота без Docker:

{{ ... }}
   ```sh
   # Для Ubuntu/Debian
   sudo apt update
   sudo apt install git curl libssl-dev libreadline-dev zlib1g-dev autoconf bison build-essential
   
   # Установка rbenv для управления версиями Ruby
   git clone https://github.com/rbenv/rbenv.git ~/.rbenv
   echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
   echo 'eval "$(rbenv init -)"' >> ~/.bashrc
   source ~/.bashrc
   
   # Установка ruby-build
   git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
   
   # Установка Ruby 3.2.0
   rbenv install 3.2.0
   rbenv global 3.2.0
   
   # Установка Bundler
   gem install bundler
   ```

2. Клонируйте репозиторий и установите зависимости:
   ```sh
   git clone https://github.com/artemypmnchk/pachca_unfurl_public.git
   cd pachca_unfurl_public
   bundle install
   ```

3. Создайте файл `.env` с необходимыми переменными окружения:
   ```sh
   cp .env.example .env
   nano .env  # Заполните переменные окружения
   ```

4. Создайте systemd сервис для автозапуска:
   ```sh
   sudo nano /etc/systemd/system/pachca-unfurl.service
   ```
   
   Содержимое файла:
   ```
   [Unit]
   Description=Pachca Unfurling Bot
   After=network.target
   
   [Service]
   Type=simple
   User=your_username
   WorkingDirectory=/path/to/pachca_unfurl_public
   ExecStart=/home/your_username/.rbenv/shims/bundle exec ruby app.rb -p 4567 -e production
   Restart=always
   Environment=RACK_ENV=production
   EnvironmentFile=/path/to/pachca_unfurl_public/.env
   
   [Install]
   WantedBy=multi-user.target
   ```

5. Активируйте и запустите сервис:
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable pachca-unfurl
   sudo systemctl start pachca-unfurl
   ```

6. Настройте Nginx как обратный прокси и SSL с Let's Encrypt (рекомендуется для продакшена).

## Добавление новых обработчиков ссылок

1. Добавьте новый обработчик в `app.rb`:

```ruby
def self.your_service_handler(url)
  # Получение токена из переменных окружения
  api_token = ENV['YOUR_SERVICE_TOKEN']
  raise 'No YOUR_SERVICE_TOKEN in ENV' unless api_token
  
  # Парсинг URL для получения идентификатора
  match = url.match(%r{your-service\.com/([a-zA-Z0-9]+)})
  raise 'Invalid URL format' unless match
  item_id = match[1]
  
  # Запрос к API сервиса
  api_url = "https://api.your-service.com/items/#{item_id}"
  uri = URI(api_url)
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{api_token}"
  req['Accept'] = 'application/json'
  
  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  raise "API error: #{res.code}" unless res.code == '200'
  
  # Обработка ответа
  data = JSON.parse(res.body)
  title = data['title'] || 'Item Title'
  description = data['description'] || 'No description'
  
  # Возвращаем результат
  {
    title: title,
    url: url,
    description: description,
    icon: '📄'
  }
end
```

2. Добавьте сервис в `services.yml`:

```yaml
- name: your_service
  match: "your-service\\.com"
  handler: "your_service_handler"
```

3. Добавьте переменную окружения в `.env`:

```
YOUR_SERVICE_TOKEN=your_api_token_here
```

## Мониторинг и обслуживание

Бот предоставляет эндпоинт `/health` для мониторинга состояния и проверки работоспособности.

### Проверка состояния

Для проверки состояния бота отправьте GET-запрос на эндпоинт `/health`:

```bash
curl https://your-bot-url.com/health
```

Ответ будет содержать следующую информацию:

```json
{
  "status": "ok",
  "version": "1.1.0",
  "environment": "production",
  "timestamp": "2025-06-02T16:57:37+00:00",
  "services": ["trello", "kaiten"],
  "checks": {
    "environment_variables": {
      "UNFURL_BOT_TOKEN": true,
      "UNFURL_SIGNING_SECRET": true,
      "TRELLO_KEY": true,
      "TRELLO_TOKEN": true,
      "KAITEN_TOKEN": true
    },
    "log_file_writable": true
  }
}
```

Если статус равен `"ok"`, бот работает корректно. Если статус `"error"`, проверьте раздел `checks` для выявления проблем.

### Логирование

Бот ведет логи в файл `unfurl.log` (или другой файл, указанный в переменной окружения `LOG_FILE`). Логи автоматически ротируются, сохраняя до 10 файлов по 1 МБ каждый.

Для просмотра логов в реальном времени используйте:

```bash
tail -f unfurl.log
```
### Эндпоинты

| Эндпоинт | Метод | Описание |
|------------|------|-------------|
| `/` | GET | Проверка доступности бота |
| `/health` | GET | Проверка состояния бота |
| `/unfurl` | POST | Обработка запросов на unfurling |

### Настройка вебхука в Пачке

При настройке вебхука в Пачке используйте эндпоинт:

```
https://your-bot-url.com/unfurl
```

## Безопасность

- Все токены хранятся только в переменных окружения, не в коде
- Проверка подписи запросов от Пачки
- Используйте HTTPS при деплое на продакшн

## Лицензия

MIT