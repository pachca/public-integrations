FROM ruby:3.2-slim

WORKDIR /app

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Копирование файлов проекта
COPY Gemfile Gemfile.lock ./
RUN bundle install --without development

# Копирование остальных файлов
COPY . .

# Настройка переменных окружения
ENV RACK_ENV=production
ENV PORT=8080

# Открытие порта
EXPOSE 8080

# Запуск приложения
CMD ["bundle", "exec", "puma", "config.ru", "-p", "8080"]
