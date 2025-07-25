FROM ruby:3.1-slim

WORKDIR /app

# Установка зависимостей для сборки нативных расширений
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Установка правильной версии Bundler
RUN gem install bundler:2.4.22

# Копирование файлов Gemfile
COPY Gemfile Gemfile.lock ./

# Установка зависимостей
RUN bundle install

# Копирование остальных файлов проекта
COPY . .

# Открытие порта
EXPOSE 4567

# Запуск сервера
CMD ["ruby", "server.rb", "-o", "0.0.0.0", "-p", "4567"]
