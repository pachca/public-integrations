#!/bin/bash
# Установка кодировки
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export RUBYOPT="-E UTF-8:UTF-8"

# Вывод информации о среде
echo "Ruby version: $(ruby -v)"
echo "Encoding settings:"
echo "  LANG=$LANG"
echo "  LC_ALL=$LC_ALL"
echo "  RUBYOPT=$RUBYOPT"
echo "  Ruby default external encoding: $(ruby -e 'puts Encoding.default_external')"
echo "  Ruby default internal encoding: $(ruby -e 'puts Encoding.default_internal')"

# Установка bundler и зависимостей
gem install bundler -v 2.4.10
bundle install

# Проверка конфигурации
echo "Content of config.ru:"
cat config.ru
