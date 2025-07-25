Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8
# encoding: utf-8
require './app'

# Настройки для Puma
if ENV['RACK_ENV'] == 'development'
  require 'sinatra/reloader' if defined?(Sinatra::Reloader)
  ENV['RACK_ALLOW_ALL_HOSTS'] = 'true'
  puts "Запуск в режиме разработки на порту #{ENV['PORT'] || 4567}"
end

run UnfurlApp
