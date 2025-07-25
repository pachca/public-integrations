#!/usr/bin/env ruby
# Простой скрипт для запуска бота

require_relative 'server'
require 'webrick'

# Если скрипт запущен напрямую, запускаем сервер
if __FILE__ == $0
  port = ENV['PORT'] || 4567
  
  # Создаем сервер WEBrick
  server = WEBrick::HTTPServer.new(Port: port, Host: '0.0.0.0')
  
  # Монтируем обработчики для разных путей
  server.mount_proc '/api/webhook', lambda { |req, res|
    Handler.call(req, res)
  }
  
  server.mount_proc '/webhook', lambda { |req, res|
    Handler.call(req, res)
  }
  
  server.mount_proc '/', lambda { |req, res|
    res.body = "Pachca Welcome Bot is running!"
    res.status = 200
    res['Content-Type'] = 'text/plain'
  }
  
  # Обработка сигнала прерывания
  trap 'INT' do 
    server.shutdown 
    puts "\nСервер остановлен"
  end
  
  puts "[#{Time.now}] Запуск бота через WEBrick на порту #{port}..."
  puts "[#{Time.now}] Сервер принимает запросы на всех интерфейсах (0.0.0.0)"
  puts "[#{Time.now}] Веб-интерфейс доступен по адресу: http://localhost:#{port}"
  puts "[#{Time.now}] Для настройки вебхука в Пачке используйте URL: http://your-domain/webhook или http://your-domain/api/webhook"
  puts "[#{Time.now}] Нажмите Ctrl+C для остановки"
  
  # Запускаем сервер
  server.start
end
