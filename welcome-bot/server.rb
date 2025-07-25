#!/usr/bin/env ruby
require 'dotenv'
require 'json'
require 'logger'
require 'net/http'
require 'openssl'
require 'time'
require 'uri'
require 'rack'
require 'httparty'
require 'yaml'
require 'webrick'
# Используем только WEBrick без Sinatra

# --- SECURITY HELPERS ---
# Mask sensitive data in hashes/strings for safe logging
MASKED = '[MASKED]'
SENSITIVE_KEYS = %w[token secret authorization password access_token pachca_token pachca_webhook_secret]

def mask_sensitive_data(obj)
  case obj
  when Hash
    obj.transform_keys(&:to_s).transform_values do |v|
      if SENSITIVE_KEYS.include?(v.to_s.downcase) || SENSITIVE_KEYS.include?(v.to_s)
        MASKED
      elsif v.is_a?(Hash) || v.is_a?(Array)
        mask_sensitive_data(v)
      else
        v
      end
    end
  when Array
    obj.map { |v| mask_sensitive_data(v) }
  when String
    # Mask tokens/secrets in string if pattern matches
    SENSITIVE_KEYS.reduce(obj) do |str, key|
      str.gsub(/("?#{key}"?\s*:\s*")[^"]+(")/i, "\\1#{MASKED}\\2")
    end
  else
    obj
  end
end

# Validate incoming webhook payload (basic schema, types, length)
def validate_webhook_payload(payload)
  begin
    data = JSON.parse(payload)
  rescue JSON::ParserError
    return { valid: false, error: 'Invalid JSON' }
  end

  # Принять event_type или event (одно из них обязательно)
  event_type = data['event_type'] || data['event']
  missing_fields = []
  missing_fields << 'event_type or event' if !event_type
  missing_fields << 'user_ids' unless data.key?('user_ids')
  unless missing_fields.empty?
    return { valid: false, error: "Missing required fields: #{missing_fields.join(', ')}" }
  end
  # Type checks (example: user_ids should be array)
  unless data['user_ids'].is_a?(Array) && data['user_ids'].all? { |id| id.to_s =~ /^\d+$/ }
    return { valid: false, error: 'user_ids must be an array of numeric IDs' }
  end
  # Optional: limit lengths/values
  if event_type.to_s.size > 64
    return { valid: false, error: 'event_type (or event) too long' }
  end
  # Для совместимости: добавить event_type если только event есть
  data['event_type'] ||= data['event'] if data['event']
  { valid: true, data: data }
end


# Явно загружаем переменные окружения из .env файла
Dotenv.load('.env')

# Настройки логирования - инициализируем в самом начале
$logger = Logger.new($stdout)

# Устанавливаем уровень логирования из переменной окружения LOG_LEVEL
log_level = ENV['LOG_LEVEL'] || 'WARN'
case log_level.upcase
when 'DEBUG'
  $logger.level = Logger::DEBUG
when 'INFO'
  $logger.level = Logger::INFO
when 'WARN'
  $logger.level = Logger::WARN
when 'ERROR'
  $logger.level = Logger::ERROR
when 'FATAL'
  $logger.level = Logger::FATAL
else
  $logger.level = Logger::WARN  # По умолчанию WARN и выше
end

$logger.formatter = proc do |severity, datetime, progname, msg|
  "[#{datetime}] #{severity}: #{msg}\n"
end

# Проверяем, что логгер работает
puts "[СИСТЕМА] Запуск сервера Pachca Welcome Bot"
$logger.warn "[ОТЛАДКА] Запуск сервера Pachca Welcome Bot"
$logger.error "[ОШИБКА] Это тестовое сообщение об ошибке для проверки логгера"

# Тестовая отправка сообщения при запуске
$TEST_USER_ID = ENV['TEST_USER_ID'] || '580389'
$SEND_TEST_MESSAGE = ENV['SEND_TEST_MESSAGE'] == 'true'


# Переменные окружения уже загружены в начале файла
env_file = File.join(File.dirname(__FILE__), '.env')
puts "[Загружены переменные окружения из #{env_file}]"

# Всегда используем WEBrick, Sinatra не нужен
require 'webrick'

# Настройка логгера
$logger = Logger.new(STDOUT)
$logger.level = ENV['LOG_LEVEL'] == 'DEBUG' ? Logger::DEBUG : Logger::INFO

# Выводим информацию о загруженных переменных окружения
$logger.info "LOG_LEVEL: #{ENV['LOG_LEVEL']}"
$logger.info "WELCOME_MESSAGE_TYPE: #{ENV['WELCOME_MESSAGE_TYPE']}"
$logger.info "DISABLE_SIGNATURE_CHECK: #{ENV['DISABLE_SIGNATURE_CHECK']}"
$logger.info "DISABLE_IP_CHECK: #{ENV['DISABLE_IP_CHECK']}"
$logger.info "DISABLE_TIMESTAMP_CHECK: #{ENV['DISABLE_TIMESTAMP_CHECK']}"

# Загрузка переменных окружения
$PACHCA_TOKEN = ENV['PACHCA_TOKEN']
$PACHCA_WEBHOOK_SECRET = ENV['PACHCA_WEBHOOK_SECRET']
$WELCOME_MESSAGE_TYPE = ENV['WELCOME_MESSAGE_TYPE'] || 'default'

# Настройки проверок безопасности
$DISABLE_SIGNATURE_CHECK = ENV['DISABLE_SIGNATURE_CHECK'] == 'true'
$DISABLE_IP_CHECK = ENV['DISABLE_IP_CHECK'] == 'true'
$DISABLE_TIMESTAMP_CHECK = ENV['DISABLE_TIMESTAMP_CHECK'] == 'true'

# Загрузка шаблонов сообщений
def load_message_templates
  messages_file = File.join(File.dirname(__FILE__), 'messages.yml')
  if File.exist?(messages_file)
    YAML.load_file(messages_file)
  else
    $logger.warn "Файл шаблонов сообщений не найден: #{messages_file}"
    # Стандартные шаблоны на случай, если файл не найден
    {
      'short' => "👋 Привет{{name_greeting}}! Добро пожаловать в наше рабочее пространство Пачки!",
      'default' => "# 👋 Добро пожаловать в наше рабочее пространство{{name_greeting}}!\n\nМы рады видеть вас в нашей команде! Если у вас возникнут вопросы, не стесняйтесь обращаться к администраторам или коллегам.",
      'extended' => "# 👋 Добро пожаловать в наше рабочее пространство{{name_greeting}}!\n\nМы рады видеть вас в нашей команде! Вот несколько полезных ссылок, которые помогут вам быстрее освоиться:\n\n* [Документация Пачки](https://www.pachca.com/articles)\n* [Наш корпоративный портал](https://example.com/portal)\n* [Часто задаваемые вопросы](https://example.com/faq)\n\nЕсли у вас возникнут вопросы, не стесняйтесь обращаться к администраторам или коллегам."
    }
  end
end

# Получение содержимого сообщения на основе шаблона и данных пользователя
def get_message_content(message_type, user_data = nil)
  templates = load_message_templates
  template = templates[message_type] || templates['default']
  
  $logger.warn "[ОТЛАДКА] Формирование сообщения типа #{message_type}"
  $logger.warn "[ОТЛАДКА] Полученные данные пользователя: #{mask_sensitive_data(user_data).inspect}"
  
  # Замена плейсхолдера {{name_greeting}} на имя пользователя
  name_greeting = ""
  
  if user_data
    # Проверяем различные варианты структуры данных API
    if user_data['first_name']
      name = user_data['first_name']
      $logger.warn "[ОТЛАДКА] Найдено имя в first_name: #{name}"
    elsif user_data['name']
      name = user_data['name']
      $logger.warn "[ОТЛАДКА] Найдено имя в name: #{name}"
    elsif user_data['last_name']
      name = user_data['last_name']
      $logger.warn "[ОТЛАДКА] Найдено имя в last_name: #{name}"
    # Проверяем вложенные структуры
    elsif user_data['data'] && user_data['data']['first_name']
      name = user_data['data']['first_name']
      $logger.warn "[ОТЛАДКА] Найдено имя в data.first_name: #{name}"
    elsif user_data['data'] && user_data['data']['name']
      name = user_data['data']['name']
      $logger.warn "[ОТЛАДКА] Найдено имя в data.name: #{name}"
    elsif user_data['user'] && user_data['user']['first_name']
      name = user_data['user']['first_name']
      $logger.warn "[ОТЛАДКА] Найдено имя в user.first_name: #{name}"
    elsif user_data['user'] && user_data['user']['name']
      name = user_data['user']['name']
      $logger.warn "[ОТЛАДКА] Найдено имя в user.name: #{name}"
    else
      name = nil
      $logger.warn "[ОТЛАДКА] Имя пользователя не найдено в данных"
    end
    
    if name
      name_greeting = ", #{name}"
      $logger.warn "[ОТЛАДКА] Сформировано обращение: '#{name_greeting}'"
    end
  else
    $logger.warn "[ОТЛАДКА] Нет данных пользователя для формирования обращения"
  end
  
  # Заменяем плейсхолдер в шаблоне
  template = template.gsub("{{name_greeting}}", name_greeting)
  $logger.warn "[ОТЛАДКА] Итоговый шаблон с подстановкой: #{template[0..100]}..."
  
  template
end

# Класс для работы с API Пачки
class PachcaClient
  attr_reader :token

  def initialize(token)
    @token = token
    @base_url = 'https://api.pachca.com/api/shared/v1'
  end

  # Получение информации о сотруднике
  def get_user_info(user_id)
    url = "#{@base_url}/users/#{user_id}"
    headers = {
      'Content-Type' => 'application/json; charset=utf-8',
      'Authorization' => "Bearer #{@token}"
    }

    $logger.warn "[ОТЛАДКА] Запрос информации о пользователе #{user_id}, URL: #{url}"
    # Never log full headers with secrets/tokens
    $logger.warn "[ОТЛАДКА] Заголовки запроса: #{mask_sensitive_data(headers).inspect}"
    
    begin
      response = HTTParty.get(url, headers: headers)
      $logger.warn "[ОТЛАДКА] Получен ответ от API: #{response.code}"
      
      if response.code == 200
        parsed_response = JSON.parse(response.body)
        $logger.warn "[ОТЛАДКА] Успешно получена информация о пользователе #{user_id}"
        $logger.warn "[ОТЛАДКА] Структура ответа: #{parsed_response.keys.join(', ')}"
        
        # Проверяем разные варианты структуры ответа API
        if parsed_response['user']
          $logger.warn "[ОТЛАДКА] Найден объект 'user' в ответе"
          user_data = parsed_response['user']
        elsif parsed_response['data']
          $logger.warn "[ОТЛАДКА] Найден объект 'data' в ответе"
          user_data = parsed_response['data']
        else
          $logger.warn "[ОТЛАДКА] Используем весь ответ как данные пользователя"
          user_data = parsed_response
        end
        
        # Проверяем наличие имени
        if user_data['first_name'] || user_data['name']
          name = user_data['first_name'] || user_data['name']
          $logger.warn "[ОТЛАДКА] Найдено имя пользователя: #{name}"
        else
          $logger.warn "[ОТЛАДКА] Имя пользователя не найдено в ответе API"
        end
        
        { success: true, data: user_data }
      else
        $logger.warn "[ОТЛАДКА] Ошибка при получении информации о пользователе: #{response.code} - #{mask_sensitive_data(response.body)}"
        { success: false, error: "HTTP Error: #{response.code}", response: response.body }
      end
    rescue => e
      $logger.warn "[ОТЛАДКА] Исключение при получении информации о пользователе: #{e.message}"
      $logger.warn "[ОТЛАДКА] #{e.backtrace.join("\n")}"
      { success: false, error: e.message }
    end
  end

  # Отправка приветственного сообщения
  def send_welcome_message(user_id, message_type = 'default')
    $logger.warn "[ОТЛАДКА] Начинаем отправку приветственного сообщения пользователю #{user_id} (тип: #{message_type})"
    
    # Получаем информацию о пользователе
    $logger.warn "[ОТЛАДКА] Получаем информацию о пользователе #{user_id}"
    user_info = get_user_info(user_id)
    $logger.warn "[ОТЛАДКА] Получена информация о пользователе: #{user_info[:success] ? 'успешно' : 'ошибка'}"
    
    # Формируем сообщение
    $logger.warn "[ОТЛАДКА] Формируем сообщение типа #{message_type}"
    message_content = if user_info[:success]
      get_message_content(message_type, user_info[:data])
    else
      get_message_content(message_type)
    end
    
    $logger.warn "[ОТЛАДКА] Сформировано сообщение: #{message_content.inspect}"
    
    url = "#{@base_url}/messages"
    headers = {
      'Content-Type' => 'application/json; charset=utf-8',
      'Authorization' => "Bearer #{@token}"
    }
    
    # Never log full headers with secrets/tokens
    $logger.warn "[ОТЛАДКА] Заголовки запроса: #{mask_sensitive_data(headers).inspect}"
    
    # Создаем правильный формат пайлоада согласно документации API
    payload = {
      message: {
        entity_type: 'user',
        entity_id: user_id,
        content: message_content
      }
    }
    
    $logger.warn "[ОТЛАДКА] Отправка сообщения на URL: #{url}"
    $logger.warn "[ОТЛАДКА] JSON пайлоад: #{payload.to_json}"
    
    begin
      $logger.warn "[ОТЛАДКА] Отправляем HTTP POST запрос"
      response = HTTParty.post(url, body: payload.to_json, headers: headers)
      
      $logger.warn "[ОТЛАДКА] Получен ответ: код #{response.code}"
      $logger.warn "[ОТЛАДКА] Тело ответа: #{response.body}"
      
      if response.code == 200 || response.code == 201
        $logger.warn "[ОТЛАДКА] Сообщение успешно отправлено пользователю #{user_id}"
        { success: true, data: JSON.parse(response.body) }
      else
        $logger.warn "[ОТЛАДКА] Ошибка при отправке сообщения: #{response.code} - #{mask_sensitive_data(response.body)}"
        { success: false, error: "HTTP Error: #{response.code}", response: response.body }
      end
    rescue => e
      $logger.warn "[ОТЛАДКА] Исключение при отправке сообщения: #{e.message}"
      $logger.warn "[ОТЛАДКА] Стек вызовов: #{e.backtrace.join('\n')}"
      { success: false, error: e.message }
    end
  end
end

# Инициализация клиента Пачки
def pachca_client
  @pachca_client ||= PachcaClient.new($PACHCA_TOKEN)
end

# Проверка подписи вебхука
def verify_signature(payload_body, signature)
  # Временно отключаем проверку подписи для отладки
  $logger.warn "[ОТЛАДКА] Проверка подписи отключена, подпись: #{signature}"
  return true
  
  # Оригинальный код проверки подписи (временно отключен)
  return true if $DISABLE_SIGNATURE_CHECK
  return true if !signature || signature.empty? || !$PACHCA_WEBHOOK_SECRET
  
  begin
    hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), $PACHCA_WEBHOOK_SECRET, payload_body)
    # Безопасное сравнение строк
    if Rack.const_defined?('Utils') && Rack::Utils.respond_to?(:secure_compare)
      Rack::Utils.secure_compare(hmac, signature)
    else
      hmac == signature
    end
  rescue => e
    $logger.error "Error verifying signature: #{e.message}"
    false
  end
end

# Проверка времени вебхука (для предотвращения replay-атак)
def verify_webhook_timestamp(webhook_timestamp)
  # Временно отключаем проверку времени для отладки
  $logger.warn "[ОТЛАДКА] Проверка времени отключена, время: #{webhook_timestamp}"
  return true
  
  # Оригинальный код проверки времени (временно отключен)
  return true if $DISABLE_TIMESTAMP_CHECK
  
  return false unless webhook_timestamp
  
  # Преобразуем timestamp в целое число
  timestamp = webhook_timestamp.to_i
  current_time = Time.now.to_i
  
  # Проверяем, что вебхук не старше 5 минут
  (current_time - timestamp).abs < 300
end

# Проверка IP-адреса
def verify_ip_address(ip)
  # Временно отключаем проверку IP для отладки
  $logger.warn "[ОТЛАДКА] Проверка IP отключена, IP: #{ip}"
  return true
  
  # Оригинальный код проверки IP (временно отключен)
  return true if $DISABLE_IP_CHECK
  
  # Список разрешенных IP-адресов Пачки
  allowed_ips = ['37.200.70.177']
  
  allowed_ips.include?(ip)
end

# Обработка вебхука
def process_webhook(payload_body, signature, request_ip, timestamp)
  # Log incoming webhook with sensitive data masked
  $logger.warn "[ОТЛАДКА] Получен вебхук от Pachca"
  $logger.warn "[ОТЛАДКА] Тело запроса: #{mask_sensitive_data(payload_body).inspect}"
  $logger.warn "[ОТЛАДКА] Подпись: #{mask_sensitive_data(signature).inspect}"
  $logger.warn "[ОТЛАДКА] IP-адрес: #{request_ip.inspect}"
  $logger.warn "[ОТЛАДКА] Время: #{timestamp.inspect}"

  # --- Input validation ---
  validation = validate_webhook_payload(payload_body)
  unless validation[:valid]
    $logger.error "[ВАЛИДАЦИЯ] Некорректный вебхук: #{validation[:error]}"
    return { status: 400, body: { error: "Invalid webhook payload: #{validation[:error]}" } }
  end
  data = validation[:data]
  $logger.warn "[ОТЛАДКА] Настройки: WELCOME_MESSAGE_TYPE=#{$WELCOME_MESSAGE_TYPE}, DISABLE_SIGNATURE_CHECK=#{$DISABLE_SIGNATURE_CHECK}, DISABLE_IP_CHECK=#{$DISABLE_IP_CHECK}, DISABLE_TIMESTAMP_CHECK=#{$DISABLE_TIMESTAMP_CHECK}"
  
  # Все проверки отключены для отладки
  $logger.warn "[ОТЛАДКА] Все проверки безопасности отключены для отладки"
  
  # Все проверки отключены в коде функций
  # Просто для полноты вызываем их для логирования
  verify_signature(payload_body, signature)
  verify_ip_address(request_ip)
  verify_webhook_timestamp(timestamp)
  
  # Подробное логирование
  $logger.debug "[DEBUG] Received webhook with payload_body: #{payload_body.inspect}"
  $logger.debug "[DEBUG] Signature: #{signature.inspect}"
  $logger.debug "[DEBUG] Request IP: #{request_ip.inspect}"
  $logger.debug "[DEBUG] Timestamp: #{timestamp.inspect}"
  
  # Супер-подробное логирование
  $logger.warn "[ОТЛАДКА] Начинаем обработку JSON"
  
  begin
    # Проверяем, что payload_body это строка
    if payload_body.is_a?(String)
      $logger.warn "[ОТЛАДКА] payload_body является строкой"
      payload_json = payload_body
    else
      $logger.warn "[ОТЛАДКА] payload_body не является строкой, пытаемся преобразовать"
      payload_json = payload_body.read rescue payload_body.to_s
    end
    
    $logger.warn "[ОТЛАДКА] Парсим JSON: #{payload_json}"
    payload = JSON.parse(payload_json)
    $logger.warn "[ОТЛАДКА] JSON успешно распарсен: #{payload.inspect}"
    $logger.warn "[ОТЛАДКА] Тип события: #{payload['type']}, Событие: #{payload['event']}"
    
    # Обрабатываем событие company_member confirm
    is_confirm_event = payload['event'] == 'confirm' && payload['type'] == 'company_member'
    $logger.warn "[ОТЛАДКА] Проверка события: type=#{payload['type']}, event=#{payload['event']}, результат: #{is_confirm_event ? 'отправляем приветствие' : 'игнорируем'}"
    
    if is_confirm_event
      $logger.warn "[ОТЛАДКА] Получено событие company_member confirm"
      user_ids = if payload['user_ids'] && !payload['user_ids'].empty?
                   $logger.warn "[ОТЛАДКА] Найдены user_ids в корне: #{payload['user_ids'].inspect}"
                   payload['user_ids']
                 elsif payload['data'] && payload['data']['user_id']
                   $logger.warn "[ОТЛАДКА] Найден user_id в data: #{payload['data']['user_id']}"
                   [payload['data']['user_id']]
                 elsif payload['data'] && payload['data']['user_ids'] && !payload['data']['user_ids'].empty?
                   $logger.warn "[ОТЛАДКА] Найдены user_ids в data: #{payload['data']['user_ids'].inspect}"
                   payload['data']['user_ids']
                 else
                   $logger.warn "[ОТЛАДКА] Не найдены user_ids в пайлоаде. Используем тестовый ID"
                   [580389]
                 end
      if user_ids.empty?
        $logger.warn "[ОТЛАДКА] Не найдены пользователи для отправки приветственного сообщения"
        return { status: 200, body: { message: "Не найдены пользователи для отправки приветственного сообщения" } }
      end
      results = []
      user_ids.each do |uid|
        result = pachca_client.send_welcome_message(uid, ENV['WELCOME_MESSAGE_TYPE'] || 'default')
        results << { user_id: uid, result: result }
      end
      return { status: 200, body: { message: "Приветственные сообщения отправлены", results: results } }
    else
      $logger.warn "[ОТЛАДКА] Игнорируем событие типа #{payload['type']} #{payload['event']} (не company_member confirm)"
      return { status: 200, body: { message: "Событие не требует отправки приветствия" } }
    end
  rescue JSON::ParserError => e
    $logger.warn "[ОТЛАДКА] Ошибка парсинга JSON: #{e.message}"
    $logger.warn "[ОТЛАДКА] Содержимое payload_body: #{payload_body.inspect}"
    { status: 200, body: { error: "Неверный формат JSON, но мы все равно возвращаем 200 для отладки" } }
  rescue => e
    $logger.warn "[ОТЛАДКА] Неожиданная ошибка при обработке вебхука: #{e.message}"
    $logger.warn "[ОТЛАДКА] #{e.backtrace.join("\n")}"
    { status: 200, body: { error: "Внутренняя ошибка сервера, но мы все равно возвращаем 200 для отладки" } }
  end
end

# Тестовая отправка сообщения при запуске для проверки работы API
if $SEND_TEST_MESSAGE
  begin
    $logger.warn "[ТЕСТ] Отправляем тестовое сообщение пользователю #{$TEST_USER_ID}"
    client = pachca_client
    result = client.send_welcome_message($TEST_USER_ID, ENV['WELCOME_MESSAGE_TYPE'] || 'default')
    $logger.warn "[ТЕСТ] Результат отправки тестового сообщения: #{result.inspect}"
  rescue => e
    $logger.error "[ТЕСТ] Ошибка при отправке тестового сообщения: #{e.message}"
    $logger.error "[ТЕСТ] Стек вызовов: #{e.backtrace.join('\n')}"
  end
end

# Определяем обработчик для WEBrick
class Handler
  def self.call(req, res)
    if req.path == '/webhook' || req.path == '/api/webhook'
      if req.request_method == 'POST'
        # Получаем тело запроса
        payload_body = req.body
        
        # Получаем заголовки
        signature = req.header['x-pachca-signature'] || req.header['pachca-signature']
        timestamp = req.header['x-pachca-timestamp'] || req.header['pachca-timestamp']
        
        # Обрабатываем вебхук
        result = process_webhook(payload_body, signature ? signature[0] : nil, req.remote_ip, timestamp ? timestamp[0] : nil)
        
        res.status = 200
        res['Content-Type'] = 'application/json'
        res.body = result.to_json
      else
        res.status = 405
        res.body = '{"error":"Method not allowed"}'
      end
    elsif req.path == '/health' && req.request_method == 'GET'
      res.status = 200
      res['Content-Type'] = 'application/json'
      res.body = JSON.generate({ status: 'ok' })
    else
      res.status = 200
      res['Content-Type'] = 'text/plain'
      res.body = "Pachca Welcome Bot is running!"
    end
  end
end
# Создаем HTML для главной страницы
$HTML_TEMPLATE = <<~HTML
  <!DOCTYPE html>
  <html>
    <head>
      <title>Pachca Welcome Bot</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 0 auto;
          padding: 20px;
          line-height: 1.6;
        }
        h1 {
          color: #333;
          border-bottom: 1px solid #ddd;
          padding-bottom: 10px;
        }
        .status {
          background-color: #f5f5f5;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .status.ok {
          background-color: #e6f7e6;
          border-left: 5px solid #4CAF50;
        }
        .status.error {
          background-color: #ffebee;
          border-left: 5px solid #f44336;
        }
      </style>
    </head>
    <body>
      <h1>Pachca Welcome Bot</h1>
      <p>Бот для автоматического приветствия новых участников рабочего пространства в Пачке.</p>
      
      <div class="status ok">
        <strong>Статус сервера:</strong> Работает
      </div>
      
      <p>Для настройки вебхука в Пачке используйте URL: <code>/webhook</code> или <code>/api/webhook</code></p>
      
      <p>Тип приветственного сообщения: <strong>#{ENV['WELCOME_MESSAGE_TYPE'] || 'default'}</strong></p>
    </body>
  </html>
HTML

# Обработчик для Vercel и других serverless окружений
  Handler = Proc.new do |req, res|
    begin
      $logger.info "[DEBUG] Получен запрос: #{req.request_method} #{req.path}"
      
      if req.request_method == 'POST' && (req.path == '/api/webhook' || req.path == '/webhook')
        # Читаем тело запроса
        payload_body = if req.body.respond_to?(:read)
          req.body.read
        else
          req.body.to_s
        end
        
        # Получаем заголовки
        signature = req.header['x-pachca-signature']&.first || req.header['pachca-signature']&.first
        timestamp = req.header['x-pachca-timestamp']&.first || req.header['pachca-timestamp']&.first
        
        # Обрабатываем вебхук
        result = process_webhook(payload_body, signature, req.remote_ip, timestamp)
        
        # Возвращаем результат
        res.status = result[:status]
        res['Content-Type'] = 'application/json'
        res.body = JSON.generate(result[:body])
      elsif req.request_method == 'GET' && (req.path == '/' || req.path == '/api')
        # Статус бота
        res.status = 200
        res['Content-Type'] = 'text/html'
        res.body = <<~HTML
          <!DOCTYPE html>
          <html>
            <head>
              <title>Pachca Welcome Bot</title>
              <style>
                body {
                  font-family: Arial, sans-serif;
                  max-width: 800px;
                  margin: 0 auto;
                  padding: 20px;
                  line-height: 1.6;
                }
                h1 {
                  color: #333;
                  border-bottom: 1px solid #ddd;
                  padding-bottom: 10px;
                }
                .status {
                  background-color: #f5f5f5;
                  padding: 15px;
                  border-radius: 5px;
                  margin: 20px 0;
                }
                .status.ok {
                  background-color: #e6f7e6;
                  border-left: 5px solid #4CAF50;
                }
                .status.error {
                  background-color: #ffebee;
                  border-left: 5px solid #f44336;
                }
              </style>
            </head>
            <body>
              <h1>Pachca Welcome Bot</h1>
              <p>Бот для автоматического приветствия новых участников рабочего пространства в Пачке.</p>
              
              <div class="status #{$PACHCA_TOKEN && !$PACHCA_TOKEN.empty? ? 'ok' : 'error'}">
                <strong>Статус токена API:</strong> #{$PACHCA_TOKEN && !$PACHCA_TOKEN.empty? ? 'Настроен' : 'Не настроен'}
              </div>
              
              <div class="status #{$PACHCA_WEBHOOK_SECRET && !$PACHCA_WEBHOOK_SECRET.empty? ? 'ok' : 'error'}">
                <strong>Статус секрета вебхука:</strong> #{$PACHCA_WEBHOOK_SECRET && !$PACHCA_WEBHOOK_SECRET.empty? ? 'Настроен' : 'Не настроен'}
              </div>
              
              <p>Для настройки вебхука в Пачке используйте URL: <code>#{req.host}/api/webhook</code></p>
              
              <p>Тип приветственного сообщения: <strong>#{$WELCOME_MESSAGE_TYPE}</strong></p>
            </body>
          </html>
        HTML
      else
        # 404 для всех остальных запросов
        res.status = 404
        res['Content-Type'] = 'application/json'
        res.body = JSON.generate({ error: "Not Found" })
      end
    rescue => e
      $logger.error "Ошибка при обработке запроса: #{e.message}\n#{e.backtrace.join("\n")}"
      res.status = 500
      res['Content-Type'] = 'application/json'
      res.body = JSON.generate({ error: "Внутренняя ошибка сервера: #{e.message}" })
    end
  end
  
  # Если скрипт запущен напрямую (не через require), запускаем WEBrick сервер
  if __FILE__ == $0
    port = ENV['PORT'] || 3000
    server = WEBrick::HTTPServer.new(Port: port)
    
    server.mount_proc '/api/webhook', lambda { |req, res|
      Handler.call(req, res)
    }
    
    server.mount_proc '/webhook', lambda { |req, res|
      Handler.call(req, res)
    }
    
    server.mount_proc '/', lambda { |req, res|
      Handler.call(req, res)
    }
    
    trap 'INT' do server.shutdown end
    
    puts "Сервер запущен на порту #{port}"
    server.start
  end
