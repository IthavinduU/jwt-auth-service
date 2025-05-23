require 'sinatra'
require 'json'
require 'jwt'
require 'securerandom'

set :bind, '0.0.0.0'
set :port, 4567

ACCESS_TOKEN_EXP = 60 * 5  # 5 minutes
REFRESH_TOKEN_EXP = 60 * 60 * 24 * 7 # 7 days
SECRET_KEY = 'super_secret_key_123'

# In-memory user DB
USERS = {
  'admin' => 'password123',
  'user1' => 'secret456'
}

# In-memory refresh token store (token => username)
REFRESH_TOKENS = {}

helpers do
  def generate_access_token(username)
    payload = {
      username: username,
      exp: Time.now.to_i + ACCESS_TOKEN_EXP
    }
    JWT.encode(payload, SECRET_KEY, 'HS256')
  end

  def generate_refresh_token
    SecureRandom.hex(64)
  end

  def decode_access_token(token)
    JWT.decode(token, SECRET_KEY, true, algorithm: 'HS256')[0]
  rescue JWT::ExpiredSignature
    :expired
  rescue
    nil
  end
end

post '/login' do
  data = JSON.parse(request.body.read)
  username = data['username']
  password = data['password']

  if USERS[username] == password
    access_token = generate_access_token(username)
    refresh_token = generate_refresh_token
    REFRESH_TOKENS[refresh_token] = { username: username, exp: Time.now + REFRESH_TOKEN_EXP }

    content_type :json
    {
      access_token: access_token,
      refresh_token: refresh_token
    }.to_json
  else
    status 401
    { error: 'Invalid credentials' }.to_json
  end
end

post '/refresh' do
  data = JSON.parse(request.body.read)
  token = data['refresh_token']

  token_data = REFRESH_TOKENS[token]

  if token_data && Time.now < token_data[:exp]
    # Issue new access token
    access_token = generate_access_token(token_data[:username])

    content_type :json
    { access_token: access_token }.to_json
  else
    status 401
    { error: 'Invalid or expired refresh token' }.to_json
  end
end

get '/protected' do
  auth_header = request.env['HTTP_AUTHORIZATION']
  token = auth_header&.split(' ')&.last

  payload = decode_access_token(token)

  case payload
  when nil
    status 401
    return { error: 'Invalid token' }.to_json
  when :expired
    status 401
    return { error: 'Token expired, please refresh' }.to_json
  else
    content_type :json
    { message: "Hello, #{payload['username']}! You are authorized." }.to_json
  end
end

post '/logout' do
  data = JSON.parse(request.body.read)
  refresh_token = data['refresh_token']

  if REFRESH_TOKENS.delete(refresh_token)
    { message: 'Logged out successfully' }.to_json
  else
    status 400
    { error: 'Invalid refresh token' }.to_json
  end
end
