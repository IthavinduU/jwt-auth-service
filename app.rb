require 'sinatra'
require 'json'
require 'jwt'

set :bind, '0.0.0.0'
set :port, 4567

SECRET_KEY = 'super_secret_key_123'

# In-memory user database
USERS = {
  'admin' => 'password123',
  'user1' => 'secret456'
}

helpers do
  def generate_token(username)
    payload = {
      username: username,
      exp: Time.now.to_i + 60 * 60 # 1 hour expiry
    }
    JWT.encode(payload, SECRET_KEY, 'HS256')
  end

  def decode_token(token)
    JWT.decode(token, SECRET_KEY, true, algorithm: 'HS256')[0]
  rescue
    nil
  end
end

post '/login' do
  data = JSON.parse(request.body.read)
  username = data['username']
  password = data['password']

  if USERS[username] == password
    token = generate_token(username)
    { token: token }.to_json
  else
    status 401
    { error: 'Invalid credentials' }.to_json
  end
end

get '/protected' do
  auth_header = request.env['HTTP_AUTHORIZATION']
  token = auth_header&.split(' ')&.last

  payload = decode_token(token)
  if payload
    { message: "Hello, #{payload['username']}! You are authorized." }.to_json
  else
    status 401
    { error: 'Invalid or expired token' }.to_json
  end
end
