# JWT Auth Microservice (Ruby + Sinatra)

This is a simple JWT authentication microservice built with Ruby and Sinatra.

## Features

- User login with username & password  
- JWT token generation  
- Protected routes requiring JWT authentication  

## Setup

1. Install Ruby (version 3.x recommended)  
2. Clone this repo  
3. Run `bundle install` to install dependencies  
4. Start the server with `bundle exec ruby app.rb`  

## API Endpoints

- `POST /login`  
  Request JSON: `{ "username": "admin", "password": "password123" }`  
  Returns JWT token on success.

- `GET /protected`  
  Requires header `Authorization: Bearer <token>`  

## Testing

Use curl or Postman to test endpoints.

---

## License

MIT
