from flask import Blueprint, jsonify, request
from models import TokenBlocklist, User
from extensions import db
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, get_jwt_identity, jwt_required, current_user


auth_bp = Blueprint("auth", __name__)


# Register a new user
@auth_bp.post('/register')
def register_user():

    data = request.get_json()

    user = User.get_user_by_username(username = data.get('username'))
    # Check if user already exists
    if user is not None: 
        return jsonify({"message": "User already exists!"}), 403
    
    new_user = User(
        username=data.get('username'),
        email=data.get('email')
    )

    new_user.set_password(password = data.get('password'))

    new_user.save()
    
    return jsonify({"message": "User created successfully!"}), 201




# Login a user
@auth_bp.post('/login')
def login_user():

    data = request.get_json()

    user = User.get_user_by_username(username = data.get('username'))
    
    if user and (user.check_password(password = data.get('password'))):

        access_token = create_access_token(identity=user.username)
        refresh_token = create_refresh_token(identity=user.username)

        #Create response object
        response = jsonify(
            {
                "message": "Login successful!"
            }
        )

        #set cookies with HTTP-only flag
        response.set_cookie(
            'access_token_cookie',
            value=access_token,
            httponly=True,
            secure=True, # For https only
            samesite='Strict', # help prevent CSRF attacks
            max_age=60*15 # 15 minutes
        )

        response.set_cookie(
            'refresh_token_cookie',
            value=refresh_token,
            httponly=True,
            secure=True, # For https only
            samesite='Strict', # help prevent CSRF attacks
            max_age=60*60*24*30 # 30 days
        )

        return response, 200
    
    return jsonify({"message": "Invalid username or password!"}), 401
        
        


@auth_bp.get('/whoami')
@jwt_required()
def whoami():
    return jsonify({
        "message": "You are logged in!",
        "user_details": {"username": current_user.username, "email": current_user.email}
    }), 200




@auth_bp.get('/refresh')
@jwt_required(refresh = True)
def refresh_access():
    identity = get_jwt_identity()

    new_access_token = create_access_token(identity = identity)

     # Get JTI of current refresh token to rotate it
    jwt_data = get_jwt()
    jti = jwt_data["jti"]

   #block the old refresh token(token rotation to prevent replay attacks)
    token_b = TokenBlocklist(jti = jti)
    token_b.save()

    #create new refresh token
    new_refresh_token = create_refresh_token(identity = identity)

    # Create response 
    response = jsonify(
          {
                "message": "Token refreshed successfully!"
          }
     )

   
    # Set new access token in cookie
    response.set_cookie(
        'access_token_cookie',
        value=new_access_token,
        httponly=True,
        secure=True, # For https only
        samesite='Strict', # help prevent CSRF attacks
        max_age=60*15 # 15 minutes
    )

    # Set new refresh token in cookie
    response.set_cookie(
        'refresh_token_cookie',
        value=new_refresh_token,
        httponly=True,
        secure=True, # For https only
        samesite='Strict', # help prevent CSRF attacks
        max_age=60*60*24*30 # 30 days
    )

    return response, 200



# Logout a user
@auth_bp.get('/logout')
@jwt_required(verify_type=False)
def logout_user():
    jwt = get_jwt()
    jti = jwt["jti"]
    token_type = jwt["type"]
    

    #add token to blocklist
    token_b = TokenBlocklist(jti = jti)
    token_b.save()

    
    # Create response
    response = jsonify({
        "message": f"{token_type} token revoked successfully!",
    })

    # Clear cookies
    response.set_cookie(
        'access_token_cookie',
        value='',
        httponly=True,
        secure=True, # For https only
        samesite='Strict', # help prevent CSRF attacks
        expires=0
    )
    response.set_cookie(
        'refresh_token_cookie',
        value='',
        httponly=True,
        secure=True, # For https only
        samesite='Strict', # help prevent CSRF attacks
        expires=0
    )

    return response, 200

    
