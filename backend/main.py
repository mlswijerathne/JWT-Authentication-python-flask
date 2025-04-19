from flask import Flask, jsonify
from extensions import db, jwt
from auth import auth_bp
from users import user_bp
from models import TokenBlocklist, User

def create_app():
    
    app = Flask(__name__)
    app.config.from_prefixed_env()

    #set JWT to use cookies
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_COOKIE_SECURE"] = True  # For HTTPS only
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True  # Enable CSRF protection
    app.config["JWT_COOKIE_SAMESITE"] = "Strict"  # Prevents CSRF

    #Configure CSRF token settings
    app.config["JWT_CSRF_CHECK_FORM"] = True
    app.config["JWT_CSRF_IN_COOKIES"] = True

    #initialize exts
    db.init_app(app)
    jwt.init_app(app)

    #register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/users')

    #load user
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_headers,_jwt_data):

        identity = _jwt_data["sub"]

        return User.query.filter_by(username = identity).one_or_none()
        

    #additional claims
    @jwt.additional_claims_loader
    def make_additional_claims(identity):
        if identity == "sandaruwan":
            return {"is_staff": True}
        return {"is_staff": False}


    # jwt error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({
            'message': 'Token has expired',
            "error": "token_expired",
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'message': 'Signature verification failded',
            "error": "invalid_token",
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'message': 'Request does not contain an access token',
            "error": "authorization_required",
        }), 401


    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_data):
        jti = jwt_data["jti"]
        
        token = db.session.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).scalar()

        return token is not None


    return app