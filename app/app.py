from flask import Flask
from flask_cors import CORS
from app.config import Config
from app.extensions.firebase import init_firebase
from app.routes.vault_routes import vault_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Extensions
    CORS(app) # Enable CORS for all routes
    init_firebase(app)

    # Register Blueprints
    app.register_blueprint(vault_bp, url_prefix='/api/vault')

    @app.route('/api/health')
    def health_check():
        return {'status': 'healthy'}, 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000)
