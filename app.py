from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pyodbc
import random
import os
import json
from werkzeug.utils import secure_filename
import uuid
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, TextAreaField, FileField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import generate_csrf
from flask_cors import CORS
from sqlalchemy import func
import requests
import openai
from dotenv import load_dotenv
import time
import google.generativeai as genai

# Ortam değişkenlerini yükle
load_dotenv()

# Flask uygulamasını oluştur
app = Flask(__name__)
CORS(app)  # CORS desteğini etkinleştir

# CSRF korumasını etkinleştir
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Sadece form gönderimlerinde kontrol et
csrf = CSRFProtect(app)

# CSRF token'ı template'e aktar
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# JWT için gizli anahtar
app.config['JWT_SECRET_KEY'] = 'gizli-jwt-anahtar'
jwt = JWTManager(app)

# JSON parse filter'ı ekle
@app.template_filter('from_json')
def from_json(value):
    return json.loads(value) if value else {}

# SQL Server bağlantı bilgileri
server = 'Yaren\SQLEXPRESS'
database = 'YemekTarifleri'

# Windows Authentication ile bağlantı
app.config['SQLALCHEMY_DATABASE_URI'] = f'mssql+pyodbc://{server}/{database}?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&TrustServerCertificate=yes'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'gizli-anahtar-buraya'

# Dosya yükleme konfigürasyonları
UPLOAD_FOLDER = os.path.join('static', 'recipe_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Veritabanı ve login yöneticisini oluştur
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Kategori modeli
class Category(db.Model):
    __tablename__ = 'Category'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    recipes = db.relationship('Recipe', back_populates='category', lazy=True)

# Kullanıcı modeli
class User(UserMixin, db.Model):
    __tablename__ = 'User'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512))
    profile_image = db.Column(db.String(255))  # Profil fotoğrafı için alan
    appearance = db.Column(db.String(20), default='light')  # Görünüm ayarı (light/dark)
    recipes = db.relationship('Recipe', backref='author', lazy=True)
    favorites = db.relationship('Recipe', secondary='dbo.favorites', backref=db.backref('favorited_by', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'profile_image': self.profile_image,
            'appearance': self.appearance
        }

# Tarif modeli
class Recipe(db.Model):
    __tablename__ = 'Recipe'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    ingredients_sections = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('dbo.User.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('dbo.Category.id'), nullable=False)
    serving_size = db.Column(db.String(50))
    preparation_time = db.Column(db.String(50))
    cooking_time = db.Column(db.String(50))
    tips = db.Column(db.Text)
    image_filename = db.Column(db.String(255))
    username = db.Column(db.String(100), nullable=True)
    category = db.relationship('Category', back_populates='recipes', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'ingredients': self.ingredients,
            'ingredients_sections': json.loads(self.ingredients_sections) if self.ingredients_sections else None,
            'instructions': self.instructions,
            'created_at': self.created_at.isoformat(),
            'views': self.views,
            'user_id': self.user_id,
            'category_id': self.category_id,
            'serving_size': self.serving_size,
            'preparation_time': self.preparation_time,
            'cooking_time': self.cooking_time,
            'tips': self.tips,
            'image_filename': self.image_filename,
            'username': self.username
        }

# Yorum modeli
class Comment(db.Model):
    __tablename__ = 'Comment'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('dbo.User.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('dbo.Recipe.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    recipe = db.relationship('Recipe', backref='comments')

# Favori tarifleri tutmak için ara tablo
favorites = db.Table('favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('dbo.User.id'), primary_key=True),
    db.Column('recipe_id', db.Integer, db.ForeignKey('dbo.Recipe.id'), primary_key=True),
    schema='dbo'
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ana sayfa
@app.route('/')
def index():
    categories = Category.query.all()
    
    # En çok görüntülenen 12 tarifi al
    popular_recipes = Recipe.query.order_by(Recipe.views.desc()).limit(12).all()
    
    return render_template('index.html', 
                         categories=categories, 
                         popular_recipes=popular_recipes)

# Admin kullanıcı oluşturma komutu
@app.cli.command("create-admin")
def create_admin():
    """Admin kullanıcı oluştur"""
    admin = User(
        username="admin",
        email="admin@example.com"
    )
    admin.set_password("admin123")
    db.session.add(admin)
    db.session.commit()
    print("Admin kullanıcı oluşturuldu!")

# Kayıt olma
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = FlaskForm()  # CSRF koruması için boş form
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Bu email adresi zaten kullanılıyor.')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# Giriş yapma
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = FlaskForm()  # CSRF koruması için boş form
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username']
        # password değişkenini al ama kontrol etme
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Şifre kontrolü yapmadan direkt giriş yap
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı')
            
    return render_template('login.html', form=form)

# Çıkış yapma
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Tarif ekleme
@app.route('/add_recipe', methods=['GET', 'POST'])
@login_required
def add_recipe():
    form = RecipeForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        # Malzemeleri JSON formatına dönüştür
        ingredients_list = [line.strip() for line in form.ingredients.data.split('\n') if line.strip()]
        ingredients_sections = json.dumps([{
            'title': 'Malzemeler',
            'ingredients': ingredients_list
        }])
        
        recipe = Recipe(
            title=form.title.data,
            ingredients=form.ingredients.data,
            ingredients_sections=ingredients_sections,  # JSON formatında malzemeler
            instructions=form.instructions.data,
            cooking_time=form.cooking_time.data,
            serving_size=form.serving_size.data,
            category_id=form.category_id.data,
            user_id=current_user.id,
            username=current_user.username
        )
        
        if form.image.data:
            image = form.image.data
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            recipe.image_filename = filename
        
        db.session.add(recipe)
        db.session.commit()
        flash('Tarifiniz başarıyla eklendi!', 'success')
        return redirect(url_for('profile'))
    return render_template('add_recipe.html', form=form)

# Tarif düzenleme
@app.route('/edit_recipe/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    if recipe.user_id != current_user.id:
        abort(403)
    
    form = RecipeForm(obj=recipe)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        recipe.title = form.title.data
        recipe.category_id = form.category_id.data
        recipe.ingredients = form.ingredients.data
        recipe.instructions = form.instructions.data
        recipe.cooking_time = form.cooking_time.data
        recipe.serving_size = form.serving_size.data
        recipe.preparation_time = form.preparation_time.data
        recipe.tips = form.tips.data
        
        if form.image.data:
            image = form.image.data
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            recipe.image_filename = filename
        
        db.session.commit()
        flash('Tarifiniz başarıyla güncellendi!', 'success')
        return redirect(url_for('profile'))
        
    if request.method == 'GET':
        form.category_id.data = recipe.category_id
        form.ingredients.data = recipe.ingredients
        form.tips.data = recipe.tips
    
    return render_template('edit_recipe.html', form=form, recipe=recipe)

# Tarif silme
@app.route('/recipe/<int:id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    
    # Sadece tarifi ekleyen kullanıcı silebilir
    if recipe.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Bu işlem için yetkiniz yok'}), 403
    
    try:
        # Tarif fotoğrafını sil
        if recipe.image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], recipe.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Favorilerden kaldır
        stmt = favorites.delete().where(favorites.c.recipe_id == id)
        db.session.execute(stmt)
        
        # Tarifi sil
        db.session.delete(recipe)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Profil sayfası
@app.route('/profile')
@login_required
def profile():
    user_recipes = Recipe.query.filter_by(user_id=current_user.id).all()
    favorite_recipes = current_user.favorites
    return render_template('profile.html', 
                         user_recipes=user_recipes, 
                         favorite_recipes=favorite_recipes)

# Kategorileri görüntüleme
@app.route('/category/<int:category_id>')
def category_view(category_id):
    # Kategoriyi bul
    category = Category.query.get_or_404(category_id)
    
    # Eğer kategori ID'si 8 (Tümü) ise, tüm tarifleri göster
    if category_id == 8:
        recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    else:
        # Bu kategorideki tarifleri al
        recipes = Recipe.query.filter_by(category_id=category_id).order_by(Recipe.created_at.desc()).all()
    
    # Her tarif için ingredients_preview oluştur
    for recipe in recipes:
        try:
            if recipe.ingredients_sections:
                sections = json.loads(recipe.ingredients_sections)
            else:
                sections = [{'title': 'Malzemeler', 'ingredients': recipe.ingredients.split('\n')}]
            if isinstance(sections, list):
                all_ingredients = []
                for section in sections:
                    if isinstance(section, dict) and 'ingredients' in section:
                        all_ingredients.extend(section['ingredients'])
                    elif isinstance(section, str):
                        all_ingredients.append(section)
                recipe.ingredients_preview = ', '.join(all_ingredients[:3]) + '...' if len(all_ingredients) > 3 else ', '.join(all_ingredients)
            elif isinstance(sections, dict):
                all_ingredients = []
                for section_ingredients in sections.values():
                    if isinstance(section_ingredients, list):
                        all_ingredients.extend(section_ingredients)
                recipe.ingredients_preview = ', '.join(all_ingredients[:3]) + '...' if len(all_ingredients) > 3 else ', '.join(all_ingredients)
        except (json.JSONDecodeError, AttributeError):
            recipe.ingredients_preview = "Malzemeler yükleniyor..."
    
    return render_template('category.html', category=category, recipes=recipes)

# Tarif görüntüleme
@app.route('/recipe/<int:id>')
def recipe(id):
    recipe = Recipe.query.get_or_404(id)
    
    # Referrer URL'i al
    referrer_url = request.referrer
    
    # Eğer referrer recipe sayfasından geliyorsa veya None ise ana sayfaya yönlendir
    if referrer_url:
        if '/recipe/' in referrer_url:
            referrer_url = url_for('index')
    else:
        referrer_url = url_for('index')
    
    # Görüntülenme sayısını artır
    recipe.views += 1
    db.session.commit()
    
    # Tarif sahibinin bilgilerini al
    recipe_user = User.query.get(recipe.user_id)
    
    # Malzemeleri JSON'dan liste formatına çevir
    try:
        ingredients_sections = json.loads(recipe.ingredients_sections) if recipe.ingredients_sections else [{"title": "Malzemeler", "ingredients": recipe.ingredients.split('\n')}]
    except json.JSONDecodeError:
        ingredients_sections = [{"title": "Malzemeler", "ingredients": recipe.ingredients.split('\n')}]
    
    # Puan ortalaması ve toplam puan sayısı
    avg_rating = db.session.query(func.avg(RecipeRating.rating)).filter_by(recipe_id=recipe.id).scalar() or 0
    rating_count = db.session.query(func.count(RecipeRating.id)).filter_by(recipe_id=recipe.id).scalar() or 0
    user_rating = None
    if current_user.is_authenticated:
        user_rating_obj = db.session.query(RecipeRating).filter_by(recipe_id=recipe.id, user_id=current_user.id).first()
        user_rating = user_rating_obj.rating if user_rating_obj else 0
    
    return render_template('recipe.html', 
                         recipe=recipe, 
                         recipe_user=recipe_user, 
                         ingredients_sections=ingredients_sections,
                         referrer_url=referrer_url,
                         avg_rating=round(avg_rating, 1),
                         rating_count=rating_count,
                         user_rating=user_rating)

# Tarif arama
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        # Başlık, malzemeler ve tariflerde arama yap
        recipes = Recipe.query.filter(
            db.or_(
                Recipe.title.ilike(f'%{query}%'),
                Recipe.ingredients.ilike(f'%{query}%'),
                Recipe.instructions.ilike(f'%{query}%')
            )
        ).all()
    else:
        recipes = []
    
    return render_template('search.html', recipes=recipes, query=query)

# Yorum ekleme
@app.route('/recipe/<int:recipe_id>/comment', methods=['POST'])
@login_required
def add_comment(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    content = request.form.get('content')
    
    if content:
        comment = Comment(
            content=content,
            user_id=current_user.id,
            recipe_id=recipe_id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Yorumunuz eklendi!', 'success')
    
    return redirect(url_for('recipe', id=recipe_id))

# Yorum silme
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id and current_user.id != 2:
        flash('Bu yorumu silme yetkiniz yok.', 'error')
        return redirect(url_for('recipe', id=comment.recipe_id))
    db.session.delete(comment)
    db.session.commit()
    flash('Yorum silindi!', 'success')
    return redirect(url_for('recipe', id=comment.recipe_id))

# Favorilere ekleme/çıkarma
@app.route('/recipe/<int:recipe_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    
    if recipe in current_user.favorites:
        current_user.favorites.remove(recipe)
        message = 'Tarif favorilerden çıkarıldı.'
    else:
        current_user.favorites.append(recipe)
        message = 'Tarif favorilere eklendi.'
    
    db.session.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'message': message})
    
    flash(message, 'success')
    return redirect(url_for('recipe', id=recipe_id))

# Rastgele tarif
@app.route('/random')
def random_recipe():
    recipe_count = Recipe.query.count()
    if recipe_count == 0:
        flash('Henüz tarif eklenmemiş.', 'info')
        return redirect(url_for('index'))
    
    random_offset = random.randint(0, recipe_count - 1)
    random_recipe = Recipe.query.offset(random_offset).first()
    return redirect(url_for('recipe', id=random_recipe.id))

# Kullanıcının tüm tarifleri
@app.route('/my-recipes')
@login_required
def user_recipes():
    user_recipes = Recipe.query.filter_by(user_id=current_user.id).order_by(Recipe.created_at.desc()).all()
    return render_template('user_recipes.html', recipes=user_recipes)

# Klasörü oluştur
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/update_recipe/<int:id>', methods=['POST'])
def update_recipe():
    recipe = Recipe.query.get_or_404(id)
    recipe.preparation_steps = json.dumps([
        {
            'step': 1,
            'icon': 'hourglass-start',
            'text': 'Hazırlanış:',
            'type': 'prep'
        },
        {
            'step': 2,
            'icon': 'utensils',
            'text': '1. Çikolata ve tereyağını benmari usulü eritin.',
            'type': 'cooking'
        },
        {
            'step': 3,
            'icon': 'utensils',
            'text': '2. Yumurta ve şekeri iyice çırpın.',
            'type': 'cooking'
        },
        {
            'step': 4,
            'icon': 'utensils',
            'text': '3. Eritilmiş çikolatayı ekleyip karıştırın.',
            'type': 'cooking'
        }
    ])
    db.session.commit()
    flash('Tarif hazırlanışı başarıyla güncellendi!', 'success')
    return redirect(url_for('recipe', id=id))

# RESTful API Endpoints

# API Login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Tüm kategorileri getir
@app.route('/api/categories', methods=['GET'])
@jwt_required()
def get_categories_api():
    categories = Category.query.all()
    return jsonify([{
        'id': cat.id,
        'name': cat.name
    } for cat in categories])

# Tüm tarifleri getir
@app.route('/api/recipes', methods=['GET'])
@jwt_required()
def get_recipes_api():
    recipes = Recipe.query.all()
    return jsonify({
        "success": True,
        "data": [recipe.to_dict() for recipe in recipes]
    })

# Kategoriye göre tarifleri getir
@app.route('/api/recipes/category/<int:category_id>', methods=['GET'])
@jwt_required()
def get_recipes_by_category_api(category_id):
    recipes = Recipe.query.filter_by(category_id=category_id).all()
    return jsonify({
        "success": True,
        "data": [recipe.to_dict() for recipe in recipes]
    })

# Tek bir tarif getir
@app.route('/api/recipes/<int:id>', methods=['GET'])
@jwt_required()
def get_recipe_api(id):
    recipe = Recipe.query.get_or_404(id)
    return jsonify({
        "success": True,
        "data": recipe.to_dict()
    })

# Yeni tarif ekle
@app.route('/api/recipes', methods=['POST'])
@jwt_required()
def create_recipe_api():
    try:
        data = request.get_json()
        recipe = Recipe(
            title=data['title'],
            ingredients=data['ingredients'],
            ingredients_sections=json.dumps(data.get('ingredients_sections', {})),
            instructions=data['instructions'],
            user_id=get_jwt_identity(),
            category_id=data['category_id'],
            serving_size=data.get('serving_size'),
            preparation_time=data.get('preparation_time'),
            cooking_time=data.get('cooking_time'),
            tips=data.get('tips'),
            username=User.query.get(get_jwt_identity()).username
        )
        db.session.add(recipe)
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Tarif başarıyla eklendi",
            "data": recipe.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 400

# Tarif güncelle
@app.route('/api/recipes/<int:id>', methods=['PUT'])
@jwt_required()
def update_recipe_api(id):
    try:
        recipe = Recipe.query.get_or_404(id)
        if recipe.user_id != get_jwt_identity():
            return jsonify({
                "success": False,
                "message": "Bu tarifi güncelleme yetkiniz yok"
            }), 403
        
        data = request.get_json()
        recipe.title = data.get('title', recipe.title)
        recipe.ingredients = data.get('ingredients', recipe.ingredients)
        recipe.ingredients_sections = json.dumps(data.get('ingredients_sections', {}))
        recipe.instructions = data.get('instructions', recipe.instructions)
        recipe.category_id = data.get('category_id', recipe.category_id)
        recipe.serving_size = data.get('serving_size', recipe.serving_size)
        recipe.preparation_time = data.get('preparation_time', recipe.preparation_time)
        recipe.cooking_time = data.get('cooking_time', recipe.cooking_time)
        recipe.tips = data.get('tips', recipe.tips)
        
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Tarif başarıyla güncellendi",
            "data": recipe.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 400

# Tarif sil
@app.route('/api/recipes/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_recipe_api(id):
    try:
        recipe = Recipe.query.get_or_404(id)
        if recipe.user_id != get_jwt_identity():
            return jsonify({
                "success": False,
                "message": "Bu tarifi silme yetkiniz yok"
            }), 403
        
        db.session.delete(recipe)
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Tarif başarıyla silindi"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 400

# Senkronizasyon için model
class SyncLog(db.Model):
    __tablename__ = 'SyncLog'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('dbo.User.id'))
    last_sync = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.String(100))
    sync_type = db.Column(db.String(50))

# Senkronizasyon endpoint'i
@app.route('/api/sync', methods=['POST'])
@jwt_required()
def sync_data():
    data = request.get_json()
    last_sync = datetime.fromisoformat(data.get('last_sync')) if data.get('last_sync') else None
    device_id = data.get('device_id')
    user_id = get_jwt_identity()
    
    # Son senkronizasyondan sonraki değişiklikleri al
    recipes_query = Recipe.query.filter(Recipe.user_id == user_id)
    favorites_query = favorites.select().where(favorites.c.user_id == user_id)
    comments_query = Comment.query.filter(Comment.user_id == user_id)
    
    if last_sync:
        recipes_query = recipes_query.filter(Recipe.created_at > last_sync)
        comments_query = comments_query.filter(Comment.created_at > last_sync)
    
    changes = {
        'recipes': [recipe.to_dict() for recipe in recipes_query.all()],
        'favorites': [{'recipe_id': f.recipe_id} for f in db.session.execute(favorites_query)],
        'comments': [{'id': c.id, 'content': c.content, 'recipe_id': c.recipe_id} 
                    for c in comments_query.all()]
    }
    
    # Yeni senkronizasyon logu oluştur
    sync_log = SyncLog(
        user_id=user_id,
        device_id=device_id,
        sync_type='full'
    )
    db.session.add(sync_log)
    db.session.commit()
    
    return jsonify({
        'changes': changes,
        'sync_time': datetime.utcnow().isoformat()
    })

class RecipeForm(FlaskForm):
    title = StringField('Tarif Başlığı', validators=[DataRequired(), Length(min=3, max=100)])
    category_id = SelectField('Kategori', coerce=int, validators=[DataRequired()])
    ingredients = TextAreaField('Malzemeler', validators=[DataRequired()])
    instructions = TextAreaField('Hazırlanışı', validators=[DataRequired()])
    cooking_time = StringField('Pişirme Süresi', validators=[DataRequired()])
    serving_size = StringField('Kaç Kişilik', validators=[DataRequired()])
    preparation_time = StringField('Hazırlama Süresi')
    tips = TextAreaField('Püf Noktası')
    image = FileField('Tarif Fotoğrafı')
    submit = SubmitField('Tarifi Kaydet')

@app.route('/profile/search')
@login_required
def profile_search():
    query = request.args.get('q', '')
    if query:
        # Kullanıcının kendi tarifleri arasında arama yap
        recipes = Recipe.query.filter(
            Recipe.user_id == current_user.id,
            Recipe.title.ilike(f'%{query}%')
        ).all()
        return jsonify([recipe.to_dict() for recipe in recipes])
    return jsonify([])

# Malzemelere göre tarif önerisi
@app.route('/suggest_recipes', methods=['POST'])
@csrf.exempt
def suggest_recipes():
    data = request.json
    # Seçilen malzemeleri normalize et
    selected_ingredients = set(ingredient.strip().lower() for ingredient in data.get('ingredients', []))
    filters = data.get('filters', {})
    
    # Temel sorgu
    recipes_query = Recipe.query
    
    # Kategori filtresi
    if filters.get('category_id'):
        recipes_query = recipes_query.filter_by(category_id=filters['category_id'])
    
    # Pişirme süresi filtresi
    time_filter = filters.get('max_cooking_time')
    if time_filter:
        all_recipes = recipes_query.all()
        filtered_recipes = []
        for recipe in all_recipes:
            # Süreyi ayıkla (örn: '25 dakika', '1 saat', '45 dk')
            import re
            time_str = recipe.cooking_time.lower() if recipe.cooking_time else ''
            dakika = None
            # 'X saat' veya 'X saat Y dakika' varsa
            saat_match = re.search(r'(\d+)\s*saat', time_str)
            dakika_match = re.search(r'(\d+)\s*dakika', time_str)
            dk_match = re.search(r'(\d+)\s*dk', time_str)
            if saat_match:
                dakika = int(saat_match.group(1)) * 60
                if dakika_match:
                    dakika += int(dakika_match.group(1))
            elif dakika_match:
                dakika = int(dakika_match.group(1))
            elif dk_match:
                dakika = int(dk_match.group(1))
            # Aralığa göre filtrele
            if dakika is not None:
                if time_filter == 'under_30' and dakika < 30:
                    filtered_recipes.append(recipe)
                elif time_filter == '30_60' and 30 <= dakika <= 60:
                    filtered_recipes.append(recipe)
                elif time_filter == 'over_60' and dakika > 60:
                    filtered_recipes.append(recipe)
        recipes_query = filtered_recipes
    else:
        recipes_query = recipes_query.all()
    
    # Porsiyon filtresi
    serving_size_filter = filters.get('serving_size')
    if serving_size_filter:
        porsiyon_araliklari = {
            '1-2': ['1-2', '1', '2'],
            '3-4': ['3-4', '3', '4'],
            '5-6': ['5-6', '5', '6'],
            '6+': ['6', '7', '8', '9', '10', '11', '12']
        }
        aralik = porsiyon_araliklari.get(serving_size_filter, [])
        def porsiyon_uyuyor(mu):
            val = (getattr(mu, 'serving_size', None) or '').lower()
            return any(a in val for a in aralik)
        if isinstance(recipes_query, list):
            recipes_query = [r for r in recipes_query if porsiyon_uyuyor(r)]
        else:
            # SQLAlchemy Query ise eski filtreyi uygula
            if serving_size_filter == '1-2':
                recipes_query = recipes_query.filter(Recipe.serving_size.ilike('%1-2%') | Recipe.serving_size.ilike('%1%') | Recipe.serving_size.ilike('%2%'))
            elif serving_size_filter == '3-4':
                recipes_query = recipes_query.filter(Recipe.serving_size.ilike('%3-4%') | Recipe.serving_size.ilike('%3%') | Recipe.serving_size.ilike('%4%'))
            elif serving_size_filter == '5-6':
                recipes_query = recipes_query.filter(Recipe.serving_size.ilike('%5-6%') | Recipe.serving_size.ilike('%5%') | Recipe.serving_size.ilike('%6%'))
            elif serving_size_filter == '6+':
                recipes_query = recipes_query.filter(Recipe.serving_size.ilike('%6%') | Recipe.serving_size.ilike('%7%') | Recipe.serving_size.ilike('%8%'))
    
    # Tüm tarifleri al ve eşleşme yüzdesini hesapla
    suggestions = []
    for recipe in recipes_query:
        # Tarif malzemelerini normalize et
        recipe_ingredients_text = recipe.ingredients.lower()
        
        # Her seçili malzeme için kontrol et
        matching_ingredients = set()
        for ingredient in selected_ingredients:
            # Yazım hatalarına karşı toleranslı arama
            # Örnek: "domates" girişi "domates salçası", "domates püresi" gibi malzemeleri de bulur
            if any(ingredient in recipe_ing.lower() for recipe_ing in recipe.ingredients.split('\n')):
                matching_ingredients.add(ingredient)
        
        # Eğer seçilen malzemelerden en az biri varsa tarifi öner
        if matching_ingredients:
            # Tüm malzemeleri liste olarak al
            all_recipe_ingredients = [ing.strip() for ing in recipe.ingredients.split('\n') if ing.strip()]
            
            # Eksik malzemeleri hesapla
            required_ingredients = [ing for ing in all_recipe_ingredients 
                                 if not any(selected.lower() in ing.lower() 
                                          for selected in selected_ingredients)]
            
            suggestions.append({
                'recipe': recipe.to_dict(),
                'matching_ingredients': sorted(list(matching_ingredients)),
                'required_ingredients': required_ingredients,
                'match_count': len(matching_ingredients)
            })
    
    # Eşleşen malzeme sayısına göre sırala
    suggestions.sort(key=lambda x: (x['match_count'], x['recipe']['views']), reverse=True)
    
    return jsonify({
        'recipes': suggestions  # Tüm eşleşen tarifleri döndür
    })

# Malzeme kategorisi modeli
class IngredientCategory(db.Model):
    __tablename__ = 'IngredientCategory'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50))  # FontAwesome icon class
    ingredients = db.relationship('Ingredient', backref='category', lazy=True)

# Malzeme modeli
class Ingredient(db.Model):
    __tablename__ = 'Ingredient'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    category_id = db.Column(db.Integer, db.ForeignKey('dbo.IngredientCategory.id'))

# Malzeme kategorilerini getir
@app.route('/ingredient_categories')
def get_ingredient_categories():
    categories = IngredientCategory.query.all()
    return jsonify([{
        'id': cat.id,
        'name': cat.name,
        'icon': cat.icon
    } for cat in categories])

# Malzeme önerileri
@app.route('/suggested_ingredients')
def suggest_ingredients():
    query = request.args.get('q', '').lower()
    category_id = request.args.get('category_id')
    
    if len(query) < 2:
        return jsonify([])
    
    ingredients_query = Ingredient.query.filter(
        Ingredient.name.ilike(f'%{query}%')
    )
    
    if category_id:
        ingredients_query = ingredients_query.filter_by(category_id=category_id)
    
    ingredients = ingredients_query.limit(10).all()
    
    return jsonify([{
        'id': ing.id,
        'name': ing.name,
        'category': {
            'id': ing.category.id,
            'name': ing.category.name,
            'icon': ing.category.icon
        } if ing.category else None
    } for ing in ingredients])

# Kullanıcı görünüm ayarlarını güncelle
@app.route('/api/user/appearance', methods=['PUT'])
@jwt_required()
def update_appearance():
    try:
        user = User.query.get_or_404(get_jwt_identity())
        data = request.get_json()
        
        if 'appearance' not in data:
            return jsonify({
                'success': False,
                'message': 'Görünüm ayarı belirtilmedi'
            }), 400
            
        appearance = data['appearance']
        if appearance not in ['light', 'dark']:
            return jsonify({
                'success': False,
                'message': 'Geçersiz görünüm ayarı. "light" veya "dark" olmalıdır.'
            }), 400
            
        user.appearance = appearance
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Görünüm ayarları güncellendi',
            'data': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400

# Kullanıcı bilgilerini getir
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        user = User.query.get_or_404(get_jwt_identity())
        return jsonify({
            'success': True,
            'data': user.to_dict()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400

@app.route('/favorites')
@login_required
def favorites_view():
    favorite_recipes = current_user.favorites
    return render_template('favorites.html', favorite_recipes=favorite_recipes)

# Yeni eklenen RecipeRating modeli
class RecipeRating(db.Model):
    __tablename__ = 'RecipeRating'
    __table_args__ = {'schema': 'dbo', 'implicit_returning': False}
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('dbo.Recipe.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('dbo.User.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='recipe_ratings')
    recipe = db.relationship('Recipe', backref='recipe_ratings')

@app.route('/recipe/<int:recipe_id>/rate', methods=['POST'])
@login_required
def rate_recipe(recipe_id):
    score = int(request.form.get('score', 0))
    if score < 1 or score > 5:
        flash('Geçersiz puan!', 'error')
        return redirect(url_for('recipe', id=recipe_id))

    rating = RecipeRating.query.filter_by(recipe_id=recipe_id, user_id=current_user.id).first()
    if rating:
        rating.rating = score
        rating.created_at = datetime.utcnow()
    else:
        rating = RecipeRating(recipe_id=recipe_id, user_id=current_user.id, rating=score)
        db.session.add(rating)
    db.session.commit()
    flash('Puanınız kaydedildi!', 'success')
    return redirect(url_for('recipe', id=recipe_id))

GEMINI_API_KEY = "AIzaSyCJGZtsQCQ8zBJ1AHMYD8-wSwrDgiFFLu0"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"

def gemini_generate_content(user_message):
    data = {
        "contents": [
            {"parts": [{"text": user_message}]}
        ]
    }
    response = requests.post(GEMINI_URL, json=data)
    response_json = response.json()
    if "candidates" not in response_json:
        return None, response_json
    gemini_reply = response_json['candidates'][0]['content']['parts'][0]['text']
    return gemini_reply, None

@app.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    if request.method == 'POST':
        user_message = request.form.get('message')
        if user_message:
            try:
                reply, error = gemini_generate_content(user_message)
                if error:
                    return jsonify({'error': error}), 500
                return jsonify({'response': reply})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    return render_template('chatbot.html')

@app.route('/api/alternatif', methods=['POST'])
def alternatif_malzeme():
    data = request.get_json()
    question = data.get('question', '').strip()
    if not question:
        return jsonify({'success': False, 'message': 'Malzeme adı boş olamaz.'}), 400
    try:
        prompt = f"{question} Kısa ve pratik bir şekilde cevapla. Eğer bir malzeme alternatifi soruluyorsa, madde madde öneriler ver."
        reply, error = gemini_generate_content(prompt)
        if error:
            return jsonify({'success': False, 'message': error}), 500
        return jsonify({'success': True, 'answer': reply})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hata: {str(e)}'}), 500

def parse_ai_recipes(ai_text):
    import re
    # '**Tarif' ile başlayanları böl
    cards = re.split(r'\*\*Tarif \d+[:：]', ai_text)
    explanation = cards[0].strip() if cards and cards[0].strip() else None
    recipes = []
    for card in cards[1:]:
        card = card.strip()
        if not card:
            continue
        # Başlık
        if '**İsim:**' in card:
            title = card.split('**İsim:**')[-1].split('\n')[0].strip()
        else:
            title = card.split('\n')[0].strip()
        # Malzemeler
        if '**Malzemeler:**' in card and '**Hazırlanışı:**' in card:
            malzeme_raw = card.split('**Malzemeler:**')[-1].split('**Hazırlanışı:**')[0].strip()
        else:
            malzeme_raw = ''
        # Hazırlanış
        if '**Hazırlanışı:**' in card and '**Porsiyon:**' in card:
            hazirlanis_raw = card.split('**Hazırlanışı:**')[-1].split('**Porsiyon:**')[0].strip()
        elif '**Hazırlanışı:**' in card:
            hazirlanis_raw = card.split('**Hazırlanışı:**')[-1].strip()
        else:
            hazirlanis_raw = ''
        # Porsiyon
        if '**Porsiyon:**' in card and '**Süre:**' in card:
            porsiyon_raw = card.split('**Porsiyon:**')[-1].split('**Süre:**')[0].strip()
        elif '**Porsiyon:**' in card:
            porsiyon_raw = card.split('**Porsiyon:**')[-1].strip()
        else:
            porsiyon_raw = ''
        # Süre
        if '**Süre:**' in card:
            sure_raw = card.split('**Süre:**')[-1].strip()
        else:
            sure_raw = ''
        # Hazırlama Süresi
        if '**Hazırlama Süresi:**' in card:
            prep_raw = card.split('**Hazırlama Süresi:**')[-1].split('\n')[0].strip()
        elif '**Hazırlık:**' in card:
            prep_raw = card.split('**Hazırlık:**')[-1].split('\n')[0].strip()
        else:
            prep_raw = ''
        # Otomatik madde madde ayırma yok, metinler olduğu gibi kaydedilecek
        recipes.append({
            'title': title,
            'ingredients': malzeme_raw,
            'instructions': hazirlanis_raw,
            'serving_size': porsiyon_raw.split('\n')[0],
            'cooking_time': sure_raw.split('\n')[0],
            'preparation_time': prep_raw
        })
    return explanation, recipes

@app.route('/ai_recipe', methods=['GET', 'POST'])
def ai_recipe():
    ai_recipes = None
    ai_explanation = None
    error = None
    if request.method == 'POST':
        ingredients = request.form.get('ingredients', '')
        if not ingredients.strip():
            error = 'Lütfen en az bir malzeme girin.'
        else:
            try:
                prompt = f"Aşağıdaki malzemelerle 10 farklı yaratıcı yemek tarifi öner. Her tarif için: isim, malzemeler, hazırlanışı, porsiyon, hazırlama süresi ve pişirme süresi belirt.\nHer tarife '**Tarif X:' başlığı ile başla.\nMalzemeler: {ingredients}"
                reply, err = gemini_generate_content(prompt)
                if err:
                    error = err
                else:
                    ai_explanation, ai_recipes = parse_ai_recipes(reply)
            except Exception as e:
                error = f'Bir hata oluştu: {str(e)}'
    return render_template('ai_recipe.html', ai_recipes=ai_recipes, ai_explanation=ai_explanation, error=error)

# Yeni eklenen UserRecipeList modeli
class UserRecipeList(db.Model):
    __tablename__ = 'UserRecipeList'
    __table_args__ = {'schema': 'dbo'}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('dbo.User.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('dbo.Recipe.id'), nullable=True)  # AI tarifler için nullable
    status = db.Column(db.String(32), default='pending')
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ai_title = db.Column(db.String(100))
    ai_ingredients = db.Column(db.Text)
    ai_instructions = db.Column(db.Text)
    ai_serving_size = db.Column(db.String(50))
    ai_cooking_time = db.Column(db.String(50))
    ai_preparation_time = db.Column(db.String(50))

    user = db.relationship('User', backref='user_recipe_list')
    recipe = db.relationship('Recipe', backref='user_recipe_list')

@app.route('/add_to_try_list', methods=['POST'])
@login_required
def add_to_try_list():
    data = request.get_json()
    title = data.get('title')
    ingredients = data.get('ingredients')
    instructions = data.get('instructions')
    serving_size = data.get('serving_size')
    cooking_time = data.get('cooking_time')
    preparation_time = data.get('preparation_time')
    if not title or not ingredients or not instructions:
        return jsonify({'success': False, 'message': 'Eksik veri'}), 400
    existing = UserRecipeList.query.filter_by(user_id=current_user.id, status='pending', ai_title=title).first()
    if existing:
        return jsonify({'success': False, 'message': 'Bu tarif zaten listenizde!'}), 409
    new_entry = UserRecipeList(
        user_id=current_user.id,
        recipe_id=None,  # AI tarifleri için None
        status='pending',
        ai_title=title,
        ai_ingredients=ingredients,
        ai_instructions=instructions,
        ai_serving_size=serving_size,
        ai_cooking_time=cooking_time,
        ai_preparation_time=preparation_time
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Tarif listenize eklendi!'})

@app.route('/to-try-recipes')
@login_required
def to_try_recipes():
    try_list = UserRecipeList.query.filter_by(user_id=current_user.id, status='pending').order_by(UserRecipeList.created_at.desc()).all()
    return render_template('to_try_recipes.html', try_list=try_list)

@app.route('/mark_tried_recipe', methods=['POST'])
@login_required
def mark_tried_recipe():
    data = request.get_json()
    try_id = data.get('id')
    entry = UserRecipeList.query.filter_by(id=try_id, user_id=current_user.id, status='pending').first()
    if not entry:
        return jsonify({'success': False, 'message': 'Tarif bulunamadı veya zaten işaretlenmiş.'}), 404
    # Eğer AI tarifi ise Recipe tablosuna ekle
    if entry.ai_title and entry.ai_instructions:
        from sqlalchemy.exc import SQLAlchemyError
        try:
            new_recipe = Recipe(
                title=entry.ai_title,
                ingredients=entry.ai_ingredients or '',
                ingredients_sections=json.dumps([{'title': 'Malzemeler', 'ingredients': [entry.ai_ingredients or '']}]),
                instructions=entry.ai_instructions or '',
                serving_size=entry.ai_serving_size,
                cooking_time=entry.ai_cooking_time,
                preparation_time=entry.ai_preparation_time,
                user_id=current_user.id,
                category_id=9,  # Yapay Zeka Tariflerim
                username=current_user.username
            )
            db.session.add(new_recipe)
            db.session.flush()  # id almak için
            entry.recipe_id = new_recipe.id
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Tarif eklenirken hata: {str(e)}'}), 500
    entry.status = 'tried'
    db.session.commit()
    return jsonify({'success': True, 'message': 'Tarif başarıyla "Denedim ve Beğendim" olarak işaretlendi ve Yapay Zeka Tariflerim kategorisine eklendi!'})

if __name__ == '__main__':
    with app.app_context():
        # Veritabanı tablolarını oluştur
        db.create_all()
        
        # Örnek kategorileri ekle
        if not IngredientCategory.query.first():
            categories = [
                ('Sebzeler', 'fa-carrot'),
                ('Meyveler', 'fa-apple-alt'),
                ('Et & Tavuk', 'fa-drumstick-bite'),
                ('Deniz Ürünleri', 'fa-fish'),
                ('Baharatlar', 'fa-mortar-pestle'),
                ('Baklagiller', 'fa-seedling'),
                ('Süt Ürünleri', 'fa-cheese'),
                ('Yağlar', 'fa-oil-can'),
                ('Tahıllar', 'fa-bread-slice'),
                ('İçecekler', 'fa-glass-water')
            ]
            
            for name, icon in categories:
                category = IngredientCategory(name=name, icon=icon)
                db.session.add(category)
            
            db.session.commit()
            
            # Örnek malzemeleri ekle
            ingredients = {
                'Sebzeler': [
                    'Domates', 'Salatalık', 'Biber', 'Patlıcan', 'Havuç',
                    'Soğan', 'Sarımsak', 'Patates', 'Ispanak', 'Kabak'
                ],
                'Meyveler': [
                    'Elma', 'Armut', 'Muz', 'Portakal', 'Limon',
                    'Çilek', 'Üzüm', 'Karpuz', 'Kavun', 'Şeftali'
                ],
                'Et & Tavuk': [
                    'Kıyma', 'Kuşbaşı', 'Tavuk Göğsü', 'Tavuk But',
                    'Dana Antrikot', 'Kuzu Pirzola', 'Hindi', 'Sucuk'
                ],
                'Deniz Ürünleri': [
                    'Hamsi', 'Levrek', 'Çipura', 'Somon', 'Karides',
                    'Kalamar', 'Midye', 'Ahtapot'
                ],
                'Baharatlar': [
                    'Tuz', 'Karabiber', 'Kırmızı Biber', 'Pul Biber',
                    'Kimyon', 'Nane', 'Kekik', 'Zerdeçal'
                ],
                'Baklagiller': [
                    'Mercimek', 'Nohut', 'Kuru Fasulye', 'Barbunya',
                    'Börülce', 'Bezelye'
                ],
                'Süt Ürünleri': [
                    'Süt', 'Yoğurt', 'Peynir', 'Kaşar', 'Tereyağı',
                    'Krema', 'Ayran', 'Lor'
                ],
                'Yağlar': [
                    'Zeytinyağı', 'Ayçiçek Yağı', 'Mısırözü Yağı',
                    'Margarin', 'Fındık Yağı'
                ],
                'Tahıllar': [
                    'Un', 'Pirinç', 'Bulgur', 'Makarna', 'Erişte',
                    'Yufka', 'Ekmek', 'Galeta Unu'
                ],
                'İçecekler': [
                    'Su', 'Maden Suyu', 'Soda', 'Çay', 'Kahve',
                    'Meyve Suyu', 'Kola'
                ]
            }
            
            for category_name, ingredient_list in ingredients.items():
                category = IngredientCategory.query.filter_by(name=category_name).first()
                if category:
                    for ingredient_name in ingredient_list:
                        if not Ingredient.query.filter_by(name=ingredient_name).first():
                            ingredient = Ingredient(name=ingredient_name, category_id=category.id)
                            db.session.add(ingredient)
            
            db.session.commit()
    
    app.run(debug=True)