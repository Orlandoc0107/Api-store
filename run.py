from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields, abort, reqparse
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
import os

app = Flask(__name__)
base_dir = os.path.abspath(os.path.dirname(__file__))
SECRET_KEY = 'a9f4f7d967d9a80deb795d58161216270692b50c1d1710c48d11011a123dc458'
key = SECRET_KEY
TEMPLATE_FOLDER = 'app/templates'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'store.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if 'SECRET_KEY' not in app.config:
    app.config['SECRET_KEY'] = 'tu_valor_por_defecto'

api = Api(app, version='1.0', title='APIREST store')
#

admin = api.namespace('admin', description='End Ponit Admin')
products_namespace = api.namespace('products', description='Operaciones relacionadas con productos')
user = api.namespace('user', description='Operaciones de edición de usuario')

#
db = SQLAlchemy(app)

todos = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    age = db.Column(db.Integer)
    dni = db.Column(db.Integer)
    address = db.Column(db.String(128))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    purchase_count = db.Column(db.Integer, default=0)
    cart = db.relationship('ShoppingCart', backref='user', lazy=True)


    def view_cart(self):
        return self.cart.view_cart()
    
#jwt

def generate_token(user_data):
    payload = {
        'id': user_data.get('id'),
        'username': user_data.get('username'),
        'email': user_data.get('email'),
        'is_admin': user_data.get('is_admin')
    }
    jwt_token = jwt.encode(payload, key, algorithm='HS256')
    
    return jwt_token

#buscar si existe el usuario
def existing_user(username):
    resp = User.query.filter_by(username=username).first()
    return resp

#validar password y username
def validate_login(username, password):
    
    user = User.query.filter_by(username=username).first()
    if user:
        id = user.id
        username = username
        password_hash = user.password_hash
        email = user.email
        is_admin = user.is_admin
        
        validar = check_password_hash(password_hash, password)
        
        if validar is True:
            
            token = generate_token ({'id':id, 'username':username, 'email':email, 'is_admin':is_admin })
            return {'token': token}
        else:
            return jsonify({'success': False, 'message': 'Error, contraseña incorrecta'}), 401
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    code = db.Column(db.Integer, nullable=True)  
    is_available = db.Column(db.Boolean, default=False) #disponible
    quantity = db.Column(db.Integer, nullable=True) #cantidad
    on_sale = db.Column(db.Boolean, default=False) #En_venta
    brand = db.Column(db.String(50), nullable=True)  #marca
    model = db.Column(db.String(50), nullable=True)  
    origin = db.Column(db.String(50), nullable=True)  
    description = db.Column(db.Text, nullable=True)  


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shopping_cart_id = db.Column(db.Integer, db.ForeignKey('shopping_cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    

class ShoppingCart(db.Model): #carro de Compra
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('CartItem', backref='shopping_cart', lazy=True)
#agregar productos
    def add_item(self, product, quantity=1):
        cart_item = CartItem(product=product, quantity=quantity)
        self.items.append(cart_item)
#remover productos
    def remove_item(self, product):
        cart_item = CartItem.query.filter_by(shopping_cart_id=self.id, product_id=product.id).first()
        if cart_item:
            db.session.delete(cart_item)
            db.session.commit()
    def view_cart(self):
        cart_info = ""
        for item in self.items:
            cart_info += f"{item.product.name} - Cantidad: {item.quantity}, Precio: ${item.product.price}\n"
        return cart_info

#rutas
@admin.route('/register')
class Register(Resource):
    def put(self):
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        #
        is_admin = True
        resp = existing_user(username)
        
        if resp is None:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            #token
            return {'message': 'Registro completado'}
        else:
            return {'message': 'El Usuario Ya existe'}
        
        
@user.route('/register')
class Register(Resource):
    def put(self):
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        #
        is_admin = False
        resp = existing_user(username)
        
        if resp is None:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            #token
            return {'message': 'Registro completado'}
        else:
            return {'message': 'El Usuario Ya existe'}
                

#Login Admin
@admin.route('/login')
class Login(Resource):
    def put(self):
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        
        login = validate_login(username , password)
        
        if login:
            print(login)
            return jsonify(login)
        else:
            return jsonify({'messeger':'Datos No Validos'})

@admin.route('/edit')
@user.route('/edit')
class Edit(Resource):
    @api.doc(security='apikey')
    def put(self):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            print('Token de autorización no proporcionado')
            return jsonify({'message': 'Token de autorización no proporcionado'}), 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            print('Formato de token inválido')
            return jsonify({'message': 'Formato de token inválido'}), 401

        token = token_parts[1]
        print('Token:', token)

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            user_id = payload.get('id')
            username = payload.get('username')
            email = payload.get('email')

            print('User ID:', user_id)
            print('Username:', username)
            print('Email:', email)

            user = User.query.filter_by(id=user_id).first()

            if user:
                request_data = request.get_json()

                print('Datos de la solicitud:', request_data)

                if 'username' in request_data:
                    user.username = request_data['username']
                if 'firstname' in request_data:
                    user.firstname = request_data['firstname']
                if 'lastname' in request_data:
                    user.lastname = request_data['lastname']
                if 'age' in request_data:
                    user.age = request_data['age']

                db.session.commit()

                print('Datos actualizados exitosamente')
                return jsonify({'message': 'Datos actualizados exitosamente'})

            else:
                print('Datos no válidos')
                return jsonify({'message': 'Datos no válidos'}), 401

        except jwt.ExpiredSignatureError:
            print('Token expirado, inicie sesión nuevamente')
            return jsonify({'message': 'Token expirado, inicie sesión nuevamente'}), 401
        except jwt.InvalidTokenError:
            print('Token inválido')
            return jsonify({'message': 'Token inválido'}), 401


@admin.route('/products')
@user.route('/products')
class ProductList(Resource):
    def get(self):
        # Ordenar productos por id antes de obtenerlos
        products = Product.query.order_by(Product.id).all()

        # Convertir objetos SQLAlchemy a un formato serializable
        products_list = [
            {
                'id': product.id,
                'name': product.name,
                'price': product.price,
                'code': product.code,
                'is_available': product.is_available,
                'quantity': product.quantity,
                'on_sale': product.on_sale,
                'brand': product.brand,
                'model': product.model,
                'origin': product.origin,
                'description': product.description
            }
            for product in products
        ]

        return jsonify(products_list)
    
###
@admin.route('/add_product')
class AddProduct(Resource):
    @api.doc(security='apikey')
    def post(self):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            print('Token de autorización no proporcionado')
            return jsonify({'message': 'Token de autorización no proporcionado'}), 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            print('Formato de token inválido')
            return jsonify({'message': 'Formato de token inválido'}), 401

        token = token_parts[1]
        print('Token:', token)

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            is_admin = payload.get('is_admin')
            id = payload.get('id')
            print('Admin:', is_admin)
            print(id)
            if is_admin == True:
                
                request_data = request.get_json()

                print('Datos del producto:', request_data)

                # Crear un nuevo producto y guardarlo en la base de datos
                new_product = Product(
                    name=request_data.get('name'),
                    price=request_data.get('price'),
                    code=request_data.get('code'),
                    is_available=request_data.get('is_available', False),
                    quantity=request_data.get('quantity'),
                    on_sale=request_data.get('on_sale', False),
                    brand=request_data.get('brand'),
                    model=request_data.get('model'),
                    origin=request_data.get('origin'),
                    description=request_data.get('description')
                )

                db.session.add(new_product)
                db.session.commit()

                print('Producto agregado exitosamente')
                return jsonify({'message': 'Producto agregado exitosamente'})

            else:
                print('Usuario no autorizado para agregar productos')
                return jsonify({'message': 'Usuario no autorizado para agregar productos'}), 403

        except jwt.ExpiredSignatureError:
            print('Token expirado, inicie sesión nuevamente')
            return jsonify({'message': 'Token expirado, inicie sesión nuevamente'}), 401
        except jwt.InvalidTokenError:
            print('Token inválido')
            return jsonify({'message': 'Token inválido'}), 401
        

####

@admin.route('/edit_product')
class EditProduct(Resource):
    @api.doc(security='apikey')
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, location='headers', required=True, help='Token de autorización (Bearer Token)')
        parser.add_argument('product_id', type=int, required=True, help='ID del producto a editar')
        parser.add_argument('name', type=str)
        parser.add_argument('price', type=float)
        parser.add_argument('code', type=int)
        parser.add_argument('is_available', type=bool)
        parser.add_argument('quantity', type=int)
        parser.add_argument('on_sale', type=bool)
        parser.add_argument('brand', type=str)
        parser.add_argument('model', type=str)
        parser.add_argument('origin', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()

        auth_header = args['Authorization']

        if not auth_header:
            return jsonify({'message': 'Token de autorización no proporcionado'}), 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            return jsonify({'message': 'Formato de token inválido'}), 401

        token = token_parts[1]

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            is_admin = payload.get('is_admin')

            if is_admin:
                product_id = args.get('product_id')
                product = Product.query.get(product_id)

                if not product:
                    return jsonify({'message': 'Producto no encontrado'}), 404

                # Actualizar solo los campos proporcionados
                if args.get('name') is not None:
                    product.name = args['name']
                if args.get('price') is not None:
                    product.price = args['price']
                if args.get('code') is not None:
                    product.code = args['code']
                if args.get('is_available') is not None:
                    product.is_available = args['is_available']
                if args.get('quantity') is not None:
                    product.quantity = args['quantity']
                if args.get('on_sale') is not None:
                    product.on_sale = args['on_sale']
                if args.get('brand') is not None:
                    product.brand = args['brand']
                if args.get('model') is not None:
                    product.model = args['model']
                if args.get('origin') is not None:
                    product.origin = args['origin']
                if args.get('description') is not None:
                    product.description = args['description']

                db.session.commit()

                # Convertir manualmente el objeto de SQLAlchemy a un diccionario
                updated_product = {
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'code': product.code,
                    'is_available': product.is_available,
                    'quantity': product.quantity,
                    'on_sale': product.on_sale,
                    'brand': product.brand,
                    'model': product.model,
                    'origin': product.origin,
                    'description': product.description
                }

                return jsonify({'message': 'Producto actualizado exitosamente', 'product': updated_product})

            else:
                return jsonify({'message': 'Usuario no autorizado para editar productos'}), 403

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado, inicie sesión nuevamente'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401

####

@admin.route('/delete_product')
class DeleteProduct(Resource):
    @api.doc(security='apikey')
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, location='headers', required=True, help='Token de autorización (Bearer Token)')
        parser.add_argument('product_id', type=int, required=True, help='ID del producto a eliminar')
        args = parser.parse_args()

        auth_header = args['Authorization']

        if not auth_header:
            return {'message': 'Token de autorización no proporcionado'}, 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            return {'message': 'Formato de token inválido'}, 401

        token = token_parts[1]

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            is_admin = payload.get('is_admin')

            if is_admin == True:
                product_id = args.get('product_id')
                product = Product.query.get(product_id)

                if not product:
                    return {'message': 'Producto no encontrado'}, 404

                db.session.delete(product)
                db.session.commit()

                return {'message': 'Producto eliminado exitosamente'}

            else:
                return {'message': 'Usuario no autorizado para eliminar productos'}, 403

        except jwt.ExpiredSignatureError:
            return {'message': 'Token expirado, inicie sesión nuevamente'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Token inválido'}, 401

####

@user.route('/add_to_cart')
class DeleteProduct(Resource):
    @api.doc(security='apikey')
    def post(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, location='headers', required=True, help='Token de autorización (Bearer Token)')
        parser.add_argument('product_id', type=int, required=True, help='ID del producto a eliminar')
        args = parser.parse_args()

        auth_header = args['Authorization']

        if not auth_header:
            return {'message': 'Token de autorización no proporcionado'}, 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            return {'message': 'Formato de token inválido'}, 401

        token = token_parts[1]

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            is_admin = payload.get('is_admin')
            user_id = payload.get('user_id')
            
            if not is_admin:  # Cambiado para verificar que no es un administrador
                
                data = request.get_json()
                
                product_id = data.get('product_id')
                quantity = data.get('quantity', 1)

                product = Product.query.get(product_id)

                if not product:
                    return {'message': 'Producto no encontrado'}, 404

                if product.quantity < quantity:
                    return {'message': 'Cantidad insuficiente en stock'}, 400
                
                shopping_cart = ShoppingCart.query.filter_by(user_id=user_id).first()  # Usando user_id

                if not shopping_cart:
                    shopping_cart = ShoppingCart(user_id=user_id)  # Usando user_id
                    
                    db.session.add(shopping_cart)
                    
                shopping_cart.add_item(product, quantity)
                
                product.quantity -= quantity
                
                user = User.query.get(user_id)
                user.points += 1
                
                db.session.commit()
                
                return {'message': 'Producto agregado al carrito exitosamente', 'cart': shopping_cart.view_cart(), 'total': shopping_cart.calculate_total()}

                
        except jwt.ExpiredSignatureError:
            return {'message': 'Token expirado, inicie sesión nuevamente'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Token inválido'}, 401

###


@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, location='headers', required=True, help='Token de autorización (Bearer Token)')
        parser.add_argument('product_id', type=int, required=True, help='ID del producto a eliminar')
        args = parser.parse_args()

        auth_header = args['Authorization']

        if not auth_header:
            return {'message': 'Token de autorización no proporcionado'}, 401

        token_parts = auth_header.split()
        if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
            return {'message': 'Formato de token inválido'}, 401

        token = token_parts[1]

        try:
            payload = jwt.decode(token, key, algorithms='HS256')

            is_admin = payload.get('is_admin')
            user_id = payload.get('user_id')
            
            if not is_admin:  # Cambiado para verificar que no es un administrador
                
                data = request.get_json()

                product_id = data.get('product_id')
                quantity = data.get('quantity', 1) 

                product = Product.query.get(product_id)

                if not product:
                    return {'message': 'Producto no encontrado'}, 404


                shopping_cart = ShoppingCart.query.filter_by(user_id=user_id).first()

                if not shopping_cart:
                    return {'message': 'Carrito no encontrado'}, 404


                shopping_cart.remove_item(product)

                product.quantity += quantity

                db.session.commit()

                return {'message': 'Producto eliminado del carrito exitosamente', 'cart': shopping_cart.view_cart(), 'total': shopping_cart.calculate_total()}
        except:
            return {'message':'Error'}
####
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=0)