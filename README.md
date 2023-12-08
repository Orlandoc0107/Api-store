# Api-store

Actualizaciones:
se agrego un endpoint para ver los datos personales 
con Autorizacion jwt


API REST store full flask, SQLalchemy, pyjwt

## Instalación

1. Clona este repositorio:

   ```bash
   git clone https://github.com/Orlandoc0107/Api-store.git
   cd Api-store
   ```

python -m venv .venv

. .venv/bin/activate

source venv/bin/activate  # Linux/Mac
# o
.\venv\Scripts\activate  # Windows

pip install -r requirements.txt

en caso de modificacion.
para actualizacion los requirements:
pip freeze > requirements.txt

export SECRET_KEY='tu_clave_secreta'
export DATABASE_URL='tu_cadena_de_conexion_bd'


python run.py


Algunos Endpoints

    /register: Registra un nuevo usuario.
    /login: Inicia sesión y obtiene un token JWT.
    /user: Obtiene información del usuario actual.
    /products: Obtiene la lista de productos.
    /product/<product_id>: Obtiene detalles de un producto específico.
    /add_to_cart: Agrega un producto al carrito.
    /remove_from_cart: Elimina un producto del carrito.
    /finalize_purchase: Finaliza la compra y actualiza el stock.
    /remove_cart: Elimina un producto del carrito y lo devuelve al stock.
    /view_cart: Obtiene detalles del carrito de compras.

Tecnologías Utilizadas

    Flask: Framework web ligero para Python.
    Flask-RESTx: Extensión de Flask para la creación de API RESTful.
    SQLAlchemy: Biblioteca de ORM para interactuar con bases de datos.

Contribuciones

¡Contribuciones son bienvenidas! Si encuentras algún problema o tienes mejoras, por favor abre un problema o envía una solicitud de extracción.


