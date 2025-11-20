# Proyecto: Explotación y Defensa de APIs Vulnerables – Damn Vulnerable RESTaurant API

## Luis Mindalo, Einer correa, Daniel Padilla, Daniel Pacheco.

#### Universidad Cooperativa de Colombia 

Este proyecto tiene como objetivo analizar, identificar y corregir las vulnerabilidades que se encuentran en una API que está diseñada de manera intencionalmente insegura, basada en el laboratorio Damn Vulnerable RESTaurant. A lo largo de diferentes niveles, se busco detectar fallos comunes en servicios REST y aplicar prácticas seguras de desarrollo, siguiendo las categorías del OWASP API Security Top 10 (2023).

La idea principal es entender cómo surgen vulnerabilidades reales en APIs modernas, como la falta de control de acceso, problemas de autorización, escalamiento de privilegios o solicitudes inseguras al servidor. Además, se muestra, con ejemplos de código corregido, qué medidas se deben tomar para evitar estos problemas en entornos de producción.

## Entorno de ejecución
Este proyecto fue desarrollado y ejecutado dentro de la terminal de windows 11, utilizando Docker para desplegar la API vulnerable Damn Vulnerable RESTaurant y sus servicios asociados.

### Requisitos
- Docker Engine
- Docker Compose
- Python 3
- Burp Suite Community Edition
- Visual Studio Code

## Iniciar el entorno
Ejecutar en la terminal dentro del directorio del proyecto:
```bash
docker-compose build
docker-compose up -d
```
Verificar los contenedores:
```bash
docker ps
```
La API estará disponible en:
```bash
http://localhost:8091
```
Documentación automática de FastAPI:
```bash
http://localhost:8091/docs
```
## Herramientas utilizadas
- Burp Suite: interceptación y explotación de endpoints
- cURL: pruebas rápidas desde la terminal
- VS Code: modificación del código fuente y aplicación de parches
- Git: versionado y repositorio del proyecto

Con estas herramientas se hicieron las pruebas, explotaciones y validación en este repositorio.

## Vulnerabilidades 

## Level 1 – Unrestricted Menu Item Deletion
El endpoint DELETE /menu/{item_id}, al no tener controles de autorización, permitía que cualquier usuario pudiera eliminar elementos del menú sin restricciones. Esto es un claro ejemplo de la vulnerabilidad clasificada como OWASP API5:2023 — Broken Function Level Authorization, que ocurre cuando no se aplican correctamente los controles de acceso en funciones específicas de la API. Esta falla compromete la integridad y disponibilidad de los datos al permitir que usuarios no autorizados realicen acciones sensibles, como borrar elementos críticos del sistema.
<img width="720" height="296" alt="image" src="https://github.com/user-attachments/assets/2af7a090-c3a5-4b44-b3ce-2bc3f5c3ba81" />


### Código antiguo
```python
@router.delete("/menu/{item_id}")
def delete_menu_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    # auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    utils.delete_menu_item(db, item_id)
```
### Explotación
Un usuario que no tenía permisos pudo enviar una solicitud DELETE y borrar elementos porque no había una revisión que verificara si realmente tenía permiso para hacer eso. Esto muestra que no se estaba validando correctamente el rol del usuario, dejando abierta la puerta para que cualquier persona pudiera hacer cosas que no debería en la API, como eliminar ítems del menú.
<img width="1100" height="431" alt="image" src="https://github.com/user-attachments/assets/36831001-8578-4d73-9dda-fee57fd680e1" />

### Código corregido
<img width="720" height="281" alt="image" src="https://github.com/user-attachments/assets/9f4cb060-8d21-4ce9-b39f-42047dbfc018" />

```python
@router.delete("/menu/{item_id}")
def delete_menu_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    utils.delete_menu_item(db, item_id)
```

### Solución y justificación
La solución que se implementó fue activar una verificación de roles usando un componente llamado RolesBasedAuthChecker, que restringe la acción solo a usuarios con los roles de EMPLOYEE y CHEF. Esto ayuda a controlar quién puede eliminar ítems y evita que usuarios sin permisos puedan hacerlo.

La justificación es que así se asegura que solo las personas autorizadas puedan realizar esa acción, protegiendo la integridad de los datos y la seguridad del sistema. Además, al hacer una prueba con un usuario sin privilegios, la API respondió con un código 403 Forbidden, lo que demuestra que la vulnerabilidad quedó corregida y que el control de acceso funciona correctamente.

<img width="720" height="292" alt="image" src="https://github.com/user-attachments/assets/2ff21c57-2182-45d9-9aff-745e3a8ef89a" />


## Level 2 – Unrestricted Profile Update (IDOR)
El endpoint del perfil tenía un problema porque permitía cambiar cualquier cuenta si se enviaba un nombre de usuario (username) cualquiera. Esto se considera una vulnerabilidad llamada Broken Object Level Authorization (BOLA) según OWASP API2:2023, porque no se limitaba la modificación solo al usuario que estaba autenticado. Es decir, cualquiera podía modificar datos de otras personas sin permiso.

### Código antiguo
```python
@router.put("/profile")
def update_profile(user: UserUpdate, current_user, db):
    db_user = get_user_by_username(db, user.username)
    for var, value in user.dict().items():
        if value:
            setattr(db_user, var, value)
    db.commit()
    return db_user
```

### Explotación
Un usuario podía cambiar datos de otra cuenta simplemente modificando el campo username en la petición.
<img width="720" height="296" alt="image" src="https://github.com/user-attachments/assets/ae405d0d-dcd3-4181-864e-3e6350cfcb71" />


### Código corregido
```python
@router.put("/profile")
def update_profile(user_update: UserUpdate, current_user, db):
    db_user = get_user_by_username(db, current_user.username)
    update_data = user_update.dict(exclude_unset=True)
    update_data.pop("username", None)
    for var, value in update_data.items():
        setattr(db_user, var, value)
    db.commit()
    return db_user
```

### Solución y justificación
La actualización ahora se vincula únicamente al usuario que está autenticado y no permite cambiar el nombre de usuario (username), lo que impide modificar perfiles de otras personas y protege los datos para que estos se mantengan seguros.

<img width="720" height="297" alt="image" src="https://github.com/user-attachments/assets/eeff9754-1d25-4d97-8014-0af47b48c43b" />


## Level 3 – Privilege Escalation
Cualquier usuario podía asignarse roles más altos como CHEF o EMPLOYEE porque el endpoint de actualización de roles no tenía controles que validaran si el usuario realmente tenía permiso para hacer eso. Esto es un problema de OWASP API5:2023 — Broken Function Level Authorization, que significa que se permiten realizar acciones administrativas sin tener los privilegios necesarios, dejando la puerta abierta a abusos y riesgos de seguridad.

### Código antiguo
```python
@router.put("/users/update_role")
async def update_user_role(user, current_user, db):
    db_user = update_user(db, user.username, user)
    return current_user
```

### Explotación 
Un usuario CUSTOMER pudo cambiar su rol a CHEF mediante una simple petición PUT, obteniendo permisos elevados.
<img width="720" height="295" alt="image" src="https://github.com/user-attachments/assets/e26c92eb-abb4-4af2-b040-c04d1995e52b" />


### Código corregido
```python
if current_user.role == models.UserRole.CUSTOMER:
    raise HTTPException(403, "Customers cannot change roles")
if user.role == models.UserRole.CHEF.value and current_user.role != models.UserRole.CHEF:
    raise HTTPException(403, "Only Chef can assign Chef role")
if current_user.username == user.username:
    raise HTTPException(403, "Users cannot modify their own role")
```

### Solución y justificación
Se pusieron normas que controlan cómo se asignan los roles, basándose en una jerarquía. Esto evita que alguien pueda darse un rol más alto sin permiso y ayuda a que cada persona tenga solo los privilegios necesarios para hacer su trabajo, siguiendo la idea de usar el mínimo privilegio posible.

Se intentó enviar otra vez la misma petición usando el mismo token de una usuaria llamada Lunnita, pero ahora que se aplicaron las correcciones y se reinició el servicio, el servidor respondió con un código 403 Forbidden (o 401) diciendo que no había autorización. Además, el rol de usuario no cambió en la base de datos, lo que significa que la medida de seguridad funcionó y la acción no autorizada fue bloqueada.

<img width="720" height="295" alt="image" src="https://github.com/user-attachments/assets/9a6a8e70-b79c-472a-8289-49ffe1050aca" />


## Problemas con la autenticación en JWT
La API tenía un problema en la autenticación porque los tokens JWT que usaba se firmaban con un secreto muy débil, como un número de solo 6 dígitos, y además no tenían fecha de expiración. Esto es peligroso porque permite que un atacante pueda falsificar los tokens o usarlos repetidamente para entrar sin permiso, haciendo que la seguridad de la API sea muy vulnerable.

## Código antiguo
```python
from apis.auth.schemas import TokenData
from apis.auth.utils.utils import get_user_by_username
from config import Settings
from db.session import get_db
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from typing_extensions import Annotated

SECRET_KEY = Settings.JWT_SECRET_KEY
ALGORITHM = "HS256"
VERIFY_SIGNATURE = False

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_signature": VERIFY_SIGNATURE},
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

```

### Explotación
<img width="720" height="404" alt="image" src="https://github.com/user-attachments/assets/da370812-4c1c-4e80-b6f2-42957cc29ce9" />
<img width="720" height="451" alt="image" src="https://github.com/user-attachments/assets/8334b4bb-8743-4b03-8ef9-5558776eba88" />


### Código corregido
```python
jwt_auht.py
from apis.auth.schemas import TokenData
from apis.auth.utils.utils import get_user_by_username
from config import Settings
from db.session import get_db
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pathlib import Path
from sqlalchemy.orm import Session
from typing_extensions import Annotated

ALGORITHM = "RS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

KEY_DIR = Path(file_).resolve().parent
PRIVATE_KEY = (_KEY_DIR / "private.pem").read_bytes()
PUBLIC_KEY = (_KEY_DIR / "public.pem").read_bytes()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,  
            algorithms=[ALGORITHM],
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception

    return user


utils.py
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Union

from apis.auth.exceptions import UserAlreadyExistsException
from config import Settings
from db.models import User, UserRole
from jose import jwt
from passlib.context import CryptContext


SECRET_KEY = Settings.JWT_SECRET_KEY
ALGORITHM = "RS256"

KEY_DIR = Path(file_).resolve().parent
PRIVATE_KEY = (_KEY_DIR / "private.pem").read_bytes()
PUBLIC_KEY = (_KEY_DIR / "public.pem").read_bytes()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



ISS = "mi-ucc"
AUD = "ucc-client"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_by_username(db, username: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    return user


def get_user_by_id(db, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    return user


def update_user_password(db, username: str, password: str) -> User:
    db_user = get_user_by_username(db, username)
    db_user.password = get_password_hash(password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


def get_user_by_phone_number(db, phone_number: str) -> User:
    user = db.query(User).filter(User.phone_number == phone_number).first()
    return user


def authenticate_user(db, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_user(
    db,
    username: str,
    password: str,
    first_name: str,
    last_name: str,
    phone_number: str,
    role: str = UserRole.CUSTOMER,
):
    if get_user_by_phone_number(db, phone_number) or get_user_by_username(db, username):
        raise UserAlreadyExistsException()

    hashed_password = get_password_hash(password)
    db_user = User(
        username=username,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        phone_number=phone_number,
        role=role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


def create_user_if_not_exists(
    db,
    username: str,
    password: str,
    first_name: str,
    last_name: str,
    phone_number: str,
    role: str = UserRole.CUSTOMER,
):
    try:
        return create_user(
            db, username, password, first_name, last_name, phone_number, role
        )
    except UserAlreadyExistsException:
        return None


def update_user(db, username: str, user):
    db_user = get_user_by_username(db, username)

    for var, value in vars(user).items():
        if value:
            setattr(db_user, var, value)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now, "iss": ISS, "aud": AUD})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def send_code_to_phone_number(phone_number: str, code: str):
    # normally this would send a code to the phone number using
    # a third party service
    print(f"Sending code {code} to phone number {phone_number}")
    return True
```
### Solución 
<img width="720" height="404" alt="image" src="https://github.com/user-attachments/assets/09209943-83cb-452e-b184-a548f9cf9b2d" />

<img width="720" height="448" alt="image" src="https://github.com/user-attachments/assets/9a5cfddd-527c-4dc5-92c8-440d24c733da" />


