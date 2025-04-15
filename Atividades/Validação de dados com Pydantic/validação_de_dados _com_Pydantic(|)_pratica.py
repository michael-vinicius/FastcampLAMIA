import enum
import hashlib
import re
from typing import Any
from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator, model_validator, ValidationError

#Expressões regulares para validação de nome e senha
VALID_NAME_REGEX = re.compile(r"^[a-zA-Z]{2,}$")
VALID_PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")

#Enum para representar os papéis do usuário
class Role(enum.IntFlag):
    USER = 1
    ADMIN = 2
    SUPERADMIN = 4

#Modelo de usuário utilizando pydantic
class User(BaseModel):
    name: str = Field(..., example="Michael", description="Nome do usuário")
    email: EmailStr = Field(..., example="michael@example.com", description="E-mail do usuário")
    password: SecretStr = Field(..., example="Password123", description="Senha do usuário")
    role: Role = Field(default=Role.USER, description="Papel do usuário", example=Role.USER)

    #Validação do campo "name"
    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not VALID_NAME_REGEX.match(value):
            raise ValueError("Nome deve conter apenas letras e ter no mínimo 2 caracteres.")
        return value

    # Validação e transformação dos campos antes de criar o modelo
    @model_validator(mode="before")
    @classmethod
    def validate_password_and_fields(cls, values: dict[str, Any]) -> dict[str, Any]:
        if "name" not in values or "password" not in values:
            raise ValueError("Os campos 'name e 'password' são obrigatorios.")
        password = values["password"]
        name = values["name"]
        if name.lower() in password.lower():
            raise ValueError("A senha não pode conter o nome do usuario.")
        if not VALID_PASSWORD_REGEX.match(password):
            raise ValueError(
                "Senha inválida: use pelo menos 8 caracteres, 1 maiúscula, 1 minúscula e 1 número."
            )
        values["password"] = hashlib.sha256(password.encode()).hexdigest()
        return values

# Função de teste para validação e serialização do modelo
def main() -> None:
    valid_user_data = {
    "name": "Michael",
    "email": "michael@example.com",
    "password": "Password123",
    "role": 1 
    }
    
    # Dados válidos para o usuário "Michael"
    # valid_user_data = {
    #     "name": "Michael",
    #     "email": "michael@example.com",
    #     "password": "Password123",
    #     "role": "USER"  
    # }
    

    
    try:
        user = User.model_validate(valid_user_data)
        print("Sucesso, usuario validado!")
        print("Dados serializados:", user.model_dump())
    except ValidationError as e:
        print("Deu ruim, corrija os dados do usuario:", e)

    # Dados com erros para demonstrar a abordagem 'fail fast'
    invalid_user_data = {
        "name": "M1chael",         
        "email": "invalid-email",
        "password": "michael123456789",
    }

    try:
        User.model_validate(invalid_user_data)
    except ValidationError as e:
        print("\n Falha na validação com dados incorretos:")
        for error in e.errors():
            print(error)

if __name__ == "__main__":
    main()

# utilizei o exemplo 3 pra reproduzir o teste, já que foi o que mais me chamou atenção na aplicação de pydantic.