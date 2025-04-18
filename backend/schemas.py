from marshmallow import Schema, fields, validate

class UserSchema(Schema): 
    id = fields.String()
    username = fields.Str()
    email = fields.Email()
    password = fields.Str()