"""A ciphertext-only storage field, excluded from Django serialization/forms."""
from django.core.exceptions import ValidationError
from django.db import models
from django.views.decorators.debug import sensitive_variables

from .services.credentials import CredentialError, validate_encrypted_password


class EncryptedPasswordField(models.TextField):
    def __init__(self, *args, **kwargs):
        kwargs["editable"] = False
        kwargs["serialize"] = False
        super().__init__(*args, **kwargs)

    @sensitive_variables()
    def validate(self, value, model_instance):
        # Do not use validators that interpolate the supplied credential value.
        try:
            validate_encrypted_password(value)
        except CredentialError:
            raise ValidationError("A valid encrypted device password is required.") from None

    @sensitive_variables()
    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        # Also protect QuerySet.update() and bulk_create(), which bypass save().
        try:
            validate_encrypted_password(value)
        except CredentialError:
            raise ValidationError("A valid encrypted device password is required.") from None
        return value

    def value_to_string(self, obj):
        return ""
