# Generated by Django 4.2.18 on 2025-01-29 15:12

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="user",
            old_name="AUTH_STATUS",
            new_name="auth_status",
        ),
        migrations.RenameField(
            model_name="user",
            old_name="AUTH_TYPE",
            new_name="auth_type",
        ),
        migrations.AlterField(
            model_name="user",
            name="photo",
            field=models.ImageField(
                blank=True,
                null=True,
                upload_to="user_photos/",
                validators=[
                    django.core.validators.FileExtensionValidator(
                        allowed_extensions=["jpg", "jpeg", "png", "heic", "heif"]
                    )
                ],
            ),
        ),
        migrations.CreateModel(
            name="UserConfirmation",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                ("created_time", models.DateTimeField(auto_now_add=True)),
                ("updated_time", models.DateTimeField(auto_now=True)),
                ("code", models.CharField(max_length=4)),
                (
                    "verify_type",
                    models.CharField(
                        choices=[
                            ("via_email", "via_email"),
                            ("via_phone", "via_phone"),
                        ],
                        max_length=31,
                    ),
                ),
                ("expiration_time", models.DateTimeField(blank=True, null=True)),
                ("is_confirmed", models.BooleanField(default=False)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="verify_codes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
