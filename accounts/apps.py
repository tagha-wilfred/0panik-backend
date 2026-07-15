from django.apps import AppConfig


# class AccountsConfig(AppConfig):
#     default_auto_field = "django.db.models.BigAutoField"
#     name = "accounts"

# from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        try:
            from accounts.models import User

            if not User.objects.filter(
                    email="taghawilfred@gmail.com").exists():

                User.objects.create_superuser(
                    email="taghawilfred@gmail.com",
                    full_name="Administrator",
                    password="strongPassword123!"
                )

        except Exception:
            pass