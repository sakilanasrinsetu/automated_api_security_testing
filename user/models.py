from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _
from utils.helpers import generate_unique_slug


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, password, **extra_fields):
        username = self.model.normalize_username(username)
        user = self.model(**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, password, **extra_fields)

    def create_superuser(self, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, password, **extra_fields)


class UserAccount(AbstractUser):
    username = None
    phone = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["phone"]

    objects = UserManager()

    def __str__(self):
        if self.first_name or self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        return self.email or self.phone or str(self.id)

    class Meta:
        ordering = ["-id"]


class UserInformation(models.Model):
    user = models.OneToOneField(
        UserAccount, on_delete=models.SET_NULL, blank=True, null=True,
        related_name="user_informations"
    )
    name = models.CharField(max_length=355, blank=True, null=True)
    slug = models.SlugField(max_length=555, unique=True)
    address = models.TextField(null=True, blank=True)
    image = models.TextField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    created_by = models.ForeignKey(
        UserAccount, on_delete=models.CASCADE, related_name='user_information_created_bys')
    updated_by = models.ForeignKey(
        UserAccount, on_delete=models.CASCADE, related_name='user_information_updated_bys',
        null=True, blank=True)

    def __str__(self):
        return f"{self.name or 'User Info'} - ID {self.id}"

    class Meta:
        ordering = ["-id"]


# ---------- SLUG SIGNAL ----------
def user_info_slug_pre_save_receiver(sender, instance, *args, **kwargs):
    if not instance.slug:
        instance.slug = generate_unique_slug(instance.name)