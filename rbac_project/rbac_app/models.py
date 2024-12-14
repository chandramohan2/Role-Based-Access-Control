from django.db import models
from django.utils.translation import gettext_lazy as _
from bson import ObjectId

def generate_object_id():
    return str(ObjectId())

class User(models.Model):
    id = models.CharField(max_length=24, primary_key=True, default=generate_object_id)


    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)

    class Role(models.TextChoices):
        STAFF = 'STAFF', _('Staff')
        SUPERVISOR = 'SUPERVISOR', _('Supervisor')
        ADMIN = 'ADMIN', _('Admin')

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.STAFF
    )

    def __str__(self):
        return self.username

class Permission(models.Model):
    name = models.CharField(max_length=255, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.name

class RolePermission(models.Model):
    role = models.CharField(
        max_length=20,
        choices=User.Role.choices
    )
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ['role', 'permission']

    def __str__(self):
        return f"{self.role} - {self.permission.name}"

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    resource = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField()
    details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"

