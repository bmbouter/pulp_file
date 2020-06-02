from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver
from django_currentuser.middleware import get_current_authenticated_user
from guardian.shortcuts import assign_perm, remove_perm

from pulp_file.app.models import FileRemote, FileRepository


@receiver(post_save, sender=FileRemote)
def create_file_remote_perms(instance, created, **kwargs):
    if created:
        for perm in instance.AUTO_ASSIGN_OBJECT_PERMS:
            assign_perm(perm, get_current_authenticated_user(), instance)


@receiver(post_delete, sender=FileRemote)
def delete_file_remote_perms(instance, **kwargs):
    import pydevd_pycharm
    pydevd_pycharm.settrace('localhost', port=29437, stdoutToServer=True, stderrToServer=True)
    for perm in instance.AUTO_ASSIGN_OBJECT_PERMS:
        remove_perm(perm, get_current_authenticated_user(), instance)
