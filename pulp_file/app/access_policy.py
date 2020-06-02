from guardian.shortcuts import get_objects_for_user
from rest_access_policy import AccessPolicy


class BaseAccessPolicy(AccessPolicy):

    @classmethod
    def scope_queryset(cls, request, qs):
        is_file_global_admin = request.user.groups.filter(name='fileGlobalAdmin').exists()
        if is_file_global_admin:
            return qs  # This user has global admin role, no queryset filtering done

        return get_objects_for_user(request.user, cls.VIEW_PERMISSION_NAME)


class FileRemoteAccessPolicy(BaseAccessPolicy):
    VIEW_PERMISSION_NAME = 'file.view_fileremote'

    statements = [
        {
            "action": ["list"],
            "principal": "authenticated",
            "effect": "allow",
        },
        {
            "action": ["*"],
            "principal": "group:fileGlobalAdmin",
            "effect": "allow",
        },
        {
            "action": ["create"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_perms:file.add_fileremote",
        },
        {  # NOTE: with queryset restriction this returns as a 404
            "action": ["retrieve"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.view_fileremote",
        },
        {
            "action": ["destroy"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.delete_fileremote",
        },
        {
            "action": ["update", "partial_update"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.change_fileremote",
        },
    ]

class FileRepositoryAccessPolicy(BaseAccessPolicy):

    statements = [
        {
            "action": ["list"],
            "principal": "authenticated",
            "effect": "allow",
        },
        {
            "action": ["*"],
            "principal": "group:fileGlobalAdmin",
            "effect": "allow",
        },
        {
            "action": ["create"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_perms:file.add_filerepository",
        },
        {  # NOTE: with queryset restriction this returns as a 404
            "action": ["retrieve"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.view_filerepository",
        },
        {
            "action": ["destroy"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.delete_filerepository",
        },
        {
            "action": ["update", "partial_update"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.change_filerepository",
        },
        {
            "action": ["sync"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": [
                "has_model_or_obj_perms:file.modify_repo_content",
                "has_remote_param_model_or_obj_perms:file.view_fileremote",
            ]
        },
        {
            "action": ["modify"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_model_or_obj_perms:file.modify_repo_content",
        },
    ]
