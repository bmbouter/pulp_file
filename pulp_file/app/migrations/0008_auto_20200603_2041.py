# Generated by Django 2.2.12 on 2020-06-03 20:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('file', '0007_filefilesystemexporter'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='filerepository',
            options={'default_related_name': '%(app_label)s_%(model_name)s', 'permissions': (('modify_repo_content', 'Modify Repository Content'),)},
        ),
    ]